"""Optional SPF dependency, registration and IP-allocation intelligence.

RDAP is queried through rdap.org's bootstrap-aware redirect service. External
lookup failures are reported as unknown, never as proof of non-registration.
"""
import ipaddress
import re
import socket
from functools import lru_cache

import dns.exception
import dns.resolver
import requests

from .resolver_cache import get_resolver
from .spf_parser import parse_spf
from .syntax import validate_record_syntax

RDAP_TIMEOUT = 4
PROVIDER_SIGNATURES = {
    "_spf.google.com": "Google Workspace",
    "spf.protection.outlook.com": "Microsoft 365",
    "sendgrid.net": "SendGrid",
    "servers.mcsv.net": "Mailchimp",
    "amazonses.com": "Amazon SES",
    "mailgun.org": "Mailgun",
    "spf.mtasv.net": "SparkPost",
    "zoho.com": "Zoho Mail",
}


def _domain_name(value):
    value = value.rstrip(".")
    return value if value and not value.startswith("%{") else None


def _rdap_entity_name(data):
    for entity in data.get("entities", []):
        for item in entity.get("vcardArray", [None, []])[1] if entity.get("vcardArray") else []:
            if len(item) >= 4 and item[0] == "fn" and item[3]:
                return str(item[3])
    return None


@lru_cache(maxsize=2048)
def domain_registration(domain):
    try:
        response = requests.get(f"https://rdap.org/domain/{domain}", timeout=RDAP_TIMEOUT,
                                headers={"Accept": "application/rdap+json"})
        if response.status_code == 404:
            return {"status": "not_registered", "registrar": None, "created": None, "expires": None}
        if response.status_code == 429 or response.status_code >= 500:
            return {"status": "unknown", "registrar": None, "created": None, "expires": None}
        response.raise_for_status()
        data = response.json()
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        registrar = None
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                registrar = _rdap_entity_name({"entities": [entity]}) or entity.get("handle")
                break
        return {"status": "registered", "registrar": registrar,
                "created": events.get("registration"), "expires": events.get("expiration")}
    except (requests.RequestException, ValueError, KeyError):
        return {"status": "unknown", "registrar": None, "created": None, "expires": None}


@lru_cache(maxsize=4096)
def ip_registration(address):
    try:
        response = requests.get(f"https://rdap.org/ip/{address}", timeout=RDAP_TIMEOUT,
                                headers={"Accept": "application/rdap+json"})
        if response.status_code == 404 or response.status_code >= 500 or response.status_code == 429:
            return {"status": "unknown", "owner": None, "handle": None, "prefix": None, "country": None}
        response.raise_for_status()
        data = response.json()
        return {"status": "allocated", "owner": _rdap_entity_name(data),
                "handle": data.get("handle"),
                "prefix": f"{data.get('startAddress', '')}-{data.get('endAddress', '')}".strip("-"),
                "country": data.get("country")}
    except (requests.RequestException, ValueError, KeyError):
        return {"status": "unknown", "owner": None, "handle": None, "prefix": None, "country": None}


def _resolve(resolver, name, record_type):
    try:
        answer = resolver.resolve(name, record_type)
        if record_type == "TXT":
            return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]
        if record_type == "MX":
            return [str(r.exchange).rstrip(".") for r in answer]
        return [str(r).rstrip(".") for r in answer]
    except (dns.exception.DNSException, OSError, ValueError, AttributeError):
        return []


@lru_cache(maxsize=4096)
def ip_routing_info(address):
    """Return public BGP visibility and origin ASN data from RIPEstat."""
    try:
        response = requests.get(
            "https://stat.ripe.net/data/prefix-overview/data.json",
            params={"resource": address}, timeout=RDAP_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        asns = data.get("asns", [])
        return {"announced": data.get("announced"),
                "prefix": data.get("prefix"),
                "asns": asns if isinstance(asns, list) else []}
    except (requests.RequestException, ValueError, KeyError):
        return {"announced": None, "prefix": None, "asns": []}


def analyze_spf(domain, record, dns_server=None):
    resolver = get_resolver(dns_server)
    result = {"record_valid": validate_record_syntax(record, "SPF"), "dns_lookup_count": 0,
              "dns_lookup_limit": 10, "dns_lookups_remaining": None,
              "domains": [], "ips": [], "warnings": []}
    try:
        terms = parse_spf(record)
    except ValueError as exc:
        result["warnings"].append(str(exc))
        return result

    domain_targets, ip_targets = [], []
    visited = set()

    def add_domain(name, source):
        name = _domain_name(name)
        if name and (name, source) not in visited:
            visited.add((name, source))
            domain_targets.append((name, source))

    def inspect_terms(current_record, path, depth=0):
        if depth > 20:
            result["warnings"].append("SPF include recursion exceeded safety depth (20)")
            return
        try:
            nested_terms = parse_spf(current_record)
        except ValueError:
            return
        for term in nested_terms:
            if term.modifier:
                if term.mechanism == "redirect":
                    result["dns_lookup_count"] += 1
                    add_domain(term.value, "redirect")
                    if term.value not in path:
                        nested = [r for r in _resolve(resolver, term.value, "TXT") if r.lower().startswith("v=spf1")]
                        if len(nested) == 1:
                            inspect_terms(nested[0], path | {term.value}, depth + 1)
                continue
            mechanism, value = term.mechanism, term.value
            if mechanism in {"include", "a", "mx", "ptr", "exists"}:
                result["dns_lookup_count"] += 1
            if mechanism == "include":
                add_domain(value, "include")
                if value not in path:
                    nested = [r for r in _resolve(resolver, value, "TXT") if r.lower().startswith("v=spf1")]
                    if len(nested) == 1:
                        inspect_terms(nested[0], path | {value}, depth + 1)
                    elif len(nested) > 1:
                        result["warnings"].append(f"Multiple SPF records returned for include target {value}")
            elif mechanism in {"a", "mx", "ptr"}:
                target = value.split("/", 1)[0] if value and not value.startswith("/") else domain
                add_domain(target, mechanism)
                if mechanism == "mx":
                    for mx in _resolve(resolver, target, "MX"):
                        add_domain(mx, "mx-host")
                        ip_targets.extend(_resolve(resolver, mx, "A"))
                        ip_targets.extend(_resolve(resolver, mx, "AAAA"))
                elif mechanism == "a":
                    ip_targets.extend(_resolve(resolver, target, "A"))
                    ip_targets.extend(_resolve(resolver, target, "AAAA"))
                else:
                    result["warnings"].append("The ptr mechanism is deprecated and discouraged; its sender-dependent reverse-DNS result cannot be established by a static SPF scan")
            elif mechanism == "exists":
                add_domain(value, "exists")
                _resolve(resolver, value, "A")
            elif mechanism == "ip4":
                ip_targets.append(value)
            elif mechanism == "ip6":
                ip_targets.append(value)

    inspect_terms(record, {domain})
    result["dns_lookups_remaining"] = max(0, 10 - result["dns_lookup_count"])
    if result["dns_lookup_count"] > 10:
        result["warnings"].append("SPF exceeds the 10-DNS-lookup limit")

    for name, source in domain_targets:
        dns_a = _resolve(resolver, name, "A") if source != "ptr" else []
        dns_aaaa = _resolve(resolver, name, "AAAA") if source != "ptr" else []
        mx_records = _resolve(resolver, name, "MX") if source == "mx" else []
        txt_records = _resolve(resolver, name, "TXT") if source in {"include", "redirect"} else []
        spf_txt = [r for r in txt_records if r.lower().startswith("v=spf1")]
        spf_status = ("valid" if len(spf_txt) == 1 else "multiple" if len(spf_txt) > 1 else "missing") if source in {"include", "redirect"} else "not_applicable"
        reg = domain_registration(name)
        provider = next((v for signature, v in PROVIDER_SIGNATURES.items()
                         if name == signature or name.endswith("." + signature)), None)
        if source == "ptr":
            status = "not_checked"
        else:
            status = "resolved" if dns_a or dns_aaaa or mx_records or txt_records else "unresolved"
        item = {"domain": name, "source": source, "dns_status": status,
                "spf_status": spf_status, "a": dns_a, "aaaa": dns_aaaa,
                "mx": mx_records, "registration": reg["status"],
                "registrar": reg["registrar"], "created": reg["created"],
                "expires": reg["expires"], "provider": provider}
        if reg["status"] == "not_registered":
            result["warnings"].append(f"SPF dependency {name} is reported not registered by RDAP")
        if spf_status == "missing":
            result["warnings"].append(f"SPF dependency {name} has no SPF TXT record")
        elif spf_status == "multiple":
            result["warnings"].append(f"SPF dependency {name} publishes multiple SPF TXT records")
        result["domains"].append(item)
        if source in {"a", "mx-host"}:
            ip_targets.extend(dns_a + dns_aaaa)

    for raw_ip in dict.fromkeys(ip_targets):
        try:
            ip = ipaddress.ip_interface(raw_ip).ip
        except ValueError:
            try:
                ip = ipaddress.ip_address(raw_ip)
            except ValueError:
                continue
        info = ip_registration(str(ip))
        routing = ip_routing_info(str(ip))
        result["ips"].append({"ip": str(ip), **info,
                              "bgp_announced": routing["announced"],
                              "bgp_prefix": routing["prefix"],
                              "asns": routing["asns"]})
    return result
