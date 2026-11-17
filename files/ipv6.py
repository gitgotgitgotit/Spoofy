# modules/ipv6.py
"""IPv6 mail exposure: AAAA on MX hosts, SPF ip6 coverage, and reverse DNS (FCrDNS)."""

import ipaddress

from . import dnsutil
from .findings import check_result, finding
from .spf_parser import parse_spf

MAX_ADDRESSES = 8


def _spf_coverage(spf_record):
    """Return (ip6 networks, mx authorised, indirect) or None if SPF is unusable."""
    if not spf_record:
        return None
    try:
        terms = parse_spf(spf_record)
    except ValueError:
        return None
    networks, mx, indirect = [], False, False
    for term in terms:
        if term.modifier:
            indirect = indirect or term.mechanism == "redirect"
        elif term.mechanism == "ip6" and term.qualifier == "+":
            try:
                networks.append(ipaddress.ip_network(term.value, strict=False))
            except ValueError:
                pass
        elif term.mechanism == "mx" and term.qualifier == "+":
            mx = True
        elif term.mechanism == "include":
            indirect = True
    return networks, mx, indirect


def _reverse_status(ip, dns_server):
    """Return (ptr_names, forward_confirmed)."""
    status, answers, _ = dnsutil.lookup(ipaddress.ip_address(ip).reverse_pointer, "PTR", dns_server)
    if status != "ok":
        return [], False
    names = [str(r.target).rstrip(".").lower() for r in answers]
    wanted = ipaddress.ip_address(ip)
    for name in names:
        fstatus, fwd, _ = dnsutil.lookup(name, "AAAA" if wanted.version == 6 else "A", dns_server)
        if fstatus == "ok" and any(ipaddress.ip_address(str(r.address)) == wanted for r in fwd):
            return names, True
    return names, False


def check_ipv6(domain, dns_server, mx_records, spf_record):
    hosts = [r for r in mx_records or [] if r.get("ipv6")]
    data = {"hosts_with_ipv6": [r["host"] for r in hosts],
            "hosts_without_ipv6": [r["host"] for r in mx_records or [] if r["host"] and not r.get("ipv6")],
            "addresses": []}
    if not hosts:
        return check_result("IPv6", False, "no MX host publishes an AAAA record", data,
                            [finding("info", "IPV6_NONE", "No IPv6 mail exposure (no AAAA on any MX host)")])

    findings = []
    if data["hosts_without_ipv6"]:
        findings.append(finding("info", "IPV6_INCONSISTENT",
                                f"IPv6 on some MX hosts only (without: {', '.join(data['hosts_without_ipv6'])}); check both paths are equally secured"))
    coverage = _spf_coverage(spf_record)
    addresses = [(r["host"], a) for r in hosts for a in r["ipv6"]]
    if len(addresses) > MAX_ADDRESSES:
        findings.append(finding("info", "IPV6_TRUNCATED", f"{len(addresses)} IPv6 addresses; first {MAX_ADDRESSES} checked"))
        addresses = addresses[:MAX_ADDRESSES]

    for host, address in addresses:
        entry = {"host": host, "address": address, "spf": "unknown", "ptr": [], "fcrdns": False}
        data["addresses"].append(entry)
        if coverage is not None:
            networks, mx_ok, indirect = coverage
            ip = ipaddress.ip_address(address)
            if mx_ok or any(ip in net for net in networks if net.version == 6):
                entry["spf"] = "authorized"
            elif indirect:
                entry["spf"] = "unknown"
            else:
                entry["spf"] = "not-listed"
                findings.append(finding(
                    "low", "IPV6_NOT_IN_SPF",
                    f"MX host {host} has IPv6 address {address} that SPF does not authorize; if it also sends mail over IPv6 those messages fail SPF",
                    "Add ip6:<prefix> (or the mx mechanism) to SPF if this host sends mail; ignore if inbound-only.", address))
        elif spf_record:
            entry["spf"] = "unparsable"
        entry["ptr"], entry["fcrdns"] = _reverse_status(address, dns_server)
        if not entry["ptr"]:
            findings.append(finding("low", "IPV6_NO_PTR", f"{address} ({host}) has no reverse DNS (PTR); many receivers reject mail from IPs without it",
                                    "Ask your provider to set a PTR record that matches the mail host name.", address))
        elif not entry["fcrdns"]:
            findings.append(finding("low", "IPV6_PTR_MISMATCH", f"{address} ({host}) has a PTR that does not resolve back to the address (no forward-confirmed rDNS)",
                                    "Make the PTR name's AAAA record point back to this address.", address))
    return check_result("IPv6", True, None, data, findings)
