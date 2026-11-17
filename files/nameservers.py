# modules/nameservers.py
"""Nameserver hygiene: count, resolvability, network diversity, lame delegations, SOA sync."""

import ipaddress

import tldextract

from . import dnsutil
from .findings import check_result, finding


def _network_key(ip):
    address = ipaddress.ip_address(ip)
    return str(ipaddress.ip_network(f"{ip}/{24 if address.version == 4 else 48}", strict=False))


def check_nameservers(domain, dns_server, direct=None):
    direct = direct or dnsutil.direct_soa
    apex = tldextract.extract(domain).registered_domain or domain
    data = {"zone": apex, "hosts": []}
    status, answers, err = dnsutil.lookup(apex, "NS", dns_server)
    if status == "error":
        return check_result("Nameservers", False, f"lookup failed ({err})", data, [finding("info", "NS_LOOKUP_FAILED", f"NS lookup failed ({err})")])
    names = sorted({str(r.target).rstrip(".").lower() for r in answers}) if status == "ok" else []
    if not names:
        return check_result("Nameservers", False, "no NS records returned", data)

    findings, serials, networks = [], {}, set()
    for host in names:
        entry = {"host": host, "ipv4": [], "ipv6": [], "nxdomain": False, "resolves": False}
        data["hosts"].append(entry)
        statuses = []
        for rtype, key in (("A", "ipv4"), ("AAAA", "ipv6")):
            st, ans, _ = dnsutil.lookup(host, rtype, dns_server)
            statuses.append(st)
            if st == "ok":
                entry[key] = [str(r.address) for r in ans]
        entry["resolves"] = bool(entry["ipv4"] or entry["ipv6"])
        entry["nxdomain"] = statuses == ["nxdomain", "nxdomain"]
        if not entry["resolves"]:
            if "error" in statuses:
                findings.append(finding("low", "NS_RESOLVE_ERROR", f"Could not resolve nameserver {host}", evidence=host))
            else:
                findings.append(finding("high", "NS_UNRESOLVABLE", f"Nameserver {host} has no A/AAAA records: queries to it fail",
                                        "Remove the stale NS record or restore the host's address records.", host))
            continue
        for ip in entry["ipv4"] + entry["ipv6"]:
            networks.add(_network_key(ip))
        probe_ip = (entry["ipv4"] or entry["ipv6"])[0]
        serial, authoritative, error = direct(probe_ip, apex)
        entry.update(serial=serial, authoritative=authoritative, error=error)
        if error:
            sev = "low" if error == "timeout" else "medium"
            findings.append(finding(sev, "NS_NO_ANSWER", f"Nameserver {host} ({probe_ip}) did not answer an SOA query ({error})",
                                    "Check the server is running and not blocking port 53.", host))
        elif not authoritative:
            findings.append(finding("medium", "NS_LAME", f"Nameserver {host} answers but is not authoritative for {apex} (lame delegation)",
                                    "Load the zone on this server or remove it from the NS set.", host))
        elif serial is not None:
            serials[host] = serial

    resolvable = [e for e in data["hosts"] if e["resolves"]]
    if len(names) < 2:
        findings.append(finding("high", "NS_SINGLE", "Only one nameserver: a single point of failure", "Publish at least two nameservers on different networks."))
    elif len(resolvable) >= 2 and len(networks) < 2:
        findings.append(finding("medium", "NS_SAME_NETWORK", "All nameservers sit in the same /24 (IPv4) or /48 (IPv6): one outage or attack takes DNS down",
                                "Use nameservers on different networks/providers."))
    if len(set(serials.values())) > 1:
        findings.append(finding("medium", "NS_SERIAL_MISMATCH",
                                "Nameservers return different SOA serials (" + ", ".join(f"{h}={s}" for h, s in sorted(serials.items())) + "): the zone is out of sync, or a transfer is in progress",
                                "Check zone transfers/replication between the nameservers.", serials))
    data["serials"] = serials
    return check_result("Nameservers", True, None, data, findings)
