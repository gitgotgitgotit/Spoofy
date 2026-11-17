# modules/mx.py
"""MX assessment: records, resolution, dangling hosts, CNAMEs, non-public addresses."""

import ipaddress

from . import dnsutil
from .findings import check_result, finding

MAX_HOSTS = 10


def _addresses(host, dns_server):
    v4, v6, errors = [], [], []
    statuses = {}
    for rtype, bucket in (("A", v4), ("AAAA", v6)):
        status, answers, err = dnsutil.lookup(host, rtype, dns_server)
        statuses[rtype] = status
        if status == "ok":
            bucket.extend(str(r.address) for r in answers)
        elif status == "error":
            errors.append(f"{rtype}:{err}")
    return v4, v6, errors, statuses


def check_mx(domain, dns_server):
    findings, records = [], []
    status, answers, err = dnsutil.lookup(domain, "MX", dns_server)
    data = {"records": records, "null_mx": False, "implicit_mx": False, "truncated": False}

    if status == "error":
        findings.append(finding("info", "MX_LOOKUP_FAILED", f"MX lookup failed ({err}); mail routing not assessed"))
        return check_result("MX", False, "lookup failed", data, findings)

    raw = []
    if status == "ok":
        for rdata in answers:
            raw.append((int(rdata.preference), str(rdata.exchange).rstrip(".").lower()))
    raw.sort()

    if any(host == "" for _, host in raw):
        data["null_mx"] = True
        if any(host != "" for _, host in raw):
            findings.append(finding("medium", "MX_NULL_WITH_OTHERS", "A null MX (\".\") is published alongside real MX records",
                                    "RFC 7505: a null MX must be the only MX record."))
        else:
            findings.append(finding("info", "MX_NULL", "Null MX published: the domain declares it does not receive mail (RFC 7505)"))
        return check_result("MX", True, None, data, findings)

    if not raw:
        v4, v6, _, _ = _addresses(domain, dns_server)
        if v4 or v6:
            data["implicit_mx"] = True
            findings.append(finding("low", "MX_IMPLICIT", "No MX record: mail falls back to the domain's A/AAAA record (RFC 5321)",
                                    "Publish an explicit MX, or a null MX (0 .) if the domain should not receive mail."))
            return check_result("MX", True, None, data, findings)
        data["no_mail"] = True
        return check_result("MX", False, "domain has no MX and no address records (does not receive mail)", data, [
            finding("info", "MX_NONE", "No MX or address records: the domain cannot receive mail",
                    "Publish a null MX (0 .) to state this explicitly and stop bounces/backscatter.")])

    if len(raw) > MAX_HOSTS:
        data["truncated"] = True
        findings.append(finding("info", "MX_TRUNCATED", f"{len(raw)} MX records; only the first {MAX_HOSTS} were checked"))
        raw = raw[:MAX_HOSTS]

    for priority, host in raw:
        record = {"priority": priority, "host": host, "ipv4": [], "ipv6": [], "cname": False, "problems": []}
        records.append(record)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            record["problems"].append("ip-literal")
            findings.append(finding("high", "MX_IP_LITERAL", f"MX target {host} is an IP address, not a hostname (invalid)",
                                    "Point the MX at a hostname with A/AAAA records.", host))
            continue

        record["ipv4"], record["ipv6"], errors, statuses = _addresses(host, dns_server)
        cname_status, _, _ = dnsutil.lookup(host, "CNAME", dns_server)
        record["cname"] = cname_status == "ok"
        if record["cname"]:
            record["problems"].append("cname")
            findings.append(finding("medium", "MX_CNAME", f"MX host {host} is a CNAME (forbidden by RFC 2181 section 10.3; some senders fail)",
                                    "Point the MX directly at a host with A/AAAA records.", host))
        if not record["ipv4"] and not record["ipv6"]:
            if errors:
                findings.append(finding("low", "MX_RESOLVE_ERROR", f"Could not resolve MX host {host} ({', '.join(errors)})", evidence=host))
            else:
                record["problems"].append("dangling")
                findings.append(finding("high", "MX_DANGLING",
                                        f"MX host {host} has no A/AAAA records: mail to it fails and the name may be claimable",
                                        "Remove the stale MX or restore its address records.", host))
        for address in record["ipv4"] + record["ipv6"]:
            if not ipaddress.ip_address(address).is_global:
                record["problems"].append("non-public")
                findings.append(finding("medium", "MX_NON_PUBLIC", f"MX host {host} resolves to non-public address {address}",
                                        "Mail servers must be reachable at public addresses.", address))

    if len(records) == 1:
        findings.append(finding("info", "MX_SINGLE", "Only one MX host: no mail redundancy"))
    return check_result("MX", True, None, data, findings)
