# modules/takeover.py
"""Takeover risk: names this domain trusts that an outsider could register or claim.

Only third-party names count: your own registered domain cannot be registered
by an attacker. "Unregistered" = the registered domain returns NXDOMAIN for NS.
"""

import tldextract

from . import dnsutil
from .findings import check_result, finding


def _registered(name):
    return tldextract.extract(name).registered_domain


def check_takeover(domain, dns_server, walk, ns_data, dkim_dangling):
    own = _registered(domain) or domain
    cache = {}

    def unregistered(name):
        reg = _registered(name)
        if not reg or reg == own:
            return False
        if reg not in cache:
            cache[reg] = dnsutil.lookup(reg, "NS", dns_server)[0] == "nxdomain"
        return cache[reg]

    findings, flagged = [], set()
    for inc in (walk or {}).get("includes", []):
        if inc["status"] == "nxdomain" and unregistered(inc["target"]):
            flagged.add(inc["target"])
            findings.append(finding("critical", "TAKEOVER_SPF_INCLUDE",
                                    f"SPF includes {inc['target']}, whose domain {_registered(inc['target'])} appears unregistered: whoever registers it controls who may send as {domain}",
                                    "Remove the include now, then investigate how it went stale.", inc["target"]))
    for host in (ns_data or {}).get("hosts", []):
        if host.get("nxdomain") and unregistered(host["host"]):
            findings.append(finding("critical", "TAKEOVER_NAMESERVER",
                                    f"Nameserver {host['host']} is on {_registered(host['host'])}, which appears unregistered: registering it would let an attacker answer for {domain}",
                                    "Remove the NS record at the registrar immediately.", host["host"]))
    for selector, target in sorted((dkim_dangling or {}).items()):
        if unregistered(target):
            findings.append(finding("critical", "TAKEOVER_DKIM_CNAME",
                                    f"DKIM selector {selector} is a CNAME to {target}, on an apparently unregistered domain: an attacker could publish their own DKIM key",
                                    "Remove the CNAME.", selector))
        else:
            findings.append(finding("medium", "DKIM_CNAME_DANGLING",
                                    f"DKIM selector {selector} is a CNAME to {target}, which does not exist (vendor record deprovisioned?); DKIM fails and a provider-hosted name may be claimable",
                                    "Remove the CNAME or re-provision the selector with the vendor.", selector))
    return check_result("Takeover risk", True, None, {"unregistered_targets": sorted(flagged)}, findings)
