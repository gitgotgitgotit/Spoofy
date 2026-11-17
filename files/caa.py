# modules/caa.py
"""CAA assessment (RFC 8659): which CAs may issue certificates for the domain."""

import tldextract

from . import dnsutil
from .findings import check_result, finding

TOO_MANY_CAS = 3


def _candidate_names(domain):
    """The domain, then each parent up to the registered domain (CAA tree climbing)."""
    registered = tldextract.extract(domain).registered_domain or domain
    labels, names = domain.split("."), []
    for i in range(len(labels)):
        name = ".".join(labels[i:])
        names.append(name)
        if name == registered:
            break
    return names


def check_caa(domain, dns_server):
    data = {"found_at": None, "issue": [], "issuewild": [], "iodef": [], "deny_all": False}
    for name in _candidate_names(domain):
        status, answers, err = dnsutil.lookup(name, "CAA", dns_server)
        if status == "error":
            return check_result("CAA", False, f"lookup failed ({err})", data,
                                [finding("info", "CAA_LOOKUP_FAILED", f"CAA lookup failed at {name} ({err})")])
        if status == "ok":
            data["found_at"] = name
            for rdata in answers:
                tag = dnsutil.text(rdata.tag).lower()
                value = dnsutil.text(rdata.value).strip()
                if tag in ("issue", "issuewild"):
                    data[tag].append(value.split(";")[0].strip())  # CA domain; parameters ignored
                elif tag == "iodef":
                    data["iodef"].append(value)
            break

    findings = []
    if data["found_at"] is None:
        findings.append(finding("low", "CAA_MISSING", "No CAA record: any certificate authority may issue certificates for this domain",
                                'Add e.g.  0 issue "letsencrypt.org"  for the CA(s) you actually use.'))
        return check_result("CAA", True, None, data, findings)

    if data["found_at"] != domain:
        findings.append(finding("info", "CAA_INHERITED", f"CAA policy inherited from {data['found_at']}"))
    issuers = [ca for ca in data["issue"] if ca]
    data["deny_all"] = bool(data["issue"]) and not issuers
    if data["deny_all"]:
        findings.append(finding("info", "CAA_DENY_ALL", "CAA forbids all issuance (issue \";\")"))
    elif not data["issue"] and not data["issuewild"]:
        findings.append(finding("low", "CAA_NO_ISSUE", "CAA records exist but none restrict issuance (no issue/issuewild property)",
                                'Add an issue property, e.g.  0 issue "letsencrypt.org".'))
    elif len(set(issuers)) > TOO_MANY_CAS:
        findings.append(finding("low", "CAA_BROAD", f"{len(set(issuers))} CAs are authorised to issue; keep this to the CAs you use",
                                evidence=sorted(set(issuers))))
    if not data["iodef"]:
        findings.append(finding("info", "CAA_NO_IODEF", "No iodef property: CAs have nowhere to report violations",
                                'Optionally add  0 iodef "mailto:security@example.com".'))
    return check_result("CAA", True, None, data, findings)
