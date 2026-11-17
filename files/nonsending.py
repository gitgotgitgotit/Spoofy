# modules/nonsending.py
"""Hygiene for domains that do not handle mail: SPF -all, DMARC reject, revoked wildcard DKIM."""

from . import dnsutil
from .findings import check_result, finding
from .txt import txt_value

PROBE_SELECTOR = "spoofy-nonexistent-selector"


def check_nonsending(domain, dns_server, mx_data, result):
    null = bool(mx_data.get("null_mx"))
    if not (null or mx_data.get("no_mail")):
        return check_result("Non-sending hygiene", False, "domain receives mail")
    basis = "publishes a null MX" if null else "has no MX or address records"
    high = "high" if null else "medium"  # an explicit null MX is a clear statement; "no MX" is only a hint
    findings = []
    if not result.get("SPF"):
        findings.append(finding(high, "NONMAIL_NO_SPF", f"This domain {basis} but has no SPF record: spoofers can use it freely",
                                'Publish "v=spf1 -all".'))
    elif result.get("SPF_MULTIPLE_ALLS") != "-all":
        findings.append(finding(high, "NONMAIL_SPF_NOT_FAIL", f"This domain {basis} but its SPF does not end in -all",
                                'Publish "v=spf1 -all".'))
    policy = result.get("DMARC_POLICY")
    if not result.get("DMARC"):
        findings.append(finding(high, "NONMAIL_NO_DMARC", f"This domain {basis} but has no DMARC record", 'Publish "v=DMARC1; p=reject; rua=mailto:..." .'))
    elif policy != "reject":
        findings.append(finding("medium", "NONMAIL_DMARC_NOT_REJECT", f"This domain {basis} but DMARC is p={policy}; nothing legitimate sends from it, so p=reject is safe",
                                "Set p=reject."))
    status, answers, _ = dnsutil.lookup(f"{PROBE_SELECTOR}._domainkey.{domain}", "TXT", dns_server)
    revoked = status == "ok" and any(v.replace(" ", "").lower().endswith("p=") or "p=;" in v.replace(" ", "").lower()
                                      for v in (txt_value(r) for r in answers))
    if not revoked:
        findings.append(finding("low", "NONMAIL_NO_DKIM_REVOKE", "No wildcard DKIM revocation (optional hardening for non-mail domains)",
                                'Publish *._domainkey TXT "v=DKIM1; p=" so no selector can validate.'))
    if not any(f["severity"] != "info" for f in findings):
        findings.append(finding("info", "NONMAIL_OK", f"This domain {basis} and is locked down (SPF -all, DMARC reject)"))
    return check_result("Non-sending hygiene", True, None, {"basis": basis}, findings)
