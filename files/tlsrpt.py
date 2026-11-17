# modules/tlsrpt.py
"""TLS-RPT (RFC 8460): _smtp._tls TXT record and reporting destinations (DNS only)."""

import re
from urllib.parse import urlsplit

from . import dnsutil
from .findings import check_result, finding
from .txt import txt_value

_MAILTO = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")


def _validate_destination(uri):
    """Return None if valid, else a reason string."""
    if uri.lower().startswith("mailto:"):
        return None if _MAILTO.match(uri[7:].split("?", 1)[0]) else "malformed mailto address"
    parts = urlsplit(uri)
    if parts.scheme == "https":
        return None if parts.hostname else "https URI without a host"
    if parts.scheme == "http":
        return "plaintext http endpoint (reports contain TLS failure details)"
    return "unsupported scheme (only mailto: and https: are allowed)"


def _txt_records(name, prefix, dns_server):
    status, answers, err = dnsutil.lookup(name, "TXT", dns_server)
    if status != "ok":
        return status, [], err
    return status, [v for v in (txt_value(r).strip() for r in answers) if v.startswith(prefix)], err


def check_tlsrpt(domain, dns_server):
    data = {"record": None, "rua": [], "mta_sts_record_present": False}
    status, records, err = _txt_records(f"_smtp._tls.{domain}", "v=TLSRPTv1", dns_server)
    if status == "error":
        return check_result("TLS-RPT", False, f"lookup failed ({err})", data,
                            [finding("info", "TLSRPT_LOOKUP_FAILED", f"TLS-RPT lookup failed ({err})")])
    sts_status, sts, _ = _txt_records(f"_mta-sts.{domain}", "v=STSv1", dns_server)
    data["mta_sts_record_present"] = bool(sts)

    findings = []
    if not records:
        if data["mta_sts_record_present"]:
            findings.append(finding("low", "TLSRPT_MISSING", "MTA-STS is published but there is no TLS-RPT record: TLS delivery failures go unreported",
                                    'Publish _smtp._tls TXT  "v=TLSRPTv1; rua=mailto:tls-reports@example.com".'))
            return check_result("TLS-RPT", True, None, data, findings)
        return check_result("TLS-RPT", False, "not deployed (no MTA-STS record seen either)", data,
                            [finding("info", "TLSRPT_NOT_DEPLOYED", "No TLS-RPT record (only relevant once MTA-STS or DANE is deployed)")])
    if len(records) > 1:
        findings.append(finding("medium", "TLSRPT_MULTIPLE", "Multiple TLS-RPT records: senders may ignore reporting",
                                "Publish exactly one v=TLSRPTv1 record."))
    data["record"] = records[0]
    tags = {}
    for part in records[0].split(";"):
        name, sep, value = part.partition("=")
        if sep:
            tags.setdefault(name.strip(), value.strip())
    uris = [u.strip() for u in tags.get("rua", "").split(",") if u.strip()]
    data["rua"] = uris
    if not uris:
        findings.append(finding("medium", "TLSRPT_NO_RUA", "TLS-RPT record has no rua= reporting destination",
                                'Add rua=mailto:... or rua=https://...'))
    for uri in uris:
        problem = _validate_destination(uri)
        if problem:
            findings.append(finding("medium", "TLSRPT_BAD_DESTINATION", f"Invalid reporting destination {uri!r}: {problem}",
                                    "Use rua=mailto:user@example.com or rua=https://host/path.", uri))
    if not any(f["severity"] != "info" for f in findings):
        findings.append(finding("info", "TLSRPT_OK", "TLS-RPT record is valid"))
    return check_result("TLS-RPT", True, None, data, findings)
