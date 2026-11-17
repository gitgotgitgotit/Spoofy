# modules/dmarc_reporting.py
"""DMARC report destinations: external authorisation (RFC 7489 7.1), syntax, ruf privacy, length."""

import re

import tldextract

from . import dnsutil
from .findings import check_result, finding
from .txt import txt_value

_ADDRESS = re.compile(r"^[^@\s,;<>]+@([^@\s,;<>]+\.[^@\s,;<>]+)$")
LONG_RECORD = 255


def _tags(record):
    tags = {}
    for part in record.split(";"):
        name, sep, value = part.partition("=")
        if sep:
            tags.setdefault(name.strip().lower(), value.strip())
    return tags


def _uris(value):
    """Split a rua/ruf value; drop the optional !size limit (mailto:a@b.c!10m)."""
    return [u.strip().split("!", 1)[0] for u in value.split(",") if u.strip()]


def check_dmarc_reporting(domain, dns_server, dmarc_record, record_domain=None):
    if not dmarc_record:
        return check_result("DMARC reporting", False, "no DMARC record")
    report_domain = record_domain or domain
    own = tldextract.extract(report_domain).registered_domain or report_domain
    tags, findings, checked = _tags(dmarc_record), [], set()
    data = {"rua": [], "ruf": [], "external_destinations": {}}

    for tag in ("rua", "ruf"):
        for uri in _uris(tags.get(tag, "")):
            data[tag].append(uri)
            if not uri.lower().startswith("mailto:"):
                findings.append(finding("low", "DMARC_REPORT_NON_MAILTO", f"{tag}={uri}: only mailto: destinations are widely supported by receivers", "Use mailto: addresses.", uri))
                continue
            match = _ADDRESS.match(uri[7:])
            if not match:
                findings.append(finding("medium", "DMARC_REPORT_BAD_ADDRESS", f"{tag}={uri}: malformed e-mail address; reports will not be delivered", "Fix the address.", uri))
                continue
            dest = match.group(1).lower()
            if (tldextract.extract(dest).registered_domain or dest) == own or dest in checked:
                continue
            checked.add(dest)
            name = f"{report_domain}._report._dmarc.{dest}"
            status, answers, err = dnsutil.lookup(name, "TXT", dns_server)
            authorised = status == "ok" and any(txt_value(r).strip().lower().startswith("v=dmarc1") for r in answers)
            data["external_destinations"][dest] = "authorised" if authorised else ("unknown" if status == "error" else "missing")
            if status == "error":
                findings.append(finding("info", "DMARC_REPORT_AUTH_UNKNOWN", f"Could not check report authorisation at {name} ({err})"))
            elif not authorised:
                findings.append(finding("medium", "DMARC_REPORT_UNAUTHORISED",
                                        f"Reports go to external domain {dest}, which has not authorised them: receivers silently drop them",
                                        f'{dest} must publish TXT {name} = "v=DMARC1".', dest))
    if data["ruf"]:
        findings.append(finding("low", "DMARC_RUF", "ruf= requests forensic reports, which can contain message content and personal data (privacy/GDPR); few receivers send them",
                                "Remove ruf unless you really need it and have a lawful basis."))
    if len(dmarc_record) > LONG_RECORD:
        findings.append(finding("low", "DMARC_LONG_RECORD", f"DMARC record is {len(dmarc_record)} characters (more than one TXT string); some DNS providers mishandle this",
                                "Shorten the record (fewer rua/ruf destinations)."))
    unverified = "unknown" in data["external_destinations"].values()
    if not unverified and not any(f["severity"] != "info" for f in findings):
        findings.append(finding("info", "DMARC_REPORTING_OK", "DMARC report destinations look correct"))
    return check_result("DMARC reporting", True, None, data, findings)
