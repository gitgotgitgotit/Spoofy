# modules/scoring.py
"""Configuration-strength score (heuristic, v1).

Each area starts at 100 and loses points per finding by severity (critical 40,
high 25, medium 12, low 5, info 0). The overall score is a weighted mean of the
applicable areas, so areas that do not apply (DKIM not scanned, BIMI not
deployed, no IPv6) are excluded rather than penalised. Caps stop a strong
average from hiding a serious problem. This is NOT an industry standard.
"""

from .dkim_hygiene import dkim_rotation_hints
from .findings import SEVERITY_ORDER, SEVERITY_PENALTY, check_result, finding

SCORING_VERSION = 1
AREA_WEIGHTS = {"DMARC": 20, "SPF": 15, "DKIM": 15, "DMARC alignment": 12, "DNSSEC": 10, "Takeover risk": 10,
                "MX": 8, "SPF hardening": 6, "Non-sending hygiene": 6, "Nameservers": 5, "CAA": 5, "TLS-RPT": 4,
                "DMARC reporting": 3, "IPv6": 3, "BIMI": 2}
GRADES = ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F"))
CAP_SPOOFABLE, CAP_POSSIBLE, CAP_CRITICAL = 59, 79, 69


def _spf(r):
    record = r.get("SPF")
    findings = []
    if r.get("SPF_MULTIPLE_RECORDS"):
        findings.append(finding("high", "SPF_MULTIPLE", "Multiple SPF records: receivers return permerror and SPF fails",
                                "Merge them into a single v=spf1 record."))
    if not record:
        if not r.get("SPF_MULTIPLE_RECORDS"):
            findings.append(finding("high", "SPF_MISSING", "No SPF record", 'Publish a record such as "v=spf1 include:<sender> -all".'))
        return check_result("SPF", True, None, {"record": None}, findings)
    mech = r.get("SPF_MULTIPLE_ALLS")
    table = {"+all": ("critical", "SPF ends in +all: every host on the internet is authorised to send as this domain"),
             "?all": ("medium", "SPF ends in ?all (neutral): it gives no protection"),
             "2many": ("medium", "SPF contains several 'all' terms"),
             None: ("medium", "SPF has no 'all' term, so unlisted senders are not rejected or softfailed")}
    if mech in table:
        severity, title = table[mech]
        findings.append(finding(severity, "SPF_ALL", title, "End the record with -all (or ~all while rolling out)."))
    elif mech == "~all":
        findings.append(finding("low", "SPF_SOFTFAIL", "SPF ends in ~all (softfail); acceptable with an enforced DMARC policy, weaker without one",
                                "Move to -all once all senders are listed."))
    if r.get("SPF_TOO_MANY_DNS_QUERIES"):
        findings.append(finding("high", "SPF_LOOKUPS", f"SPF needs {r.get('SPF_NUM_DNS_QUERIES')} DNS lookups (limit 10): receivers return permerror",
                                "Remove unused includes or flatten the record."))
    return check_result("SPF", True, None, {"record": record, "all": mech, "lookups": r.get("SPF_NUM_DNS_QUERIES")}, findings)


def _dmarc(r):
    findings = []
    if r.get("DMARC_MULTIPLE_RECORDS"):
        findings.append(finding("high", "DMARC_MULTIPLE", "Multiple DMARC records: DMARC is not applied (RFC 7489)", "Publish exactly one record."))
    elif not r.get("DMARC"):
        findings.append(finding("critical", "DMARC_MISSING", "No DMARC record: nothing tells receivers to reject spoofed mail",
                                'Publish _dmarc TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com", then tighten.'))
    else:
        if r.get("DMARC_POLICY") not in ("none", "quarantine", "reject"):
            findings.append(finding("high", "DMARC_BAD_P", "DMARC record has a missing or invalid p= policy (the record is ignored)",
                                    "Set p=none, p=quarantine or p=reject."))
        if not r.get("DMARC_AGGREGATE_REPORT"):
            findings.append(finding("low", "DMARC_NO_RUA", "No rua= address: you receive no aggregate reports and cannot see abuse or broken senders",
                                    "Add rua=mailto:<address>."))
    return check_result("DMARC", True, None, {"record": r.get("DMARC"), "policy": r.get("DMARC_POLICY")}, findings)


def _dkim(r):
    if not r.get("DKIM_ENABLED"):
        return check_result("DKIM", False, "not scanned (use --dkim)")
    live = [k for k in r.get("DKIM_ANALYSIS") or [] if k.get("live")]
    if not live:
        return check_result("DKIM", False, "no live selector found (discovery is wordlist-limited; absence is not a finding)")
    findings = []
    for key in live:
        sel, alerts = key["selector"], set(key.get("alerts", []))
        if key["overall"] == "critical":
            findings.append(finding("critical", "DKIM_WEAK_KEY", f"{sel}: {key['issues'][0]}", "Replace with an RSA key of at least 2048 bits.", sel))
        elif key["status"] == "weak":
            findings.append(finding("medium", "DKIM_KEY_1024", f"{sel}: 1024-bit RSA key", "Rotate to 2048-bit RSA.", sel))
        elif key["status"] == "invalid":
            findings.append(finding("medium", "DKIM_INVALID", f"{sel}: record is invalid ({'; '.join(key['issues'])})", evidence=sel))
        if "TESTING_MODE" in alerts:
            findings.append(finding("high", "DKIM_TESTING", f"{sel}: t=y testing mode is on, so verifiers treat the domain as unsigned",
                                    "Remove t=y.", sel))
        if "SHA1_ALLOWED" in alerts:
            findings.append(finding("medium", "DKIM_SHA1", f"{sel}: h= permits SHA-1 (forbidden by RFC 8301)", "Set h=sha256.", sel))
        if "SMALL_EXPONENT" in alerts:
            findings.append(finding("medium", "DKIM_EXPONENT", f"{sel}: small RSA public exponent", "Use e=65537.", sel))
    findings.extend(dkim_rotation_hints(r.get("DKIM")))
    for sig in r.get("DKIM_SIGNATURES") or []:
        if sig.get("alerts"):
            findings.append(finding("medium", "DKIM_SIG_SHA1", f"Sample message for selector {sig['selector']} is signed with rsa-sha1",
                                    "Configure the signer for rsa-sha256 or ed25519-sha256."))
    return check_result("DKIM", True, None, {"live_selectors": [k["selector"] for k in live]}, findings)


def _bimi(r):
    if not r.get("BIMI_RECORD"):
        return check_result("BIMI", False, "not deployed (optional)")
    findings = []
    if r.get("DMARC_POLICY") not in ("quarantine", "reject"):
        findings.append(finding("medium", "BIMI_NEEDS_ENFORCEMENT", "BIMI is published but DMARC is not enforced (p=quarantine/reject required)"))
    location = r.get("BIMI_LOCATION") or ""
    if not location.startswith("https://"):
        findings.append(finding("medium", "BIMI_LOCATION", "BIMI logo location (l=) is missing or not HTTPS"))
    if not r.get("BIMI_AUTHORITY"):
        findings.append(finding("low", "BIMI_NO_VMC", "No a= certificate (VMC/CMC): major mailbox providers will not show the logo",
                                "Obtain a VMC/CMC and publish its URL in a=. (Certificate validity is not checked by this tool.)"))
    return check_result("BIMI", True, None, {"record": r["BIMI_RECORD"]}, findings)


def _area_score(findings):
    return max(0, 100 - sum(SEVERITY_PENALTY[f["severity"]] for f in findings))


def _grade(score):
    return next(letter for floor, letter in GRADES if score >= floor)


def build_score(result, checks):
    """checks: {area: check_result} for the areas computed elsewhere (alignment + extended)."""
    areas = {"SPF": _spf(result), "DMARC": _dmarc(result), "DKIM": _dkim(result), "BIMI": _bimi(result)}
    areas.update(checks or {})
    out, not_assessed, weighted, total_weight = {}, [], 0.0, 0
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for name, weight in AREA_WEIGHTS.items():
        check = areas.get(name)
        if check is None:
            not_assessed.append({"area": name, "reason": "skipped (--basic)"})
            continue
        for item in check["findings"]:
            counts[item["severity"]] += 1
        if not check["applicable"]:
            not_assessed.append({"area": name, "reason": check.get("reason")})
            out[name] = {"score": None, "weight": weight, "applicable": False, "reason": check.get("reason"),
                         "findings": check["findings"], "data": check["data"]}
            continue
        score = _area_score(check["findings"])
        weighted += score * weight
        total_weight += weight
        out[name] = {"score": score, "weight": weight, "applicable": True, "reason": None,
                     "findings": check["findings"], "data": check["data"]}

    overall = round(weighted / total_weight) if total_weight else 0
    caps = []
    spoofable = result.get("SPOOFING_POSSIBLE")
    if spoofable is True and overall > CAP_SPOOFABLE:
        caps.append({"max": CAP_SPOOFABLE, "reason": "the domain can be spoofed (SPF/DMARC verdict)"})
    elif spoofable is None and result.get("SPOOFING_TYPE") and overall > CAP_POSSIBLE:
        caps.append({"max": CAP_POSSIBLE, "reason": "spoofing could not be ruled out"})
    if counts["critical"] and overall > CAP_CRITICAL:
        caps.append({"max": CAP_CRITICAL, "reason": "at least one critical finding"})
    if caps:
        overall = min(overall, *(c["max"] for c in caps))
        caps = [c for c in caps if c["max"] == overall]  # report only the cap that actually binds
    return {"version": SCORING_VERSION, "overall": overall, "grade": _grade(overall), "caps": caps,
            "finding_counts": counts, "areas": out, "not_assessed": not_assessed,
            "note": "Heuristic configuration-strength score; not an industry standard."}
