# modules/alignment.py
"""DMARC alignment and enforcement analysis (SPF/DKIM alignment modes, policy strength)."""

from .findings import check_result, finding

RANK = {"none": 0, "quarantine": 1, "reject": 2}


def _mode(value):
    """Return (effective mode, invalid?). Absent/invalid values behave as relaxed."""
    if value is None:
        return "relaxed", False
    if value in ("r", "s"):
        return ("relaxed" if value == "r" else "strict"), False
    return "relaxed", True


def check_alignment(dmarc_record, policy, pct, aspf, adkim, sp, inherited, has_rua, spf_record,
                    dkim_enabled=False, dkim_analysis=None):
    if not dmarc_record:
        return check_result("DMARC alignment", False, "no DMARC record")
    findings = []
    spf_mode, spf_bad = _mode(aspf)
    dkim_mode, dkim_bad = _mode(adkim)
    for tag, bad in (("aspf", spf_bad), ("adkim", dkim_bad)):
        if bad:
            findings.append(finding("medium", f"ALIGN_BAD_{tag.upper()}", f"{tag}= has an invalid value; receivers treat it as relaxed",
                                    f"Use {tag}=r (relaxed) or {tag}=s (strict)."))
    data = {"spf_alignment": spf_mode, "dkim_alignment": dkim_mode, "effective_policy": None, "pct": pct}

    effective = sp if (inherited and sp in RANK) else policy
    data["effective_policy"] = effective
    if effective in RANK:
        if effective == "none":
            severity = "medium" if has_rua else "high"
            findings.append(finding(severity, "ALIGN_P_NONE",
                                    "DMARC policy is p=none: failing mail is delivered, so the domain can be spoofed"
                                    + ("" if has_rua else " and nothing is being reported"),
                                    "Review rua reports, fix legitimate senders, then move to p=quarantine and p=reject."))
        elif effective == "quarantine":
            findings.append(finding("low", "ALIGN_P_QUARANTINE", "DMARC policy is p=quarantine: spoofed mail is only sent to spam",
                                    "Move to p=reject once reports show no legitimate failures."))
        try:
            percent = int(pct) if pct is not None else 100
            if not 0 <= percent <= 100:
                raise ValueError
        except ValueError:
            percent = 100
            findings.append(finding("low", "ALIGN_BAD_PCT", f"pct={pct} is not a valid percentage (0-100)"))
        if effective != "none" and percent < 100:
            findings.append(finding("medium" if percent < 50 else "low", "ALIGN_PCT",
                                    f"Policy applies to only {percent}% of failing mail",
                                    "Raise pct to 100 (or remove it) once rollout is complete."))
    if sp in RANK and policy in RANK and RANK[sp] < RANK[policy]:
        findings.append(finding("medium", "ALIGN_SP_WEAKER", f"Subdomain policy sp={sp} is weaker than p={policy}: subdomains are easier to spoof",
                                "Set sp to the same value as p (or remove sp)."))

    live_keys = [k for k in dkim_analysis or [] if k.get("live")]
    if not spf_record:
        if not dkim_enabled:
            findings.append(finding("medium", "ALIGN_NO_SPF", "No SPF record, so DMARC can only pass through DKIM alignment (DKIM was not checked; use --dkim)"))
        elif live_keys:
            findings.append(finding("low", "ALIGN_DKIM_ONLY", "No SPF record: DMARC relies on DKIM alignment alone"))
        else:
            findings.append(finding("medium", "ALIGN_NOTHING_FOUND",
                                    "No SPF record and no DKIM key discovered: no aligned mechanism could be confirmed (DKIM discovery is wordlist-limited)",
                                    "Publish SPF and/or DKIM for every legitimate sender; try --dkim-header with a real message."))
    if spf_mode == "strict" or dkim_mode == "strict":
        findings.append(finding("info", "ALIGN_STRICT", "Strict alignment is set: mail signed or sent from subdomains or third parties "
                                "under a different domain will fail DMARC; verify all senders align"))
    if spf_mode == "relaxed" and dkim_mode == "relaxed" and not (spf_bad or dkim_bad):
        findings.append(finding("info", "ALIGN_RELAXED", "Relaxed alignment (default): any subdomain of the organizational domain aligns"))
    return check_result("DMARC alignment", True, None, data, findings)
