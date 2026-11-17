# modules/findings.py
"""Shared finding / check-result shapes used by the assessment modules and the score."""

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_PENALTY = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 0}


def finding(severity, code, title, fix=None, evidence=None):
    if severity not in SEVERITY_PENALTY:
        raise ValueError(f"unknown severity: {severity}")
    return {"severity": severity, "code": code, "title": title, "fix": fix, "evidence": evidence}


def check_result(area, applicable=True, reason=None, data=None, findings=None):
    """applicable=False means "not assessed / not deployed": excluded from the score, never penalised."""
    return {"area": area, "applicable": applicable, "reason": reason, "data": data or {}, "findings": findings or []}
