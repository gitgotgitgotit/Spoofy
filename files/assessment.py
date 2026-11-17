# modules/assessment.py
"""Runs the DNS-only checks and turns everything into the configuration score."""

import concurrent.futures

from .alignment import check_alignment
from .caa import check_caa
from .dmarc_reporting import check_dmarc_reporting
from .dnssec import check_dnssec
from .findings import check_result, finding
from .ipv6 import check_ipv6
from .mx import check_mx
from .nameservers import check_nameservers
from .nonsending import check_nonsending
from .scoring import build_score
from .spf_hardening import check_spf_hardening
from .spf_walk import walk_spf
from .takeover import check_takeover
from .tlsrpt import check_tlsrpt


def _safe(area, func, *args):
    """A failing check must never take the whole domain scan down."""
    try:
        return func(*args)
    except Exception as exc:  # noqa: BLE001
        reason = f"check failed: {type(exc).__name__}"
        return check_result(area, False, reason, {}, [finding("info", f"{area.upper()}_ERROR", f"{area} check failed ({type(exc).__name__}: {exc})")])


def assess(result, dns_server, extended=True):
    """Return {"score": ..., "checks": {area: check_result}} for one scanned domain."""
    domain = result["DOMAIN"]
    inherited = bool(result.get("DMARC_RECORD_DOMAIN")) and result["DMARC_RECORD_DOMAIN"] != domain
    checks = {"DMARC alignment": _safe(
        "DMARC alignment", check_alignment, result.get("DMARC"), result.get("DMARC_POLICY"), result.get("DMARC_PCT"),
        result.get("DMARC_ASPF"), result.get("DMARC_ADKIM"), result.get("DMARC_SP"), inherited,
        bool(result.get("DMARC_AGGREGATE_REPORT")), result.get("SPF"), bool(result.get("DKIM_ENABLED")), result.get("DKIM_ANALYSIS"))}
    if extended:
        spf = result.get("SPF")
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = {"DNSSEC": pool.submit(_safe, "DNSSEC", check_dnssec, domain, dns_server),
                       "MX": pool.submit(_safe, "MX", check_mx, domain, dns_server),
                       "CAA": pool.submit(_safe, "CAA", check_caa, domain, dns_server),
                       "TLS-RPT": pool.submit(_safe, "TLS-RPT", check_tlsrpt, domain, dns_server),
                       "Nameservers": pool.submit(_safe, "Nameservers", check_nameservers, domain, dns_server),
                       "DMARC reporting": pool.submit(_safe, "DMARC reporting", check_dmarc_reporting, domain, dns_server,
                                                      result.get("DMARC"), result.get("DMARC_RECORD_DOMAIN")),
                       "_walk": pool.submit(walk_spf, domain, spf, dns_server)}
            for area, future in futures.items():
                try:
                    checks[area] = future.result()
                except Exception as exc:  # noqa: BLE001 - only the walk can raise here; see _safe for the rest
                    checks[area] = {"area": area, "applicable": False, "reason": f"check failed: {type(exc).__name__}", "data": {}, "findings": []}
        walk = checks.pop("_walk")
        if "includes" not in walk:  # the walk itself failed: continue without it
            walk = {"includes": [], "void_lookups": 0, "lookups": 0, "ptr": False, "ip_ranges": [], "errors": [], "truncated": False}
        mx_data = checks["MX"]["data"]
        checks["IPv6"] = _safe("IPv6", check_ipv6, domain, dns_server, mx_data.get("records"), spf)
        checks["Non-sending hygiene"] = _safe("Non-sending hygiene", check_nonsending, domain, dns_server, mx_data, result)
        checks["Takeover risk"] = _safe("Takeover risk", check_takeover, domain, dns_server, walk,
                                        checks["Nameservers"]["data"], result.get("DKIM_DANGLING_CNAMES"))
        checks["SPF hardening"] = _safe("SPF hardening", check_spf_hardening, spf, walk,
                                        checks["Takeover risk"]["data"].get("unregistered_targets", []))
    return {"score": build_score(result, checks), "checks": {k: v["data"] for k, v in checks.items()}}
