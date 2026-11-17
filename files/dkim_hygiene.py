# modules/dkim_hygiene.py
"""DKIM rotation hints from DNS alone.

DNS cannot tell the age of a key. These are heuristics, and are labelled that way:
  * the same public key under several selectors (rotation does not isolate keys), and
  * date-looking selector names (s202301, 2023-01) whose newest date is old.
"""

import re
import time

from .dkim_analysis import parse_tags
from .findings import finding

_DATE_SELECTOR = re.compile(r"^[a-z]*[-_]?(20\d{2})(?:[-_]?(0[1-9]|1[0-2]))?(?:[-_]?(?:0[1-9]|[12]\d|3[01]))?$", re.I)
STALE_MONTHS = 18


def _public_key(record):
    try:
        return "".join(parse_tags(record).get("p", "").split()) or None
    except ValueError:
        return None


def dkim_rotation_hints(records, now=None, stale_months=STALE_MONTHS):
    live = [r for r in records or [] if r.get("source") == "dns"]
    findings = []
    by_key = {}
    for rec in live:
        key = _public_key(rec["record"])
        if key:
            by_key.setdefault(key, []).append(rec["selector"])
    for selectors in by_key.values():
        if len(selectors) > 1:
            findings.append(finding("low", "DKIM_KEY_REUSED",
                                    f"The same public key is published under selectors {', '.join(sorted(selectors))}: rotating one selector does not retire the key",
                                    "Give each selector its own key pair, and retire old selectors after rotation.", sorted(selectors)))
    current = time.gmtime(now if now is not None else time.time())
    dated = []
    for rec in live:
        match = _DATE_SELECTOR.match(rec["selector"])
        if not match:
            continue
        year, month = int(match.group(1)), int(match.group(2) or 12)  # year-only: assume December (least alarmist)
        if year <= current.tm_year + 1:
            dated.append(((year, month), rec["selector"]))
    if dated:
        (year, month), selector = max(dated)
        age = (current.tm_year - year) * 12 + (current.tm_mon - month)
        if age >= stale_months:
            findings.append(finding("low", "DKIM_ROTATION_STALE",
                                    f"Newest date-named selector {selector} looks about {age} months old (heuristic from the name, not the key's real age): rotation may be overdue",
                                    "Rotate DKIM keys at least yearly; publish a new selector and retire the old one.", selector))
    return findings
