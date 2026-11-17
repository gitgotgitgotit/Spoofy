"""Syntax validation for SPF and DMARC records."""
import re
from .spf_parser import validate_spf


def validate_record_syntax(record, record_type):
    if record_type == "SPF":
        return validate_spf(record)
    if record_type != "DMARC" or not isinstance(record, str):
        return False
    tags = {}
    for item in record.split(";"):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            return False
        key, value = item.split("=", 1)
        key, value = key.strip().lower(), value.strip()
        if key in tags or not value:
            return False
        tags[key] = value
    if tags.get("v", "").upper() != "DMARC1" or tags.get("p", "").lower() not in {"none", "quarantine", "reject"}:
        return False
    patterns = {
        "sp": r"^(none|quarantine|reject)$", "pct": r"^(100|[1-9]?\d)$",
        "rf": r"^afrf(?:\s*,\s*afrf)*$", "fo": r"^(?:0|1|d|s)(?::(?:0|1|d|s))*$",
        "ri": r"^\d+$", "aspf": r"^(r|s)$", "adkim": r"^(r|s)$",
    }
    for key, pattern in patterns.items():
        if key in tags and not re.fullmatch(pattern, tags[key], re.I):
            return False
    for key in ("rua", "ruf"):
        if key in tags:
            for uri in tags[key].split(","):
                uri = uri.strip()
                if not re.fullmatch(r"mailto:[^\s@,;]+@[^\s@,;]+(?:!\d+[kmgt]?)?", uri, re.I):
                    return False
    # Unknown extension tags are permitted by DMARC; consumers should ignore them.
    return True
