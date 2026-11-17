"""Small, RFC-aware SPF parser shared by validation and intelligence reporting."""
from dataclasses import dataclass
import ipaddress
import re

DOMAIN_RE = re.compile(r"(?=.{1,253}\.?$)(?:[A-Za-z0-9_%{}-]+\.)+[A-Za-z0-9_%{}-]+\.?$")

@dataclass(frozen=True)
class SPFTerm:
    raw: str
    qualifier: str = "+"
    mechanism: str = ""
    value: str = ""
    modifier: bool = False


def parse_spf(record):
    if not isinstance(record, str):
        raise ValueError("SPF record must be text")
    parts = record.strip().split()
    if not parts or parts[0].lower() != "v=spf1":
        raise ValueError("SPF record must begin with v=spf1")
    terms = []
    for raw in parts[1:]:
        if "=" in raw and (":" not in raw or raw.index("=") < raw.index(":")):
            key, value = raw.split("=", 1)
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", key) or not value:
                raise ValueError(f"Invalid SPF modifier: {raw}")
            terms.append(SPFTerm(raw, mechanism=key.lower(), value=value, modifier=True))
            continue
        qualifier = raw[0] if raw[:1] in "+-~?" else "+"
        token = raw[1:] if raw[:1] in "+-~?" else raw
        if ":" in token:
            mechanism, value = token.split(":", 1)
        elif "/" in token:
            mechanism, suffix = token.split("/", 1)
            value = "/" + suffix
        else:
            mechanism, value = token, ""
        mechanism = mechanism.lower()
        if mechanism not in {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}:
            raise ValueError(f"Unknown SPF mechanism: {mechanism}")
        terms.append(SPFTerm(raw, qualifier, mechanism, value))
    return terms


def _valid_domain(value):
    # SPF domain-spec permits underscore labels and macro expansions.
    name = value.split("/", 1)[0].rstrip(".")
    if not DOMAIN_RE.fullmatch(name + "."):
        return False
    if any(not label or len(label) > 63 for label in name.split(".")):
        return False
    return True


def validate_spf(record):
    try:
        terms = parse_spf(record)
        seen_modifiers = set()
        all_count = 0
        all_positions = []
        for index, term in enumerate(terms):
            m, value = term.mechanism, term.value
            if term.modifier:
                if m in seen_modifiers:
                    return False
                if m in {"redirect", "exp"} and not _valid_domain(value):
                    return False
                seen_modifiers.add(m)
                continue
            if m == "all":
                all_count += 1
                all_positions.append(index)
                if value:
                    return False
            elif m in {"include", "exists"}:
                if not _valid_domain(value):
                    return False
            elif m in {"a", "mx", "ptr"}:
                if m == "ptr" and "/" in value:
                    return False
                if value:
                    if value.startswith("/"):
                        domain_part, cidr = "", value
                    else:
                        domain_part, _, cidr = value.partition("/")
                    if domain_part and not _valid_domain(domain_part):
                        return False
                    if cidr:
                        pieces = cidr.replace("//", "/").lstrip("/").split("/")
                        if len(pieces) > 2 or not all(x.isdigit() for x in pieces):
                            return False
                        if int(pieces[0]) > 32 or (len(pieces) == 2 and int(pieces[1]) > 128):
                            return False
            elif m == "ip4":
                try:
                    ipaddress.IPv4Network(value, strict=False)
                except ValueError:
                    return False
            elif m == "ip6":
                try:
                    ipaddress.IPv6Network(value, strict=False)
                except ValueError:
                    return False
        if all_count > 1:
            return False
        if all_positions and any(not term.modifier for term in terms[all_positions[0] + 1:]):
            return False
        return True
    except (ValueError, TypeError):
        return False
