# modules/inputs.py
"""Normalisation of user-supplied domain input (-d / -iL)."""

import re
from urllib.parse import urlsplit

_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


def normalize_domain(raw):
    """Return a clean lowercase ASCII domain, or None if `raw` is not usable.

    Accepts plain domains, URLs (https://Example.com/path), e-mail addresses,
    host:port, trailing dots, unicode (IDNA) names and inline '# comments'.
    """
    if raw is None:
        return None
    text = raw.split("#", 1)[0].strip()
    if not text:
        return None
    if "://" in text:
        text = urlsplit(text).hostname or ""
    else:
        if "@" in text:
            text = text.rsplit("@", 1)[1]
        text = text.split("/", 1)[0].split(":", 1)[0]
    text = text.strip().rstrip(".").lower()
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = text.split(".")
    if len(text) > 253 or len(labels) < 2 or not all(_LABEL.match(l) for l in labels):
        return None
    return text


def load_domains(lines):
    """Normalise and de-duplicate (order preserving) an iterable of lines.

    Returns (domains, rejected) where rejected holds the non-blank, non-comment
    lines that could not be understood as a domain.
    """
    seen, domains, rejected = set(), [], []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        domain = normalize_domain(stripped)
        if domain is None:
            rejected.append(stripped)
        elif domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains, rejected
