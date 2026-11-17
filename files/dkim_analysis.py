"""Cryptographic strength analysis for discovered DKIM public-key records.

The analyzer separates key quality from discovery failures: a selector that
could not be queried is never represented as a weak key. Public keys are parsed
with ``cryptography`` (with a small DER fallback for keys too small for the
local OpenSSL to load) so sizes and types come from the encoded key itself.

Each result carries:
  status   key strength: critical | weak | good | strong | revoked | unsupported | invalid
  overall  what to show/alert on: critical | warning | good | strong | info
           (a "good" key with t=y or SHA-1 allowed is downgraded to "warning")
  alerts   machine-readable codes, e.g. WEAK_KEY_512, WEAK_KEY_768,
           TESTING_MODE, SHA1_ALLOWED
  live     False for keys that only came from an archive (historical data)
"""

import base64
import binascii

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

KNOWN_TAGS = ("v", "h", "k", "n", "p", "s", "t")

# Alerts that downgrade an otherwise fine key to "warning".
WARNING_ALERTS = {"SHA1_ALLOWED", "TESTING_MODE", "SMALL_EXPONENT", "KEY_1024"}
CRITICAL_ALERT_PREFIX = "WEAK_KEY_"

SEVERITY_RANK = {"critical": 2, "warning": 1}
FAIL_ON_RANK = {"weak": 1, "critical": 2}

SOURCE_NOTES = {
    "archive-historical": "Seen only in archive.prove.email; the selector is no longer in live DNS. Historical data, not a live finding.",
    "archive-unverified": "Seen in archive.prove.email; the live DNS lookup failed, so this key could not be confirmed as current.",
}


class _NotRSA(ValueError):
    pass


def parse_tags(record):
    """Return DKIM tag/value pairs. Tag names are case-sensitive (RFC 6376)."""
    if not isinstance(record, str):
        raise ValueError("DKIM record is not text")
    tags = {}
    for part in record.strip().strip('"').split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if not name:
            continue
        if name in tags:
            raise ValueError(f"duplicate DKIM tag: {name}")
        tags[name] = value.strip()
    return tags


_parse_tags = parse_tags  # backwards-compatible alias


# --- minimal DER reader: lets us size RSA keys OpenSSL refuses to load ---------
def _der_read(buf, pos):
    tag, length = buf[pos], buf[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4:
            raise ValueError("bad DER length")
        length = int.from_bytes(buf[pos:pos + count], "big")
        pos += count
    end = pos + length
    if end > len(buf):
        raise ValueError("truncated DER")
    return tag, pos, end


def _rsa_numbers_from_der(raw):
    """Return (modulus, exponent) from SPKI or PKCS#1 DER without OpenSSL."""
    try:
        tag, start, _ = _der_read(raw, 0)
        if tag != 0x30:
            raise ValueError("not a DER SEQUENCE")
        t1, s1, e1 = _der_read(raw, start)
        if t1 == 0x30:  # SubjectPublicKeyInfo: AlgorithmIdentifier, BIT STRING
            t2, s2, e2 = _der_read(raw, e1)
            if t2 != 0x03:
                raise ValueError("expected BIT STRING")
            return _rsa_numbers_from_der(raw[s2 + 1:e2])
        if t1 != 0x02:
            raise ValueError("expected INTEGER")
        t2, s2, e2 = _der_read(raw, e1)
        if t2 != 0x02:
            raise ValueError("expected INTEGER")
        return int.from_bytes(raw[s1:e1], "big"), int.from_bytes(raw[s2:e2], "big")
    except IndexError:
        raise ValueError("malformed DER")


def _load_rsa(raw):
    """Return (bits, exponent). Falls back to raw DER for sub-1024-bit keys."""
    try:
        key = serialization.load_der_public_key(raw)
        if not isinstance(key, rsa.RSAPublicKey):
            raise _NotRSA("not an RSA key")
        return key.key_size, key.public_numbers().e
    except _NotRSA:
        raise
    except (ValueError, TypeError, UnsupportedAlgorithm) as original:
        try:
            modulus, exponent = _rsa_numbers_from_der(raw)
        except ValueError:
            raise original
        bits = modulus.bit_length()
        if bits >= 1024:  # OpenSSL rejected a normal-sized key: genuinely broken
            raise original
        return bits, exponent


def _weak_rsa(result, bits):
    """Explicit alerts for sub-1024-bit RSA keys (512 / 768 get their own code)."""
    result.update(status="critical", strength="critical")
    if bits <= 512:
        code = "WEAK_KEY_512"
        how = ("512-bit RSA has been factored in hours on rented cloud hardware" if bits == 512
               else "keys this small are trivially factorable")
        text = (f"RSA key is {bits} bits: {how}, so the private key can be recovered and DKIM signatures forged")
    elif bits <= 768:
        code = "WEAK_KEY_768"
        text = (f"RSA key is {bits} bits: 768-bit RSA was factored publicly in 2009 and is within "
                "reach of well-resourced attackers; DKIM signatures may be forgeable")
    else:
        code = "WEAK_KEY_SUB1024"
        text = f"RSA key is {bits} bits; below the 1024-bit minimum in RFC 8301"
    result["alerts"].append(code)
    result["issues"].append(text)
    result["recommendations"].append("Replace immediately with an RSA key of at least 2048 bits")


def _new_result(selector, source):
    return {
        "selector": selector,
        "source": source,
        "live": source == "dns",
        "key_type": None,
        "key_bits": None,
        "status": "invalid",
        "strength": "unknown",
        "overall": "warning",
        "revoked": False,
        "alerts": [],
        "issues": [],
        "notes": [],
        "recommendations": [],
    }


def _analyze_into(result, record):
    try:
        tags = parse_tags(record)
    except ValueError as exc:
        result["issues"].append(str(exc))
        return

    for name in tags:  # RFC 6376: tag names are case-sensitive
        if name not in KNOWN_TAGS and name.lower() in KNOWN_TAGS:
            result["issues"].append(f"tag name {name}= must be lowercase; verifiers ignore it")

    version = tags.get("v")
    if version is not None and next(iter(tags), None) != "v":
        result["issues"].append("DKIM version tag v= must be the first tag")
        return
    if version is not None and version != "DKIM1":
        result["issues"].append(f"unexpected DKIM version: {version} (must be exactly DKIM1)")
        return

    key_type = tags.get("k", "rsa").lower()
    result["key_type"] = key_type
    if "p" not in tags:
        result["issues"].append("public-key tag p= is missing")
        return

    encoded_key = "".join(tags["p"].split())
    if not encoded_key:
        result.update(status="revoked", strength="revoked", revoked=True)
        result["alerts"].append("REVOKED")
        result["issues"].append("public key is empty; selector is revoked")
        return

    try:
        raw_key = base64.b64decode(encoded_key + "=" * (-len(encoded_key) % 4), validate=True)
    except (binascii.Error, ValueError):
        result["issues"].append("public key is not valid Base64")
        return

    try:
        if key_type == "rsa":
            bits, exponent = _load_rsa(raw_key)
            result["key_bits"] = bits
            if bits < 1024:
                _weak_rsa(result, bits)
            elif bits < 2048:
                result.update(status="weak", strength="weak")
                result["alerts"].append("KEY_1024")
                result["issues"].append(f"RSA key is {bits} bits; below the 2048-bit recommendation "
                                        "(1024 is the RFC 8301 minimum and is within reach of nation-state attackers)")
                result["recommendations"].append("Rotate to an RSA key of at least 2048 bits")
            elif bits < 3072:
                result.update(status="good", strength="good")
                result["recommendations"].append("2048-bit RSA meets the common DKIM baseline; consider 3072 bits for a higher margin")
            else:
                result.update(status="strong", strength="strong")
            if bits > 4096:
                result["recommendations"].append("Check DNS and mail-provider compatibility with unusually large DKIM keys")
            if exponent < 65537:
                result["alerts"].append("SMALL_EXPONENT")
                result["issues"].append(f"RSA public exponent is {exponent}; 65537 is standard, and small exponents "
                                        "have enabled signature-forgery attacks against sloppy verifiers")
        elif key_type == "ed25519":
            if len(raw_key) != 32:  # DKIM Ed25519 keys are 32 raw bytes, not DER
                result["issues"].append(f"Ed25519 public key must be 32 bytes, got {len(raw_key)}")
                return
            ed25519.Ed25519PublicKey.from_public_bytes(raw_key)
            result.update(key_bits=256, status="strong", strength="strong")
        else:
            result["status"] = "unsupported"
            result["issues"].append(f"unsupported DKIM key type: {key_type}")
            return
    except _NotRSA:
        result["issues"].append("key type is rsa but encoded key is not RSA")
        return
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        result["issues"].append(f"public key could not be decoded: {exc}")
        return

    # Hash algorithms (h=): which digests this key accepts.
    hash_tag = tags.get("h")
    if hash_tag:
        allowed = {item.strip().lower() for item in hash_tag.split(":") if item.strip()}
        if "sha1" in allowed:
            result["alerts"].append("SHA1_ALLOWED")
            only = " (and ONLY sha1)" if allowed == {"sha1"} else ""
            result["issues"].append(f"h= permits SHA-1{only}; RFC 8301 forbids SHA-1 for DKIM signing and verification")
            result["recommendations"].append("Set h=sha256 or remove SHA-1 from h=")
    else:
        result["alerts"].append("NO_HASH_RESTRICTION")
        result["notes"].append("no h= tag: the key accepts every hash algorithm, including SHA-1; consider h=sha256")

    service_types = tags.get("s")
    if service_types and "*" in {item.strip() for item in service_types.split(":")}:
        result["notes"].append("service type includes wildcard (*), allowing all service types")

    # Flags (t=): y = testing mode, s = strict identity.
    flags = {item.strip().lower() for item in tags.get("t", "").split(":") if item.strip()}
    if "y" in flags:
        result["alerts"].append("TESTING_MODE")
        result["issues"].append("t=y (testing mode) is set: verifiers are told to treat this domain's DKIM "
                                "as if unsigned, so it gives no protection until t=y is removed")
        result["recommendations"].append("Remove t=y once DKIM rollout is complete")
    if "s" in flags:
        result["notes"].append("strict identity flag t=s is set")


def _finalize(result):
    status, alerts = result["status"], result["alerts"]
    if status == "critical" or any(a.startswith(CRITICAL_ALERT_PREFIX) for a in alerts):
        overall = "critical"
    elif status in ("weak", "invalid") or WARNING_ALERTS.intersection(alerts):
        overall = "warning"
    elif status in ("good", "strong"):
        overall = status
    else:  # revoked / unsupported
        overall = "info"
    result["overall"] = overall
    note = SOURCE_NOTES.get(result["source"])
    if note:
        result["notes"].insert(0, note)


def analyze_dkim_key(selector, record, source="dns"):
    """Analyze one DKIM key record and return a JSON-serializable result.

    `source` is "dns" for a key seen in live DNS; any other value (archive-*)
    marks the result as non-live so it is never reported as a current finding.
    """
    result = _new_result(selector, source)
    _analyze_into(result, record)
    _finalize(result)
    return result


def analyze_dkim_keys(records, sources=None):
    """Analyze a mapping of selector -> DKIM TXT value (sources: selector -> source)."""
    sources = sources or {}
    return [analyze_dkim_key(sel, value, sources.get(sel, "dns")) for sel, value in sorted(records.items())]


def severity_rank(item):
    """0 = fine, 1 = warning, 2 = critical; non-live (archive) items always 0."""
    if not item.get("live", True):
        return 0
    return SEVERITY_RANK.get(item.get("overall"), 0)


def sort_by_severity(analysis):
    """Worst live findings first, then by selector name."""
    return sorted(analysis or [], key=lambda item: (-severity_rank(item), not item.get("live", True), item.get("selector", "")))


def worst_live_rank(analysis):
    return max((severity_rank(item) for item in analysis or []), default=0)


def forgeable_keys(analysis):
    """Live RSA keys below 1024 bits (factorable): usable for DKIM forgery."""
    return [item for item in analysis or []
            if item.get("live") and item.get("key_type") == "rsa" and item.get("overall") == "critical"
            and (item.get("key_bits") or 0) < 1024]
