# modules/txt.py
"""Shared helpers for turning dnspython TXT rdata into plain strings."""


def txt_value(rdata):
    """Return the full TXT value with its <character-string> chunks joined.

    A TXT record longer than 255 bytes is stored as several chunks. Joining the
    raw bytes (instead of stripping quotes from str(rdata), which leaves a space
    between chunks) keeps long DMARC/DKIM/BIMI values intact.
    """
    strings = getattr(rdata, "strings", None)
    if strings is not None:
        return b"".join(strings).decode("utf-8", errors="replace")
    return str(rdata).replace('" "', "").strip('"')
