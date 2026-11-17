# modules/dnsutil.py
"""One place for DNS lookups that distinguishes absence from failure."""

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.resolver

from .resolver_cache import get_resolver


def lookup(name, rtype, dns_server, configure=None):
    """Return (status, answers, error).

    status: "ok" | "nxdomain" | "nodata" | "error". NXDOMAIN/NODATA mean the
    record is absent; "error" (timeout, SERVFAIL, ...) means *unknown* and must
    never be reported as absence.
    """
    try:
        resolver = get_resolver(dns_server)
        resolver.timeout, resolver.lifetime = 5, 8
        if configure:
            configure(resolver)
        return "ok", resolver.resolve(name, rtype), None
    except dns.resolver.NXDOMAIN:
        return "nxdomain", [], None
    except dns.resolver.NoAnswer:
        return "nodata", [], None
    except dns.exception.Timeout:
        return "error", [], "timeout"
    except dns.resolver.NoNameservers:
        return "error", [], "SERVFAIL"
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        return "error", [], type(exc).__name__


def text(value):
    """bytes/str/Name -> str (dnspython returns bytes for CAA tag/value)."""
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)


def direct_soa(ip, name, timeout=4):
    """Ask one authoritative server directly for the SOA of `name`.

    Returns (serial | None, authoritative, error | None). Used to find lame
    delegations (no AA flag / REFUSED / no answer) and out-of-sync serials.
    """
    try:
        query = dns.message.make_query(name, "SOA")
        response = dns.query.udp(query, ip, timeout=timeout)
        if response.flags & dns.flags.TC:
            response = dns.query.tcp(query, ip, timeout=timeout)
    except dns.exception.Timeout:
        return None, False, "timeout"
    except Exception as exc:  # noqa: BLE001
        return None, False, type(exc).__name__
    if response.rcode() != 0:
        return None, False, f"rcode {response.rcode()}"
    serial = None
    for rrset in response.answer:
        for rdata in rrset:
            if hasattr(rdata, "serial"):
                serial = int(rdata.serial)
    return serial, bool(response.flags & dns.flags.AA), None
