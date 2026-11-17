"""Minimal stand-ins for dnspython/tldextract, installed ONLY if the real packages are missing.

Lets the offline tests run without network access. With the real packages present
this is a no-op, so the same tests exercise the real exception classes.
"""
import sys
import types


def install():
    try:
        import dns.exception  # noqa: F401
        import dns.resolver  # noqa: F401
    except ImportError:
        dns = types.ModuleType("dns")
        exc = types.ModuleType("dns.exception")
        res = types.ModuleType("dns.resolver")

        class DNSException(Exception):
            pass

        class Timeout(DNSException):
            pass

        exc.DNSException, exc.Timeout = DNSException, Timeout
        for name in ("NXDOMAIN", "NoAnswer", "NoNameservers"):
            setattr(res, name, type(name, (DNSException,), {}))

        class LRUCache:
            def __init__(self, *a, **k):
                pass

        class Resolver:
            def __init__(self, *a, **k):
                self.nameservers, self.cache = [], None

            def resolve(self, *a, **k):
                raise res.NXDOMAIN()

        res.LRUCache, res.Resolver = LRUCache, Resolver
        flags = types.ModuleType("dns.flags")
        flags.RD, flags.CD, flags.AD, flags.DO, flags.AA, flags.TC = 0x0100, 0x0010, 0x0020, 0x8000, 0x0400, 0x0200
        message, query = types.ModuleType("dns.message"), types.ModuleType("dns.query")
        message.make_query = lambda *a, **k: None
        query.udp = query.tcp = lambda *a, **k: (_ for _ in ()).throw(Timeout())
        dns.exception, dns.resolver, dns.flags, dns.message, dns.query = exc, res, flags, message, query
        sys.modules.update({"dns": dns, "dns.exception": exc, "dns.resolver": res, "dns.flags": flags,
                            "dns.message": message, "dns.query": query})

    try:
        import tldextract  # noqa: F401
    except ImportError:
        ext = types.ModuleType("tldextract")

        def extract(domain):
            labels = domain.split(".")
            registered = ".".join(labels[-2:]) if len(labels) >= 2 else domain
            return types.SimpleNamespace(registered_domain=registered,
                                         subdomain=".".join(labels[:-2]), domain=labels[-2] if len(labels) > 1 else domain,
                                         suffix=labels[-1])

        ext.extract = extract
        sys.modules["tldextract"] = ext
