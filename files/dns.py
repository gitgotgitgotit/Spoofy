"""DNS discovery and retrieval of email-authentication records."""
import dns.resolver
import tldextract
from .spf import SPF
from .dmarc import DMARC
from .bimi import BIMI
from .resolver_cache import get_resolver


class DNS:
    def __init__(self, domain):
        self.domain = domain
        self.soa_record = None
        self.soa_mname = None
        self.dns_server = "1.1.1.1"
        self.spf_record = None
        self.dmarc_record = None
        self.bimi_record = None
        self.get_soa_record()
        self.get_dns_server()

    def _soa_names(self):
        """Names to try for SOA: the domain, then its registered domain (a plain
        subdomain has no SOA of its own, which used to make every server look dead)."""
        apex = tldextract.extract(self.domain).registered_domain
        return list(dict.fromkeys([self.domain, apex or self.domain]))

    def _resolve_soa(self, resolver):
        for name in self._soa_names():
            try:
                return resolver.resolve(name, "SOA")
            except (dns.exception.DNSException, OSError, ValueError):
                continue
        return None

    def get_soa_record(self):
        answer = self._resolve_soa(get_resolver("1.1.1.1"))
        self.soa_mname = str(answer[0].mname).rstrip(".") if answer else None
        # soa_record used to be socket.gethostbyname(mname). That went through the
        # *system* resolver (bypassing the configured one, leaking the query and
        # blocking) and the value was never used, so it now just mirrors the MNAME.
        self.soa_record = self.soa_mname

    def get_dns_server(self):
        # An SOA MNAME is authoritative metadata, not necessarily a recursive
        # resolver. Use known recursive resolvers and choose based on query
        # success, not on whether SPF and DMARC both happen to exist.
        for server in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
            if self._resolve_soa(get_resolver(server)) is None:
                continue
            self.dns_server = server
            break
        self.spf_record = SPF(self.domain, self.dns_server)
        self.dmarc_record = DMARC(self.domain, self.dns_server)
        self.bimi_record = BIMI(self.domain, self.dns_server)

    def get_txt_record(self, record_type):
        try:
            query = get_resolver(self.dns_server).resolve(self.domain, record_type)
            return str(query[0]) if query else None
        except (dns.exception.DNSException, OSError, ValueError):
            return None

    def __str__(self):
        return (f"Domain: {self.domain}\nSOA Record: {self.soa_record}\nDNS Server: {self.dns_server}\n"
                f"SPF Record: {self.spf_record.spf_record}\nDMARC Record: {self.dmarc_record.dmarc_record}\n"
                f"BIMI Record: {self.bimi_record.bimi_record}")
