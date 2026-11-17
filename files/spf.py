"""SPF record retrieval and RFC 7208 DNS-term accounting."""
import dns.resolver
from .resolver_cache import get_resolver
from .spf_parser import parse_spf
from .txt import txt_value as _txt_value


class SPF:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server
        self.multiple_spf_records = False
        self.spf_record = self.get_spf_record()
        self.all_mechanism = self.get_spf_all_string() if self.spf_record else None
        self.spf_dns_query_count = self.get_spf_dns_queries() if self.spf_record else 0
        self.too_many_dns_queries = self.spf_dns_query_count > 10

    def get_spf_record(self, domain=None):
        try:
            resolver = get_resolver([self.dns_server, "1.1.1.1", "8.8.8.8"])
            records = [_txt_value(r) for r in resolver.resolve(domain or self.domain, "TXT")]
            matches = [r for r in records if r.lower().startswith("v=spf1 ") or r.lower() == "v=spf1"]
            if domain is None or domain == self.domain:
                self.multiple_spf_records = len(matches) > 1
            return matches[0] if len(matches) == 1 else None
        except (dns.exception.DNSException, OSError, ValueError):
            return None

    def get_spf_all_string(self):
        """Return the effective all qualifier, following redirect modifiers safely."""
        visited = {self.domain}
        record = self.spf_record
        while record:
            try:
                terms = parse_spf(record)
            except ValueError:
                return None
            alls = [f"{t.qualifier}all" for t in terms if not t.modifier and t.mechanism == "all"]
            if len(alls) > 1:
                return "2many"
            if alls:
                return alls[0]
            redirect = next((t.value for t in terms if t.modifier and t.mechanism == "redirect"), None)
            if not redirect or redirect in visited:
                return None
            visited.add(redirect)
            record = self.get_spf_record(redirect)
        return None

    def get_spf_dns_queries(self):
        """Count RFC-defined DNS-query mechanisms across reachable SPF records.

        Each include/redirect/a/mx/ptr/exists term counts once. Cycles are
        guarded per recursion path; repeated includes remain separately counted.
        """
        if not self.spf_record:
            return 0
        resolver = get_resolver(self.dns_server)
        total = 0
        max_depth = 20

        def walk(record, path, depth):
            nonlocal total
            if depth > max_depth:
                return
            try:
                terms = parse_spf(record)
            except ValueError:
                return
            for term in terms:
                if term.modifier:
                    if term.mechanism == "redirect":
                        target = term.value
                        total += 1
                        if target not in path:
                            walk_target(target, path, depth)
                elif term.mechanism in {"include", "a", "mx", "ptr", "exists"}:
                    total += 1
                    if term.mechanism == "include" and term.value not in path:
                        walk_target(term.value, path, depth)

        def walk_target(target, path, depth):
            try:
                answers = resolver.resolve(target, "TXT")
                records = [_txt_value(r) for r in answers]
                nested = [r for r in records if r.lower().startswith("v=spf1")]
                if len(nested) == 1:
                    walk(nested[0], path | {target}, depth + 1)
            except (dns.exception.DNSException, OSError, ValueError):
                pass

        walk(self.spf_record, {self.domain}, 0)
        return total

    def __str__(self):
        return (f"SPF Record: {self.spf_record}\nAll Mechanism: {self.all_mechanism}\n"
                f"DNS Query Count: {self.spf_dns_query_count}\nToo Many DNS Queries: {self.too_many_dns_queries}")
