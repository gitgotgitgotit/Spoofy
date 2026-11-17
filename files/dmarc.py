# modules/dmarc.py

import dns.resolver
import re
import tldextract
from .resolver_cache import get_resolver
from .txt import txt_value


class DMARC:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server
        self.multiple_records = False   # >1 DMARC record at the chosen name: RFC 7489 says DMARC is not applied
        self.record_domain = None       # name the record was found at (the domain itself, or its organizational domain)
        self.dmarc_record = self.get_dmarc_record()
        self.policy = None
        self.pct = None
        self.aspf = None
        self.adkim = None
        self.sp = None
        self.fo = None
        self.rua = None

        if self.dmarc_record:
            self.policy = self.get_dmarc_policy()
            self.pct = self.get_dmarc_pct()
            self.aspf = self.get_dmarc_aspf()
            self.adkim = self._lower(self.get_dmarc_tag("adkim"))
            self.sp = self.get_dmarc_subdomain_policy()
            self.fo = self.get_dmarc_forensic_reports()
            self.rua = self.get_dmarc_aggregate_reports()

    def get_dmarc_record(self):
        """Policy discovery per RFC 7489 section 6.6.3.

        Query _dmarc.<domain> first, then fall back to the organizational domain
        only if that name has no DMARC record. More than one record at a name ends
        discovery with no policy (multiple_records is set).
        """
        org_domain = tldextract.extract(self.domain).registered_domain
        candidates = [self.domain]
        if org_domain and org_domain != self.domain:
            candidates.append(org_domain)
        for candidate in candidates:
            records = self._dmarc_records(candidate)
            if len(records) == 1:
                self.record_domain = candidate
                return records[0]
            if len(records) > 1:
                self.multiple_records = True
                self.record_domain = candidate
                return None
        return None

    def get_dmarc_record_for_domain(self, domain):
        """Back-compat: the single DMARC record at _dmarc.<domain>, else None."""
        records = self._dmarc_records(domain)
        return records[0] if len(records) == 1 else None

    def _dmarc_records(self, domain):
        try:
            answers = get_resolver(self.dns_server).resolve(f"_dmarc.{domain}", "TXT")
        except Exception:
            return []
        records = []
        for rdata in answers:
            value = txt_value(rdata).strip()  # joins multi-string TXT without injecting spaces
            if value.replace(" ", "").lower().startswith("v=dmarc1"):
                records.append(value)
        return records

    def get_dmarc_tag(self, tag):
        """Returns the value of a specific DMARC tag, matching the tag exactly
        (not as a substring of another tag, e.g. 'p=' must not match inside 'sp=')."""
        record = str(self.dmarc_record)
        match = re.search(rf"(?:^|;)\s*{re.escape(tag)}=([^;]*)", record)
        if match:
            return match.group(1).strip()
        return None

    @staticmethod
    def _lower(value):
        """p/sp/aspf values are case-insensitive (ABNF literals), e.g. p=REJECT."""
        return value.lower() if isinstance(value, str) else value

    def get_dmarc_policy(self):
        """Returns the policy value from a DMARC record."""
        return self._lower(self.get_dmarc_tag("p"))

    def get_dmarc_pct(self):
        """Returns the pct value from a DMARC record."""
        return self.get_dmarc_tag("pct")

    def get_dmarc_aspf(self):
        """Returns the aspf value from a DMARC record"""
        return self._lower(self.get_dmarc_tag("aspf"))

    def get_dmarc_subdomain_policy(self):
        """Returns the policy to apply for subdomains from a DMARC record."""
        return self._lower(self.get_dmarc_tag("sp"))

    def get_dmarc_forensic_reports(self):
        """Returns the email addresses to which forensic reports should be sent."""
        fo = self.get_dmarc_tag("fo")
        if self.get_dmarc_tag("ruf") is not None and fo == "1":
            return self.get_dmarc_tag("ruf")
        return None

    def get_dmarc_aggregate_reports(self):
        """Returns the email addresses to which aggregate reports should be sent."""
        return self.get_dmarc_tag("rua")

    def __str__(self):
        return (
            f"DMARC Record: {self.dmarc_record}\n"
            f"Policy: {self.policy}\n"
            f"Pct: {self.pct}\n"
            f"ASPF: {self.aspf}\n"
            f"Subdomain Policy: {self.sp}\n"
            f"Forensic Report URI: {self.fo}\n"
            f"Aggregate Report URI: {self.rua}"
        )
