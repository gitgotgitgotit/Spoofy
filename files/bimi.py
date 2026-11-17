# modules/bimi.py

import dns.resolver
from .resolver_cache import get_resolver
from .txt import txt_value


class BIMI:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server
        self.bimi_record = self.get_bimi_record()  # plain str (JSON/Excel safe), not an rdata object
        self.version = None
        self.location = None
        self.authority = None

        if self.bimi_record:
            tags = self._tags()
            self.version = tags.get("v")
            self.location = tags.get("l")
            self.authority = tags.get("a")

    def get_bimi_record(self):
        """Returns the BIMI record text for the domain, or None."""
        try:
            answers = get_resolver(self.dns_server).resolve(f"default._bimi.{self.domain}", "TXT")
            for rdata in answers:
                value = txt_value(rdata).strip()
                if value.replace(" ", "").lower().startswith("v=bimi1"):
                    return value
        except Exception:
            pass
        return None

    def _tags(self):
        """Parse tag=value pairs split on ';' (URLs like l=...?a=1 must not be re-split)."""
        tags = {}
        for part in str(self.bimi_record).split(";"):
            name, sep, value = part.partition("=")
            name = name.strip().lower()
            if sep and name and name not in tags:
                tags[name] = value.strip()
        return tags

    def get_bimi_version(self):
        """Returns the version value from a BIMI record."""
        return self.version

    def get_bimi_location(self):
        """Returns the location value from a BIMI record."""
        return self.location

    def get_bimi_authority(self):
        """Returns the authority value from a BIMI record."""
        return self.authority

    def get_bimi_details(self):
        """Returns a tuple containing version, location, and authority from a BIMI record."""
        return self.version, self.location, self.authority

    def __str__(self):
        return (
            f"BIMI Record: {self.bimi_record}\n"
            f"Version: {self.version}\n"
            f"Location: {self.location}\n"
            f"Authority: {self.authority}"
        )
