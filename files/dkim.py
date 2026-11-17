# modules/dkim.py

import concurrent.futures
import email
import os
import random
import re
import threading
import time

import dns.exception
import dns.resolver
import requests

from .resolver_cache import get_resolver
from .dkim_analysis import analyze_dkim_keys, parse_tags
from .txt import txt_value

# Path to the packaged default wordlist (see files/dkim_selectors.txt). A
# small built-in fallback is kept below in case the file is missing (e.g. a
# packaging issue), so the tool never silently loses all selector coverage.
DEFAULT_SELECTORS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "files", "dkim_selectors.txt"
)

FALLBACK_SELECTORS = [
    "google", "selector1", "selector2", "k1", "k2", "dkim", "default", "mail", "s1", "s2",
]

# Cap simultaneous requests to the archive.prove.email API across *all*
# threads/domains in a run. Without this, `-t 20 --dkim` on a large domain
# list fires up to 20 concurrent requests at a shared third-party API with
# no coordination, which is a good way to get rate-limited or IP-banned.
_API_SEMAPHORE = threading.Semaphore(5)
_API_MAX_RETRIES = 3
_API_BACKOFF_BASE_SECONDS = 1.0


def load_selectors(path=None):
    """Loads DKIM selectors (one per line) from a wordlist file.

    Falls back to a small built-in list if the file is missing or unreadable,
    so a packaging/path issue degrades gracefully instead of finding nothing.
    """
    file_path = path or DEFAULT_SELECTORS_FILE
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            selectors = [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            ]
        return selectors if selectors else list(FALLBACK_SELECTORS)
    except OSError:
        return list(FALLBACK_SELECTORS)


_SELECTOR_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9._-]{0,62})$")
_SHA1_SIGNATURE_ALGS = {"rsa-sha1"}


def looks_like_dkim(value):
    """True if a TXT value is a DKIM key record (parsed, not substring-matched).

    A naive `"p=" in value` also matches SPF `exp=` and DMARC `sp=` text.
    """
    try:
        tags = parse_tags(value)
    except ValueError:  # duplicate tags etc.: still a DKIM record if it says so
        return value.strip().strip('"').replace(" ", "").lower().startswith("v=dkim1")
    version = tags.get("v")
    if version is not None:
        return version.strip().upper() == "DKIM1"
    return "p" in tags


def load_header_signatures(path):
    """Read DKIM-Signature headers (d=, s=, a=) from a raw message / header dump."""
    with open(path, "rb") as handle:
        message = email.message_from_binary_file(handle)
    signatures = []
    for value in message.get_all("DKIM-Signature", []):
        tags = {}
        for part in re.sub(r"\s+", "", str(value)).split(";"):
            if "=" in part:
                name, tag_value = part.split("=", 1)
                tags.setdefault(name, tag_value)
        domain, selector = tags.get("d", "").lower(), tags.get("s", "")
        if not domain or not _SELECTOR_RE.match(selector):
            continue
        algorithm = tags.get("a", "").lower()
        alerts = ["SIGNATURE_SHA1"] if algorithm in _SHA1_SIGNATURE_ALGS else []
        signatures.append({"domain": domain, "selector": selector, "algorithm": algorithm, "alerts": alerts})
    return signatures


class DKIM:
    def __init__(self, domain, dns_server=None, api_base_url=None, selectors=None,
                 selectors_file=None, max_workers=15, use_api=False, extra_selectors=None,
                 header_signatures=None, check_dangling=True):
        self.domain = domain
        self.dns_server = dns_server
        self.api_base_url = api_base_url or "https://archive.prove.email/api"
        self.max_workers = max_workers
        self.use_api = use_api
        self.check_dangling = check_dangling
        self.dangling_cnames = {}  # selector -> CNAME target that does not resolve (takeover candidate)

        # Signatures from a user-supplied real message: only those for this domain
        # name a selector we can look up under it.
        self.header_signatures = [sig for sig in (header_signatures or []) if sig["domain"] == domain.lower()]
        wanted = [*(extra_selectors or []), *(sig["selector"] for sig in self.header_signatures)]
        base = selectors or load_selectors(selectors_file)
        self.selectors = list(dict.fromkeys([sel for sel in wanted if _SELECTOR_RE.match(sel)] + list(base)))

        # selector -> reason. NXDOMAIN/NODATA is *absence*; timeouts/SERVFAIL are
        # *unknown* and are tracked here so they are never mistaken for absence.
        self.lookup_errors = {}
        self.dns_records = {}
        self._checked = set()
        self._query_selectors(self.selectors)

        self.api_records = self.get_dkim_record_from_api() if use_api else {}
        # Confirm archive-only selectors against live DNS so their source is accurate.
        self._query_selectors([sel for sel in self.api_records if sel not in self._checked])

        self.records = self.build_records()
        self.dkim_record = self.records or None
        self.key_analysis = analyze_dkim_keys(
            {rec["selector"]: rec["record"] for rec in self.records},
            {rec["selector"]: rec["source"] for rec in self.records},
        )

    def _check_selector(self, selector):
        """Return (selector, value|None, error|None) for one selector lookup."""
        name = f"{selector}._domainkey.{self.domain}"
        error = None
        for _attempt in range(2):  # one retry, timeouts only
            try:
                resolver = get_resolver(self.dns_server)
                resolver.timeout = 5
                resolver.lifetime = 5
                answers = resolver.resolve(name, "TXT")
            except dns.resolver.NXDOMAIN:
                self._probe_dangling_cname(selector, name)
                return selector, None, None
            except dns.resolver.NoAnswer:
                return selector, None, None
            except dns.exception.Timeout:
                error = "timeout"
                continue
            except dns.resolver.NoNameservers:
                return selector, None, "SERVFAIL/no nameservers"
            except Exception as exc:  # noqa: BLE001 - recorded, never silently dropped
                return selector, None, type(exc).__name__
            for rdata in answers:
                value = txt_value(rdata)
                if looks_like_dkim(value):
                    return selector, value, None
            return selector, None, None
        return selector, None, error

    def _probe_dangling_cname(self, selector, name):
        """TXT gave NXDOMAIN: if the name is a CNAME, its target does not exist (dangling)."""
        if not self.check_dangling:
            return
        try:
            for rdata in get_resolver(self.dns_server).resolve(name, "CNAME"):
                self.dangling_cnames[selector] = str(rdata.target).rstrip(".").lower()
        except Exception:  # noqa: BLE001 - no CNAME / lookup failed: nothing to report
            pass

    def _query_selectors(self, selectors):
        """Query selector._domainkey.domain for each selector (live DNS)."""
        todo = [sel for sel in selectors if sel not in self._checked]
        self._checked.update(todo)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for selector, value, error in executor.map(self._check_selector, todo):
                if value is not None:
                    self.dns_records[selector] = value
                elif error:
                    self.lookup_errors[selector] = error

    def brute_force_dkim_selectors(self):
        """Back-compat wrapper: re-run the wordlist and return {selector: value}."""
        self._checked -= set(self.selectors)
        self._query_selectors(self.selectors)
        return dict(self.dns_records)

    def get_dkim_record_from_api(self):
        """Returns DKIM records for a given domain using the archive.prove.email API.

        Kept as a supplementary source: it can occasionally surface selectors
        (or historical keys) outside the wordlist above, at no extra cost to
        try. Retries on rate limiting (429) and transient server errors
        (5xx) with capped, jittered backoff, honoring a Retry-After header
        when the server provides one. A process-wide semaphore caps how many
        of these requests can be in flight at once, regardless of how many
        domains/threads are running.
        """
        base_url = self.api_base_url.rstrip("/")
        url = f"{base_url}/key"
        params = {"domain": self.domain}
        headers = {"accept": "application/json"}

        with _API_SEMAPHORE:
            for attempt in range(_API_MAX_RETRIES + 1):
                try:
                    response = requests.get(url, params=params, headers=headers, timeout=10)
                except requests.exceptions.RequestException:
                    return {}

                if response.status_code == 200:
                    try:
                        return self.format_api_records(response.json())
                    except (KeyError, ValueError, TypeError):
                        return {}

                retryable = response.status_code == 429 or response.status_code >= 500
                if retryable and attempt < _API_MAX_RETRIES:
                    delay = self._retry_delay(response, attempt)
                    time.sleep(delay)
                    continue

                return {}

        return {}

    @staticmethod
    def _retry_delay(response, attempt):
        """Computes how long to wait before retrying, preferring the server's
        Retry-After header and falling back to jittered exponential backoff."""
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return float(retry_after)
            except ValueError:
                pass
        return _API_BACKOFF_BASE_SECONDS * (2 ** attempt) + random.uniform(0, 0.5)

    def format_api_records(self, api_response):
        """Formats the API response into a {selector: value} dict, deduplicated by most recent."""
        if not isinstance(api_response, list):
            return {}

        records_by_selector = {}
        for record in api_response:
            if not isinstance(record, dict):
                continue

            selector = record.get("selector")
            value = record.get("value")
            last_seen = str(record.get("lastSeenAt") or "")
            # Archive data is untrusted: it becomes a DNS name, so validate it.
            if not isinstance(selector, str) or not _SELECTOR_RE.match(selector) or not isinstance(value, str):
                continue

            existing = records_by_selector.get(selector)
            if existing is None or last_seen > existing[1]:
                records_by_selector[selector] = (value, last_seen)

        return {selector: value for selector, (value, _) in records_by_selector.items()}

    def build_records(self):
        """Structured records: [{selector, fqdn, source, record}], sorted by selector.

        source is "dns" (live), "archive-historical" (archive only; selector is
        gone from DNS) or "archive-unverified" (archive only; the live lookup
        failed, so it could not be confirmed).
        """
        records = []
        for selector in sorted(set(self.dns_records) | set(self.api_records)):
            if selector in self.dns_records:
                source, value = "dns", self.dns_records[selector]
            else:
                source = "archive-unverified" if selector in self.lookup_errors else "archive-historical"
                value = self.api_records[selector]
            records.append({"selector": selector, "fqdn": f"{selector}._domainkey.{self.domain}",
                            "source": source, "record": value})
        return records

    def merge_records(self):
        """Back-compat: one readable string. Presentation only; data lives in .records."""
        if not self.records:
            return None
        return "\n".join(f"{r['fqdn']} ({r['source']}) -> {r['record']}" for r in self.records)

    def __str__(self):
        return f"DKIM Record: {self.merge_records()}"
