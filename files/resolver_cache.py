# modules/resolver_cache.py

"""Shared, thread-safe DNS cache used across a single Spoofy run.

Every module (SPF, DMARC, BIMI, DKIM, DNS) previously created its own throwaway
dns.resolver.Resolver() with no cache, so identical lookups were repeated
across domains in a batch scan - most visibly, popular SPF `include:` targets
(e.g. `include:_spf.google.com`, `include:sendgrid.net`) get re-resolved for
every single domain in a list that happens to use them, and SOA/nameserver
discovery is repeated even when many domains share the same DNS
infrastructure.

get_resolver() hands out a Resolver backed by one shared LRU cache for the
whole process, so repeat lookups across domains (and across threads - dnspython's
LRUCache is internally lock-protected) are served from memory instead of
re-querying the network.
"""

import dns.resolver

# Shared across the whole process/run. 10k entries is generous for typical
# batch sizes while staying small in memory.
_shared_cache = dns.resolver.LRUCache(max_size=10000)


def get_resolver(nameservers=None):
    """Returns a dns.resolver.Resolver configured with the shared run-wide cache.

    nameservers may be a single server string, a list of server strings
    (None entries are dropped), or omitted to use dnspython's system defaults.
    """
    resolver = dns.resolver.Resolver()
    resolver.cache = _shared_cache

    if nameservers:
        if isinstance(nameservers, str):
            nameservers = [nameservers]
        nameservers = [ns for ns in nameservers if ns]
        if nameservers:
            resolver.nameservers = nameservers

    return resolver
