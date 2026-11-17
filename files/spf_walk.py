# modules/spf_walk.py
"""Bounded SPF walk (RFC 7208) used by the hardening and takeover checks.

Records, per include/redirect target, whether it exists and has an SPF record;
counts DNS lookups and *void* lookups (NXDOMAIN/NODATA; more than 2 is a
permerror under RFC 7208 4.6.4); and collects `ptr` use and authorised ranges.
"""

import ipaddress

from . import dnsutil
from .spf_parser import parse_spf

MAX_RECORDS = 25  # bounds DNS traffic for deeply nested include trees


def _target(term, owner):
    value = (term.value or "").split("/", 1)[0]
    return value or owner


def _is_macro(name):
    return "%" in name


def _spf_records(name, dns_server):
    """Return (status, [spf record strings]). status: ok | nxdomain | nodata | error."""
    status, answers, err = dnsutil.lookup(name, "TXT", dns_server)
    if status != "ok":
        return status, []
    from .txt import txt_value
    records = [v for v in (txt_value(r).strip() for r in answers) if v.lower().startswith("v=spf1")]
    return "ok", records


def walk_spf(domain, spf_record, dns_server, max_records=MAX_RECORDS):
    out = {"includes": [], "void_lookups": 0, "lookups": 0, "ptr": False, "ip_ranges": [],
           "errors": [], "truncated": False}
    if not spf_record:
        return out
    seen, queue, processed = {domain}, [(domain, spf_record)], 0

    def void(status):
        if status in ("nxdomain", "nodata"):
            out["void_lookups"] += 1

    while queue:
        owner, record = queue.pop(0)
        processed += 1
        try:
            terms = parse_spf(record)
        except ValueError as exc:
            out["errors"].append(f"{owner}: {exc}")
            continue
        for term in terms:
            mech = term.mechanism
            if mech in ("include", "redirect") and (term.value or ""):
                target = term.value.strip().rstrip(".").lower()
                out["lookups"] += 1
                if _is_macro(target):
                    continue
                if target in seen:
                    out["includes"].append({"target": target, "parent": owner, "status": "loop"})
                    continue
                seen.add(target)
                if processed + len(queue) >= max_records:
                    out["truncated"] = True
                    out["includes"].append({"target": target, "parent": owner, "status": "not-checked"})
                    continue
                status, records = _spf_records(target, dns_server)
                void(status)
                if status == "ok" and records:
                    out["includes"].append({"target": target, "parent": owner, "status": "ok"})
                    queue.append((target, records[0]))
                else:
                    shown = {"ok": "no-spf", "nodata": "no-spf"}.get(status, status)
                    out["includes"].append({"target": target, "parent": owner, "status": shown})
            elif mech in ("a", "mx"):
                out["lookups"] += 1
                name = _target(term, owner).rstrip(".").lower()
                if _is_macro(name):
                    continue
                if mech == "mx":
                    status, _, _ = dnsutil.lookup(name, "MX", dns_server)
                    void(status)
                else:
                    s4, _, _ = dnsutil.lookup(name, "A", dns_server)
                    s6, _, _ = dnsutil.lookup(name, "AAAA", dns_server)
                    if s4 in ("nxdomain", "nodata") and s6 in ("nxdomain", "nodata"):
                        out["void_lookups"] += 1
            elif mech == "exists" and term.value:
                out["lookups"] += 1
                if not _is_macro(term.value):
                    void(dnsutil.lookup(term.value.strip().rstrip(".").lower(), "A", dns_server)[0])
            elif mech == "ptr":
                out["lookups"] += 1
                out["ptr"] = True
            elif mech in ("ip4", "ip6") and term.value:
                try:
                    network = ipaddress.ip_network(term.value, strict=False)
                except ValueError:
                    continue
                out["ip_ranges"].append({"network": str(network), "version": network.version,
                                         "prefix": network.prefixlen, "qualifier": term.qualifier, "owner": owner})
    return out
