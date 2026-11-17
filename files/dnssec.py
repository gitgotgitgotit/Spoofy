# modules/dnssec.py
"""DNSSEC assessment: DS/DNSKEY presence, chain validity, signature expiry, algorithms.

Validation is delegated to the recursive resolver (1.1.1.1 / 8.8.8.8 / 9.9.9.9 all
validate): we trust its AD flag rather than re-validating the chain ourselves, and
say so in the output. A bogus chain is detected the standard way: the validating
resolver answers SERVFAIL, but the same query succeeds with checking disabled (CD).
"""

import time

import dns.flags
import tldextract

from . import dnsutil
from .findings import check_result, finding

FIX = "Enable DNSSEC at your DNS provider and publish the resulting DS record at your registrar."
WEAK_ALGORITHMS = {1: ("RSAMD5", "high"), 3: ("DSA", "high"),
                   5: ("RSASHA1", "low"), 6: ("DSA-NSEC3-SHA1", "low"), 7: ("RSASHA1-NSEC3-SHA1", "low")}
EXPIRY_WARN_SECONDS = 72 * 3600
RRSIG = 46


def _configure(cd=False):
    def apply(resolver):
        resolver.cache = None  # the shared cache ignores DO/AD, so it would hide signatures
        resolver.use_edns(0, dns.flags.DO, 1232)
        if cd:  # setting .flags replaces the defaults, so RD must be kept
            resolver.flags = dns.flags.RD | dns.flags.CD
    return apply


def _flags(answer):
    return int(getattr(getattr(answer, "response", None), "flags", 0) or 0)


def _rrsig_expiries(answer):
    expiries = []
    for rrset in getattr(getattr(answer, "response", None), "answer", None) or []:
        if int(getattr(rrset, "rdtype", 0)) == RRSIG:
            expiries.extend(int(rdata.expiration) for rdata in rrset)
    return expiries


def check_dnssec(domain, dns_server, now=None):
    now = now if now is not None else time.time()
    name = tldextract.extract(domain).registered_domain or domain
    data = {"checked_name": name, "has_ds": False, "has_dnskey": False, "validated": False,
            "bogus": False, "algorithms": [], "signature_expires": None,
            "method": "resolver AD flag (not an independent chain validation)"}
    findings = []

    ds_status, ds, ds_err = dnsutil.lookup(name, "DS", dns_server, _configure())
    key_status, keys, key_err = dnsutil.lookup(name, "DNSKEY", dns_server, _configure())

    if "SERVFAIL" in (ds_err, key_err):
        cd_status, cd_keys, _ = dnsutil.lookup(name, "DNSKEY", dns_server, _configure(cd=True))
        if cd_status in ("ok", "nodata"):
            data["bogus"] = True
            findings.append(finding(
                "critical", "DNSSEC_BOGUS",
                "DNSSEC validation fails: validating resolvers return SERVFAIL for this domain, "
                "so it (and its mail) is unreachable for everyone who validates",
                "Fix the broken chain: re-publish the correct DS at the registrar, or remove the DS if DNSSEC is not wanted.",
                {"servfail_with_checking": True, "answer_with_checking_disabled": True}))
            if cd_status == "ok":
                keys = cd_keys
                data["has_dnskey"] = True
        else:
            findings.append(finding("info", "DNSSEC_UNKNOWN", f"DNSSEC state could not be determined ({ds_err or key_err})"))
            return check_result("DNSSEC", False, "lookup failed", data, findings)

    data["has_ds"] = ds_status == "ok"
    data["has_dnskey"] = data["has_dnskey"] or key_status == "ok"

    if data["has_dnskey"] and not data["bogus"]:
        data["validated"] = bool(_flags(keys) & dns.flags.AD)

    # Signature lifetime (RRSIG over the DNSKEY set)
    expiries = _rrsig_expiries(keys) if data["has_dnskey"] else []
    if expiries:
        soonest = min(expiries)
        data["signature_expires"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(soonest))
        if soonest < now:
            findings.append(finding("critical", "DNSSEC_SIGNATURE_EXPIRED",
                                    f"DNSKEY signatures expired on {data['signature_expires']}",
                                    "Re-sign the zone; check your signer/automation."))
        elif soonest - now < EXPIRY_WARN_SECONDS:
            findings.append(finding("high", "DNSSEC_SIGNATURE_EXPIRING",
                                    f"DNSKEY signatures expire within 72 hours ({data['signature_expires']})",
                                    "Check that automatic re-signing is working."))

    if data["has_ds"] and data["has_dnskey"]:
        if data["validated"]:
            findings.append(finding("info", "DNSSEC_OK", "DNSSEC is deployed and the resolver validated the chain"))
        elif not data["bogus"]:
            findings.append(finding("medium", "DNSSEC_UNVALIDATED",
                                    "DS and DNSKEY exist but the resolver did not mark the answer authenticated; "
                                    "the chain could not be confirmed",
                                    "Verify the DS at the registrar matches a current DNSKEY (e.g. with dnsviz.net)."))
    elif data["has_ds"] and not data["has_dnskey"]:
        findings.append(finding("high", "DNSSEC_DS_WITHOUT_DNSKEY",
                                "The parent publishes a DS record but the zone has no DNSKEY: the chain is broken",
                                "Re-enable signing at the DNS provider or remove the DS record at the registrar."))
    elif data["has_dnskey"] and not data["has_ds"]:
        findings.append(finding("medium", "DNSSEC_NOT_ANCHORED",
                                "The zone publishes DNSKEY records but the parent has no DS: DNSSEC is not active",
                                "Publish the DS record at your registrar."))
    elif not data["bogus"]:
        findings.append(finding("medium", "DNSSEC_UNSIGNED", "DNSSEC is not enabled", FIX))

    # Algorithm hygiene
    algorithms = set()
    for rdata in list(ds if ds_status == "ok" else []) + list(keys if data["has_dnskey"] else []):
        algorithm = getattr(rdata, "algorithm", None)
        if algorithm is not None:
            algorithms.add(int(algorithm))
    data["algorithms"] = sorted(algorithms)
    for algorithm in sorted(algorithms & set(WEAK_ALGORITHMS)):
        label, severity = WEAK_ALGORITHMS[algorithm]
        findings.append(finding(severity, f"DNSSEC_ALGORITHM_{algorithm}", f"DNSSEC uses deprecated algorithm {label} ({algorithm})",
                                "Roll to ECDSAP256SHA256 (13) or ED25519 (15)."))
    if ds_status == "ok":
        digests = {int(getattr(r, "digest_type", 0)) for r in ds}
        if digests == {1}:
            findings.append(finding("low", "DNSSEC_DS_SHA1_ONLY", "The DS record only uses a SHA-1 digest",
                                    "Publish a SHA-256 (digest type 2) DS record."))
    return check_result("DNSSEC", True, None, data, findings)
