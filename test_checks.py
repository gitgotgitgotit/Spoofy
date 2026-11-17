"""Offline tests for the DNS-only checks (DNSSEC, MX, CAA, TLS-RPT, IPv6), alignment and the score."""
import contextlib
import io
import time
import types
import unittest
from unittest import mock

import tests_stubs

tests_stubs.install()

import dns.exception  # noqa: E402
import dns.flags  # noqa: E402
import dns.resolver  # noqa: E402

from modules import assessment, dnsutil, report  # noqa: E402
from modules.alignment import check_alignment  # noqa: E402
from modules.caa import check_caa  # noqa: E402
from modules.dnssec import check_dnssec  # noqa: E402
from modules.ipv6 import check_ipv6  # noqa: E402
from modules.mx import check_mx  # noqa: E402
from modules.scoring import build_score  # noqa: E402
from modules.tlsrpt import check_tlsrpt  # noqa: E402

NS = types.SimpleNamespace
NOANSWER, NXDOMAIN, SERVFAIL, TIMEOUT = dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout


class Answer(list):
    def __init__(self, items, flags=0, rrsigs=()):
        super().__init__(items)
        rrsets = [list(items)] + ([_rrset(46, rrsigs)] if rrsigs else [])
        self.response = NS(flags=flags, answer=rrsets)


def _rrset(rdtype, rdatas):
    return _IterRRset(rdtype, rdatas)


class _IterRRset(list):
    def __init__(self, rdtype, rdatas):
        super().__init__(rdatas)
        self.rdtype = rdtype


def txt(*chunks):
    return NS(strings=[c.encode() for c in chunks])


def mx(pref, host):
    return NS(preference=pref, exchange=host)


def addr(ip):
    return NS(address=ip)


def rrsig(expiration):
    return NS(expiration=expiration)


def caa(tag, value, flags=0):
    return NS(flags=flags, tag=tag.encode(), value=value.encode())


class FakeResolver:
    """zone: {(name, rtype): list|Answer|Exception, (name, rtype, 'cd'): ...}. Anything else: NXDOMAIN."""

    def __init__(self, zone):
        self.zone, self.flags, self.cache, self.timeout, self.lifetime, self.edns = zone, None, None, None, None, None

    def use_edns(self, *args, **kwargs):
        self.edns = args

    def resolve(self, name, rtype):
        cd = bool(self.flags and self.flags & dns.flags.CD)
        if cd:
            assert self.flags & dns.flags.RD, "setting flags must keep RD or the query is not recursive"
        key = (name.lower(), rtype, "cd") if cd and (name.lower(), rtype, "cd") in self.zone else (name.lower(), rtype)
        entry = self.zone.get(key, NXDOMAIN())
        if isinstance(entry, Exception):
            raise entry
        return entry if isinstance(entry, Answer) else Answer(entry)


def zone_patch(zone):
    return mock.patch.object(dnsutil, "get_resolver", lambda *a, **k: FakeResolver(zone))


def codes(result, severity=None):
    return [f["code"] for f in result["findings"] if severity in (None, f["severity"])]


FUTURE = time.time() + 30 * 86400
KEY5 = NS(algorithm=5, flags=257)
KEY13 = NS(algorithm=13, flags=257)
DS13 = NS(key_tag=1, algorithm=13, digest_type=2)


class DnssecTests(unittest.TestCase):
    def run_check(self, zone, now=None):
        with zone_patch(zone):
            return check_dnssec("example.com", "1.1.1.1", now=now)

    def test_unsigned(self):
        r = self.run_check({("example.com", "DS"): NOANSWER(), ("example.com", "DNSKEY"): NOANSWER()})
        self.assertEqual(codes(r), ["DNSSEC_UNSIGNED"])

    def test_signed_and_validated(self):
        r = self.run_check({("example.com", "DS"): [DS13],
                            ("example.com", "DNSKEY"): Answer([KEY13], dns.flags.AD, [rrsig(int(FUTURE))])})
        self.assertEqual(codes(r), ["DNSSEC_OK"])
        self.assertTrue(r["data"]["validated"])
        self.assertEqual(r["data"]["algorithms"], [13])

    def test_expired_and_expiring_signatures(self):
        base = {("example.com", "DS"): [DS13]}
        expired = self.run_check({**base, ("example.com", "DNSKEY"): Answer([KEY13], dns.flags.AD, [rrsig(int(time.time()) - 3600)])})
        self.assertIn("DNSSEC_SIGNATURE_EXPIRED", codes(expired, "critical"))
        soon = self.run_check({**base, ("example.com", "DNSKEY"): Answer([KEY13], dns.flags.AD, [rrsig(int(time.time()) + 3600)])})
        self.assertIn("DNSSEC_SIGNATURE_EXPIRING", codes(soon, "high"))

    def test_bogus_chain_detected_via_servfail_then_cd_success(self):
        zone = {("example.com", "DS"): [DS13], ("example.com", "DNSKEY"): SERVFAIL(),
                ("example.com", "DNSKEY", "cd"): Answer([KEY13], 0, [rrsig(int(FUTURE))])}
        r = self.run_check(zone)
        self.assertIn("DNSSEC_BOGUS", codes(r, "critical"))
        self.assertTrue(r["data"]["bogus"])

    def test_servfail_that_persists_with_cd_is_unknown_not_bogus(self):
        r = self.run_check({("example.com", "DS"): NOANSWER(), ("example.com", "DNSKEY"): SERVFAIL(),
                            ("example.com", "DNSKEY", "cd"): SERVFAIL()})
        self.assertFalse(r["applicable"])
        self.assertNotIn("DNSSEC_BOGUS", codes(r))

    def test_partial_deployments(self):
        ds_only = self.run_check({("example.com", "DS"): [DS13], ("example.com", "DNSKEY"): NOANSWER()})
        self.assertIn("DNSSEC_DS_WITHOUT_DNSKEY", codes(ds_only, "high"))
        key_only = self.run_check({("example.com", "DS"): NOANSWER(), ("example.com", "DNSKEY"): Answer([KEY13], 0)})
        self.assertIn("DNSSEC_NOT_ANCHORED", codes(key_only, "medium"))
        no_ad = self.run_check({("example.com", "DS"): [DS13], ("example.com", "DNSKEY"): Answer([KEY13], 0)})
        self.assertIn("DNSSEC_UNVALIDATED", codes(no_ad, "medium"))

    def test_deprecated_algorithm_and_sha1_ds(self):
        r = self.run_check({("example.com", "DS"): [NS(key_tag=1, algorithm=5, digest_type=1)],
                            ("example.com", "DNSKEY"): Answer([KEY5], dns.flags.AD, [rrsig(int(FUTURE))])})
        self.assertIn("DNSSEC_ALGORITHM_5", codes(r, "low"))
        self.assertIn("DNSSEC_DS_SHA1_ONLY", codes(r, "low"))

    def test_checks_registered_domain_for_subdomains(self):
        zone = {("example.com", "DS"): [DS13], ("example.com", "DNSKEY"): Answer([KEY13], dns.flags.AD, [rrsig(int(FUTURE))])}
        with zone_patch(zone):
            r = check_dnssec("mail.example.com", "1.1.1.1")
        self.assertEqual(r["data"]["checked_name"], "example.com")
        self.assertTrue(r["data"]["validated"])


class MxTests(unittest.TestCase):
    def run_check(self, zone, domain="example.com"):
        with zone_patch(zone):
            return check_mx(domain, "1.1.1.1")

    def test_healthy_mx(self):
        r = self.run_check({("example.com", "MX"): [mx(10, "mx1.example.com."), mx(20, "mx2.example.com.")],
                            ("mx1.example.com", "A"): [addr("8.8.8.8")], ("mx2.example.com", "A"): [addr("8.8.4.4")],
                            ("mx2.example.com", "AAAA"): [addr("2001:4860:4860::8888")]})
        self.assertEqual([f["code"] for f in r["findings"]], [])
        self.assertEqual([rec["host"] for rec in r["data"]["records"]], ["mx1.example.com", "mx2.example.com"])
        self.assertEqual(r["data"]["records"][1]["ipv6"], ["2001:4860:4860::8888"])

    def test_dangling_cname_private_and_ip_literal(self):
        r = self.run_check({("example.com", "MX"): [mx(1, "gone.example.com."), mx(2, "alias.example.com."),
                                                    mx(3, "lan.example.com."), mx(4, "192.0.2.1.")],
                            ("alias.example.com", "A"): [addr("8.8.8.8")], ("alias.example.com", "CNAME"): [NS(target="x")],
                            ("lan.example.com", "A"): [addr("10.0.0.5")]})
        self.assertEqual(sorted(codes(r)), ["MX_CNAME", "MX_DANGLING", "MX_IP_LITERAL", "MX_NON_PUBLIC"])

    def test_resolution_error_is_not_dangling(self):
        r = self.run_check({("example.com", "MX"): [mx(1, "slow.example.com.")],
                            ("slow.example.com", "A"): TIMEOUT(), ("slow.example.com", "AAAA"): TIMEOUT()})
        self.assertIn("MX_RESOLVE_ERROR", codes(r))
        self.assertNotIn("MX_DANGLING", codes(r))

    def test_null_mx_implicit_mx_and_no_mail(self):
        null = self.run_check({("example.com", "MX"): [mx(0, ".")]})
        self.assertEqual((codes(null), null["applicable"]), (["MX_NULL"], True))
        mixed = self.run_check({("example.com", "MX"): [mx(0, "."), mx(10, "mx.example.com.")], ("mx.example.com", "A"): [addr("8.8.8.8")]})
        self.assertIn("MX_NULL_WITH_OTHERS", codes(mixed))
        implicit = self.run_check({("example.com", "MX"): NOANSWER(), ("example.com", "A"): [addr("8.8.8.8")]})
        self.assertIn("MX_IMPLICIT", codes(implicit))
        none = self.run_check({("example.com", "MX"): NOANSWER()})
        self.assertFalse(none["applicable"])

    def test_servfail_is_not_scored(self):
        r = self.run_check({("example.com", "MX"): SERVFAIL()})
        self.assertFalse(r["applicable"])


class CaaTests(unittest.TestCase):
    def run_check(self, zone, domain="example.com"):
        with zone_patch(zone):
            return check_caa(domain, "1.1.1.1")

    def test_missing(self):
        self.assertEqual(codes(self.run_check({("example.com", "CAA"): NOANSWER()})), ["CAA_MISSING"])

    def test_restricted_with_iodef_is_clean(self):
        r = self.run_check({("example.com", "CAA"): [caa("issue", "letsencrypt.org; accounturi=x"), caa("iodef", "mailto:a@example.com")]})
        self.assertEqual(codes(r), [])
        self.assertEqual(r["data"]["issue"], ["letsencrypt.org"])

    def test_inherits_from_parent_up_to_registered_domain(self):
        r = self.run_check({("example.com", "CAA"): [caa("issue", ";")]}, domain="a.b.example.com")
        self.assertEqual(r["data"]["found_at"], "example.com")
        self.assertIn("CAA_INHERITED", codes(r))
        self.assertTrue(r["data"]["deny_all"])

    def test_tree_climb_stops_at_the_registered_domain(self):
        r = self.run_check({("com", "CAA"): [caa("issue", "tld-level.example")]}, domain="a.example.com")
        self.assertEqual(codes(r), ["CAA_MISSING"])

    def test_broad_and_no_issue(self):
        broad = self.run_check({("example.com", "CAA"): [caa("issue", f"ca{i}.com") for i in range(5)] + [caa("iodef", "mailto:a@b.c")]})
        self.assertEqual(codes(broad), ["CAA_BROAD"])
        no_issue = self.run_check({("example.com", "CAA"): [caa("iodef", "mailto:a@b.c")]})
        self.assertEqual(codes(no_issue), ["CAA_NO_ISSUE"])


class TlsRptTests(unittest.TestCase):
    def run_check(self, zone):
        with zone_patch(zone):
            return check_tlsrpt("example.com", "1.1.1.1")

    def test_valid_record(self):
        r = self.run_check({("_smtp._tls.example.com", "TXT"): [txt("v=TLSRPTv1; rua=mailto:r@example.com,https://rpt.example.com/x")]})
        self.assertEqual(codes(r), ["TLSRPT_OK"])
        self.assertEqual(len(r["data"]["rua"]), 2)

    def test_bad_destinations(self):
        r = self.run_check({("_smtp._tls.example.com", "TXT"): [txt("v=TLSRPTv1; rua=mailto:nope,http://x.example.com,ftp://x")]})
        self.assertEqual(codes(r).count("TLSRPT_BAD_DESTINATION"), 3)
        no_rua = self.run_check({("_smtp._tls.example.com", "TXT"): [txt("v=TLSRPTv1")]})
        self.assertIn("TLSRPT_NO_RUA", codes(no_rua))

    def test_multiple_records(self):
        r = self.run_check({("_smtp._tls.example.com", "TXT"): [txt("v=TLSRPTv1; rua=mailto:a@b.co"), txt("v=TLSRPTv1; rua=mailto:c@d.co")]})
        self.assertIn("TLSRPT_MULTIPLE", codes(r))

    def test_missing_matters_only_with_mta_sts(self):
        plain = self.run_check({})
        self.assertFalse(plain["applicable"])
        with_sts = self.run_check({("_mta-sts.example.com", "TXT"): [txt("v=STSv1; id=1")]})
        self.assertEqual((with_sts["applicable"], codes(with_sts)), (True, ["TLSRPT_MISSING"]))


class Ipv6Tests(unittest.TestCase):
    MX = [{"host": "mx.example.com", "ipv4": ["8.8.8.8"], "ipv6": ["2001:db8::25"]}]

    def run_check(self, zone, spf, mx_records=None):
        with zone_patch(zone):
            return check_ipv6("example.com", "1.1.1.1", mx_records or self.MX, spf)

    PTR = "5.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"

    def test_authorized_with_fcrdns_is_clean(self):
        zone = {(self.PTR, "PTR"): [NS(target="mx.example.com.")], ("mx.example.com", "AAAA"): [addr("2001:db8::25")]}
        r = self.run_check(zone, "v=spf1 ip6:2001:db8::/32 -all")
        self.assertEqual(codes(r), [])
        self.assertEqual((r["data"]["addresses"][0]["spf"], r["data"]["addresses"][0]["fcrdns"]), ("authorized", True))

    def test_not_listed_in_spf_and_no_ptr(self):
        r = self.run_check({}, "v=spf1 ip4:8.8.8.8 -all")
        self.assertEqual(sorted(codes(r)), ["IPV6_NOT_IN_SPF", "IPV6_NO_PTR"])

    def test_includes_make_spf_unknown_not_a_finding(self):
        r = self.run_check({}, "v=spf1 include:_spf.example.net -all")
        self.assertEqual(r["data"]["addresses"][0]["spf"], "unknown")
        self.assertNotIn("IPV6_NOT_IN_SPF", codes(r))

    def test_mx_mechanism_authorizes_and_ptr_mismatch(self):
        zone = {(self.PTR, "PTR"): [NS(target="other.example.com.")], ("other.example.com", "AAAA"): [addr("2001:db8::99")]}
        r = self.run_check(zone, "v=spf1 mx -all")
        self.assertEqual(codes(r), ["IPV6_PTR_MISMATCH"])

    def test_no_ipv6_is_not_applicable(self):
        r = self.run_check({}, "v=spf1 -all", [{"host": "mx.example.com", "ipv4": ["8.8.8.8"], "ipv6": []}])
        self.assertFalse(r["applicable"])


def align(**kw):
    args = dict(dmarc_record="v=DMARC1", policy="reject", pct=None, aspf=None, adkim=None, sp=None, inherited=False,
                has_rua=True, spf_record="v=spf1 -all", dkim_enabled=False, dkim_analysis=None)
    args.update(kw)
    return check_alignment(**args)


class AlignmentTests(unittest.TestCase):
    def test_enforced_default_is_clean(self):
        r = align()
        self.assertEqual(codes(r, "high") + codes(r, "medium") + codes(r, "low"), [])
        self.assertEqual((r["data"]["spf_alignment"], r["data"]["dkim_alignment"]), ("relaxed", "relaxed"))

    def test_policy_strength(self):
        self.assertIn("ALIGN_P_NONE", codes(align(policy="none", has_rua=False), "high"))
        self.assertIn("ALIGN_P_NONE", codes(align(policy="none"), "medium"))
        self.assertIn("ALIGN_P_QUARANTINE", codes(align(policy="quarantine"), "low"))

    def test_pct_and_subdomain_policy(self):
        self.assertIn("ALIGN_PCT", codes(align(pct="25"), "medium"))
        self.assertIn("ALIGN_PCT", codes(align(pct="75"), "low"))
        self.assertIn("ALIGN_BAD_PCT", codes(align(pct="abc")))
        self.assertIn("ALIGN_SP_WEAKER", codes(align(sp="none")))
        inherited = align(policy="reject", sp="none", inherited=True)
        self.assertEqual(inherited["data"]["effective_policy"], "none")

    def test_modes_and_invalid_values(self):
        r = align(aspf="s", adkim="r")
        self.assertEqual((r["data"]["spf_alignment"], r["data"]["dkim_alignment"]), ("strict", "relaxed"))
        self.assertIn("ALIGN_STRICT", codes(r))
        self.assertIn("ALIGN_BAD_ASPF", codes(align(aspf="x")))

    def test_mechanism_availability(self):
        self.assertIn("ALIGN_NO_SPF", codes(align(spf_record=None), "medium"))
        live = [{"live": True}]
        self.assertIn("ALIGN_DKIM_ONLY", codes(align(spf_record=None, dkim_enabled=True, dkim_analysis=live), "low"))
        self.assertIn("ALIGN_NOTHING_FOUND", codes(align(spf_record=None, dkim_enabled=True, dkim_analysis=[])))

    def test_no_dmarc_not_applicable(self):
        self.assertFalse(align(dmarc_record=None)["applicable"])


def good_result(**over):
    r = {"DOMAIN": "example.com", "SPF": "v=spf1 -all", "SPF_MULTIPLE_ALLS": "-all", "SPF_NUM_DNS_QUERIES": 2,
         "SPF_TOO_MANY_DNS_QUERIES": False, "DMARC": "v=DMARC1; p=reject; rua=mailto:a@b.co", "DMARC_POLICY": "reject",
         "DMARC_AGGREGATE_REPORT": "mailto:a@b.co", "DKIM_ENABLED": False, "SPOOFING_POSSIBLE": False}
    r.update(over)
    return r


class ScoreTests(unittest.TestCase):
    def test_clean_basic_config_scores_100_and_unassessed_areas_are_listed(self):
        score = build_score(good_result(), {"DMARC alignment": align()})
        self.assertEqual((score["overall"], score["grade"], score["caps"]), (100, "A", []))
        reasons = {n["area"]: n["reason"] for n in score["not_assessed"]}
        self.assertIn("not scanned", reasons["DKIM"])
        self.assertIn("optional", reasons["BIMI"])
        self.assertIn("--basic", reasons["DNSSEC"])

    def test_missing_dmarc_is_critical_and_capped(self):
        score = build_score(good_result(DMARC=None, DMARC_POLICY=None, SPOOFING_POSSIBLE=True), {"DMARC alignment": align(dmarc_record=None)})
        self.assertEqual(score["areas"]["DMARC"]["score"], 60)
        self.assertLessEqual(score["overall"], 59)
        self.assertEqual(score["grade"], "F")
        self.assertTrue(score["caps"])

    def test_critical_finding_caps_at_69(self):
        r = good_result(SPF_MULTIPLE_ALLS="+all")
        score = build_score(r, {"DMARC alignment": align()})
        self.assertEqual(score["overall"], 69)
        self.assertEqual(score["caps"], [{"max": 69, "reason": "at least one critical finding"}])
        self.assertEqual(score["finding_counts"]["critical"], 1)

    def test_weights_not_equal_a_broken_dnssec_hurts_more_than_missing_optional_bimi(self):
        unsigned = {"DNSSEC": {"area": "DNSSEC", "applicable": True, "reason": None, "data": {}, "findings": [
            {"severity": "critical", "code": "X", "title": "t", "fix": None, "evidence": None}]}}
        with_bimi = build_score(good_result(), {"DMARC alignment": align()})
        broken = build_score(good_result(), {"DMARC alignment": align(), **unsigned})
        self.assertEqual(with_bimi["overall"], 100)  # absent BIMI is not penalised
        self.assertLess(broken["overall"], 95)

    def test_dkim_findings_flow_into_the_score(self):
        weak = {"selector": "s", "live": True, "overall": "critical", "status": "critical", "alerts": ["WEAK_KEY_512"], "issues": ["RSA key is 512 bits"]}
        testing = {"selector": "t", "live": True, "overall": "warning", "status": "good", "alerts": ["TESTING_MODE", "SHA1_ALLOWED"], "issues": []}
        score = build_score(good_result(DKIM_ENABLED=True, DKIM_ANALYSIS=[weak, testing]), {"DMARC alignment": align()})
        dkim_codes = [f["code"] for f in score["areas"]["DKIM"]["findings"]]
        self.assertEqual(sorted(dkim_codes), ["DKIM_SHA1", "DKIM_TESTING", "DKIM_WEAK_KEY"])
        self.assertEqual(score["areas"]["DKIM"]["score"], 100 - 40 - 25 - 12)
        archive_only = {**weak, "live": False}
        none_live = build_score(good_result(DKIM_ENABLED=True, DKIM_ANALYSIS=[archive_only]), {})
        self.assertFalse(none_live["areas"]["DKIM"]["applicable"])

    def test_spf_findings(self):
        self.assertEqual([f["code"] for f in build_score(good_result(SPF=None, SPF_MULTIPLE_ALLS=None), {})["areas"]["SPF"]["findings"]], ["SPF_MISSING"])
        soft = build_score(good_result(SPF_MULTIPLE_ALLS="~all"), {})["areas"]["SPF"]
        self.assertEqual((soft["score"], [f["code"] for f in soft["findings"]]), (95, ["SPF_SOFTFAIL"]))
        many = build_score(good_result(SPF_TOO_MANY_DNS_QUERIES=True), {})["areas"]["SPF"]
        self.assertIn("SPF_LOOKUPS", [f["code"] for f in many["findings"]])

    def test_bimi_only_scored_when_deployed(self):
        score = build_score(good_result(BIMI_RECORD="v=BIMI1", BIMI_LOCATION="http://x", BIMI_AUTHORITY=""), {})
        self.assertEqual(sorted(f["code"] for f in score["areas"]["BIMI"]["findings"]), ["BIMI_LOCATION", "BIMI_NO_VMC"])

    def test_error_in_a_check_does_not_break_assessment(self):
        zone = {}
        with zone_patch(zone), mock.patch.object(assessment, "check_dnssec", side_effect=RuntimeError("boom")):
            out = assessment.assess(good_result(), "1.1.1.1", extended=True)
        self.assertFalse(out["score"]["areas"]["DNSSEC"]["applicable"])
        self.assertIn("check failed", out["score"]["areas"]["DNSSEC"]["reason"])
        self.assertIsInstance(out["score"]["overall"], int)

    def test_basic_mode_skips_extended_checks(self):
        out = assessment.assess(good_result(), "1.1.1.1", extended=False)
        self.assertEqual(set(out["checks"]), {"DMARC alignment"})
        self.assertNotIn("DNSSEC", out["score"]["areas"])


class PrinterTests(unittest.TestCase):
    def test_score_section_lists_findings_with_fixes(self):
        score = build_score(good_result(DMARC=None, DMARC_POLICY=None, SPOOFING_POSSIBLE=True), {"DMARC alignment": align(dmarc_record=None)})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            report.printer(DOMAIN="example.com", DOMAIN_TYPE="domain", DNS_SERVER="1.1.1.1", SCORE=score)
        out = buf.getvalue()
        self.assertIn("SECURITY SCORE", out)
        self.assertIn("grade F", out)
        self.assertIn("[critical] No DMARC record", out)
        self.assertIn("Fix:", out)
        self.assertIn("Capped at 59", out)


class CliScoreTests(unittest.TestCase):
    def test_min_score_exit_code_and_basic_flag(self):
        import os
        import tempfile
        import spoofy
        seen = {}

        def fake(domain, **kw):
            seen.update(kw)
            return {"DOMAIN": domain, "SCORE_OVERALL": 55 if domain == "bad.com" else 95}

        with tempfile.TemporaryDirectory() as tmp:
            lst = os.path.join(tmp, "d.txt")
            with open(lst, "w") as fh:
                fh.write("good.com\nbad.com\n")
            argv = ["spoofy", "-iL", lst, "-o", "json", "--out", os.path.join(tmp, "o.json"), "--basic"]
            with mock.patch.object(spoofy, "process_domain", fake), mock.patch("sys.argv", argv + ["--min-score", "60"]):
                with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stderr(io.StringIO()) as err:
                    spoofy.main()
            self.assertEqual(ctx.exception.code, 2)
            self.assertIn("bad.com (55)", err.getvalue())
            self.assertIs(seen["extended"], False)
            with mock.patch.object(spoofy, "process_domain", fake), mock.patch("sys.argv", argv + ["--min-score", "50"]):
                spoofy.main()


if __name__ == "__main__":
    unittest.main()
