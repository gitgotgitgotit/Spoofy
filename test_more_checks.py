"""Offline tests: SPF walk/hardening, takeover, nameservers, non-sending hygiene, DMARC reporting, DKIM hygiene."""
import time
import unittest
from unittest import mock

import tests_stubs

tests_stubs.install()

from modules import assessment, dkim as dkim_mod  # noqa: E402
from modules.dkim import DKIM  # noqa: E402
from modules.dkim_hygiene import dkim_rotation_hints  # noqa: E402
from modules.dmarc_reporting import check_dmarc_reporting  # noqa: E402
from modules.nameservers import check_nameservers  # noqa: E402
from modules.nonsending import check_nonsending  # noqa: E402
from modules.spf_hardening import check_spf_hardening  # noqa: E402
from modules.spf_walk import walk_spf  # noqa: E402
from modules.takeover import check_takeover  # noqa: E402
from test_checks import (FakeResolver, NS, NOANSWER, NXDOMAIN, SERVFAIL, TIMEOUT, addr, codes,  # noqa: E402
                         good_result, mx, txt, zone_patch)

NS_OK = [NS(target="ns1.example.net."), NS(target="ns2.example.org.")]


def walk(zone, record, domain="example.com", **kw):
    with zone_patch(zone):
        return walk_spf(domain, record, "1.1.1.1", **kw)


class SpfWalkAndHardeningTests(unittest.TestCase):
    RECORD = "v=spf1 include:a.example.net include:b.example.net a:gone.example.com mx ptr ip4:10.0.0.0/8 -all"
    ZONE = {("a.example.net", "TXT"): [txt("v=spf1 ip4:1.2.3.4 -all")]}

    def test_walk_counts_void_lookups_and_statuses(self):
        w = walk(self.ZONE, self.RECORD)
        self.assertEqual({i["target"]: i["status"] for i in w["includes"]}, {"a.example.net": "ok", "b.example.net": "nxdomain"})
        self.assertEqual(w["void_lookups"], 3)  # b.example.net + a:gone + mx (no MX records)
        self.assertTrue(w["ptr"])
        self.assertEqual(w["lookups"], 5)  # 2 includes + a + mx + ptr
        self.assertEqual(sorted(r["network"] for r in w["ip_ranges"]), ["1.2.3.4/32", "10.0.0.0/8"])

    def test_hardening_findings(self):
        r = check_spf_hardening(self.RECORD, walk(self.ZONE, self.RECORD))
        self.assertEqual(sorted(codes(r)), ["SPF_HUGE_RANGE", "SPF_INCLUDE_MISSING", "SPF_PTR", "SPF_VOID_LOOKUPS"])

    def test_skip_targets_avoids_double_reporting(self):
        r = check_spf_hardening(self.RECORD, walk(self.ZONE, self.RECORD), skip_targets=["b.example.net"])
        self.assertNotIn("SPF_INCLUDE_MISSING", codes(r))

    def test_include_without_spf_record_and_loops_and_macros(self):
        zone = {("plain.example.net", "TXT"): [txt("hello world")], ("loop.example.net", "TXT"): [txt("v=spf1 include:loop.example.net -all")]}
        rec = "v=spf1 include:plain.example.net include:loop.example.net include:%{d}.x.net -all"
        w = walk(zone, rec)
        self.assertEqual([(i["target"], i["status"]) for i in w["includes"]],
                         [("plain.example.net", "no-spf"), ("loop.example.net", "ok"), ("loop.example.net", "loop")])  # self-include detected, no infinite walk
        self.assertIn("SPF_INCLUDE_NO_RECORD", codes(check_spf_hardening(rec, w)))
        self.assertNotIn("%{d}.x.net", [i["target"] for i in w["includes"]])

    def test_allow_all_and_only_plus_qualified_ranges_count(self):
        rec = "v=spf1 ip4:0.0.0.0/0 ~ip4:8.0.0.0/8 ip6:2001:db8::/16 ip4:172.16.0.0/12 -all"
        r = check_spf_hardening(rec, walk({}, rec))
        self.assertEqual(sorted(codes(r)), ["SPF_ALLOW_ALL_RANGE", "SPF_HUGE_RANGE", "SPF_LARGE_RANGE"])
        self.assertEqual(codes(r, "critical"), ["SPF_ALLOW_ALL_RANGE"])

    def test_long_record_truncation_and_clean_record(self):
        long_rec = "v=spf1 " + " ".join(f"ip4:192.0.2.{i}" for i in range(1, 60)) + " -all"
        self.assertIn("SPF_LONG_RECORD", codes(check_spf_hardening(long_rec, walk({}, long_rec))))
        clean = "v=spf1 ip4:192.0.2.1 -all"
        self.assertEqual(codes(check_spf_hardening(clean, walk({}, clean))), [])
        deep = {(f"i{n}.example.net", "TXT"): [txt(f"v=spf1 include:i{n + 1}.example.net -all")] for n in range(10)}
        w = walk(deep, "v=spf1 include:i0.example.net -all", max_records=3)
        self.assertTrue(w["truncated"])
        self.assertIn("SPF_WALK_TRUNCATED", codes(check_spf_hardening("v=spf1 include:i0.example.net -all", w)))

    def test_no_spf_not_applicable(self):
        self.assertFalse(check_spf_hardening(None, walk({}, None))["applicable"])


class TakeoverTests(unittest.TestCase):
    def run_check(self, zone, w=None, ns_data=None, dangling=None):
        with zone_patch(zone):
            return check_takeover("example.com", "1.1.1.1", w or {"includes": []}, ns_data or {"hosts": []}, dangling)

    def test_unregistered_include_domain_is_critical(self):
        w = {"includes": [{"target": "_spf.dead.net", "parent": "example.com", "status": "nxdomain"}]}
        r = self.run_check({}, w)  # dead.net has no NS => NXDOMAIN => unregistered
        self.assertEqual(codes(r, "critical"), ["TAKEOVER_SPF_INCLUDE"])
        self.assertEqual(r["data"]["unregistered_targets"], ["_spf.dead.net"])

    def test_registered_domain_or_own_domain_is_not_a_takeover(self):
        w = {"includes": [{"target": "_spf.vendor.net", "parent": "example.com", "status": "nxdomain"},
                          {"target": "spf.example.com", "parent": "example.com", "status": "nxdomain"}]}
        self.assertEqual(codes(self.run_check({("vendor.net", "NS"): [NS(target="ns.vendor.net.")]}, w)), [])

    def test_unregistered_nameserver_domain(self):
        ns = {"hosts": [{"host": "ns1.dead-dns.org", "nxdomain": True}, {"host": "ns2.example.com", "nxdomain": True}]}
        r = self.run_check({}, ns_data=ns)
        self.assertEqual(codes(r, "critical"), ["TAKEOVER_NAMESERVER"])  # own-domain NS host is not a takeover

    def test_dkim_dangling_cname(self):
        r = self.run_check({("vendor.net", "NS"): [NS(target="x.")]}, dangling={"sel1": "k1.dkim.vendor.net", "sel2": "k.gone.org"})
        self.assertEqual(sorted(codes(r)), ["DKIM_CNAME_DANGLING", "TAKEOVER_DKIM_CNAME"])
        self.assertEqual(codes(r, "critical"), ["TAKEOVER_DKIM_CNAME"])

    def test_dkim_class_detects_dangling_cname(self):
        zone = {("sel1._domainkey.example.com", "CNAME"): [NS(target="k.dkim.vendor.net.")]}
        with mock.patch.object(dkim_mod, "get_resolver", lambda *a, **k: FakeResolver(zone)):
            d = DKIM("example.com", "1.1.1.1", selectors=["sel1", "plain"])
            self.assertEqual(d.dangling_cnames, {"sel1": "k.dkim.vendor.net"})
            d2 = DKIM("example.com", "1.1.1.1", selectors=["sel1"], check_dangling=False)
            self.assertEqual(d2.dangling_cnames, {})


class NameserverTests(unittest.TestCase):
    ZONE = {("example.com", "NS"): NS_OK, ("ns1.example.net", "A"): [addr("8.8.8.8")], ("ns2.example.org", "A"): [addr("1.1.1.1")]}

    def run_check(self, zone, direct):
        with zone_patch(zone):
            return check_nameservers("sub.example.com", "9.9.9.9", direct=direct)

    def test_healthy(self):
        r = self.run_check(self.ZONE, lambda ip, name: (2026010101, True, None))
        self.assertEqual(codes(r), [])
        self.assertEqual(r["data"]["zone"], "example.com")  # checks the registered domain, not the subdomain

    def test_lame_error_and_serial_mismatch(self):
        answers = {"8.8.8.8": (5, True, None), "1.1.1.1": (7, False, None)}
        self.assertEqual(sorted(codes(self.run_check(self.ZONE, lambda ip, n: answers[ip]))), ["NS_LAME"])
        answers = {"8.8.8.8": (5, True, None), "1.1.1.1": (None, False, "timeout")}
        r = self.run_check(self.ZONE, lambda ip, n: answers[ip])
        self.assertEqual(codes(r, "low"), ["NS_NO_ANSWER"])
        answers = {"8.8.8.8": (None, False, "rcode 5"), "1.1.1.1": (5, True, None)}
        self.assertEqual(codes(self.run_check(self.ZONE, lambda ip, n: answers[ip]), "medium"), ["NS_NO_ANSWER"])
        answers = {"8.8.8.8": (5, True, None), "1.1.1.1": (6, True, None)}
        self.assertEqual(codes(self.run_check(self.ZONE, lambda ip, n: answers[ip])), ["NS_SERIAL_MISMATCH"])

    def test_single_unresolvable_and_same_network(self):
        single = {("example.com", "NS"): [NS(target="ns1.example.net.")], ("ns1.example.net", "A"): [addr("8.8.8.8")]}
        self.assertIn("NS_SINGLE", codes(self.run_check(single, lambda ip, n: (1, True, None))))
        dead = {("example.com", "NS"): NS_OK, ("ns1.example.net", "A"): [addr("8.8.8.8")]}
        r = self.run_check(dead, lambda ip, n: (1, True, None))
        self.assertEqual(codes(r, "high"), ["NS_UNRESOLVABLE"])
        self.assertTrue([h for h in r["data"]["hosts"] if h["nxdomain"]])
        same = {**self.ZONE, ("ns2.example.org", "A"): [addr("8.8.8.9")]}
        self.assertEqual(codes(self.run_check(same, lambda ip, n: (1, True, None))), ["NS_SAME_NETWORK"])

    def test_resolution_error_is_not_unresolvable(self):
        zone = {**self.ZONE, ("ns2.example.org", "A"): TIMEOUT(), ("ns2.example.org", "AAAA"): TIMEOUT()}
        r = self.run_check(zone, lambda ip, n: (1, True, None))
        self.assertIn("NS_RESOLVE_ERROR", codes(r))
        self.assertNotIn("NS_UNRESOLVABLE", codes(r))

    def test_lookup_failure_not_scored(self):
        self.assertFalse(self.run_check({("example.com", "NS"): SERVFAIL()}, None)["applicable"])


REVOKED = {("spoofy-nonexistent-selector._domainkey.example.com", "TXT"): [txt("v=DKIM1; p=")]}


class NonSendingTests(unittest.TestCase):
    def run_check(self, mx_data, result, zone=None):
        with zone_patch(zone or {}):
            return check_nonsending("example.com", "1.1.1.1", mx_data, result)

    def test_null_mx_without_protection(self):
        r = self.run_check({"null_mx": True}, {"SPF": None, "DMARC": None})
        self.assertEqual(sorted(codes(r, "high")), ["NONMAIL_NO_DMARC", "NONMAIL_NO_SPF"])
        self.assertIn("NONMAIL_NO_DKIM_REVOKE", codes(r, "low"))

    def test_no_mx_hint_is_one_level_lower(self):
        r = self.run_check({"no_mail": True}, {"SPF": None, "DMARC": None})
        self.assertEqual(sorted(codes(r, "medium")), ["NONMAIL_NO_DMARC", "NONMAIL_NO_SPF"])

    def test_locked_down_domain_is_clean(self):
        r = self.run_check({"null_mx": True}, {"SPF": "v=spf1 -all", "SPF_MULTIPLE_ALLS": "-all", "DMARC": "v=DMARC1; p=reject", "DMARC_POLICY": "reject"}, REVOKED)
        self.assertEqual(codes(r), ["NONMAIL_OK"])

    def test_weak_policies(self):
        r = self.run_check({"null_mx": True}, {"SPF": "v=spf1 ~all", "SPF_MULTIPLE_ALLS": "~all", "DMARC": "v=DMARC1; p=none", "DMARC_POLICY": "none"}, REVOKED)
        self.assertEqual(sorted(codes(r)), ["NONMAIL_DMARC_NOT_REJECT", "NONMAIL_SPF_NOT_FAIL"])

    def test_not_applicable_when_domain_receives_mail(self):
        self.assertFalse(self.run_check({"records": [{"host": "mx"}], "null_mx": False}, {})["applicable"])


class DmarcReportingTests(unittest.TestCase):
    def run_check(self, record, zone=None, **kw):
        with zone_patch(zone or {}):
            return check_dmarc_reporting("example.com", "1.1.1.1", record, **kw)

    def test_external_destination_needs_authorisation(self):
        rec = "v=DMARC1; p=reject; rua=mailto:r@vendor.net!10m,mailto:r2@vendor.net"
        bad = self.run_check(rec)
        self.assertEqual(codes(bad, "medium"), ["DMARC_REPORT_UNAUTHORISED"])  # one finding: destination de-duplicated, !size stripped
        ok = self.run_check(rec, {("example.com._report._dmarc.vendor.net", "TXT"): [txt("v=DMARC1")]})
        self.assertEqual(codes(ok), ["DMARC_REPORTING_OK"])
        self.assertEqual(ok["data"]["external_destinations"], {"vendor.net": "authorised"})

    def test_internal_and_subdomain_destinations_need_no_authorisation(self):
        self.assertEqual(codes(self.run_check("v=DMARC1; p=none; rua=mailto:a@example.com,mailto:b@mail.example.com")), ["DMARC_REPORTING_OK"])

    def test_authorisation_uses_the_record_domain(self):
        zone = {("example.com._report._dmarc.vendor.net", "TXT"): [txt("v=DMARC1")]}
        with zone_patch(zone):
            r = check_dmarc_reporting("sub.example.com", "1.1.1.1", "v=DMARC1; p=none; rua=mailto:a@vendor.net", record_domain="example.com")
        self.assertEqual(codes(r), ["DMARC_REPORTING_OK"])

    def test_ruf_bad_address_scheme_length_and_lookup_error(self):
        r = self.run_check("v=DMARC1; p=none; rua=mailto:not-an-address,https://x.example.com/r; ruf=mailto:f@example.com")
        self.assertEqual(sorted(codes(r)), ["DMARC_REPORT_BAD_ADDRESS", "DMARC_REPORT_NON_MAILTO", "DMARC_RUF"])
        long_rec = "v=DMARC1; p=none; rua=" + ",".join(f"mailto:r{i}@example.com" for i in range(15))
        self.assertIn("DMARC_LONG_RECORD", codes(self.run_check(long_rec)))
        err = self.run_check("v=DMARC1; p=none; rua=mailto:a@vendor.net", {("example.com._report._dmarc.vendor.net", "TXT"): TIMEOUT()})
        self.assertEqual(codes(err), ["DMARC_REPORT_AUTH_UNKNOWN"])  # a timeout is not "unauthorised"

    def test_no_dmarc_not_applicable(self):
        self.assertFalse(self.run_check(None)["applicable"])


NOW = time.mktime((2026, 11, 17, 12, 0, 0, 0, 0, 0))


def rec(selector, key="AAAA", source="dns"):
    return {"selector": selector, "source": source, "record": f"v=DKIM1; k=rsa; p={key}"}


class DkimHygieneTests(unittest.TestCase):
    def test_key_reuse(self):
        f = dkim_rotation_hints([rec("a", "KEY1"), rec("b", "KEY1"), rec("c", "KEY2")], NOW)
        self.assertEqual([x["code"] for x in f], ["DKIM_KEY_REUSED"])
        self.assertEqual(f[0]["evidence"], ["a", "b"])

    def test_stale_date_selector(self):
        f = dkim_rotation_hints([rec("s202301", "K1"), rec("s202112", "K2")], NOW)
        self.assertEqual([x["code"] for x in f], ["DKIM_ROTATION_STALE"])
        self.assertIn("s202301", f[0]["title"])
        self.assertIn("heuristic", f[0]["title"])

    def test_recent_and_non_date_selectors_are_not_flagged(self):
        self.assertEqual(dkim_rotation_hints([rec("s202610", "K1"), rec("2026-03", "K2"), rec("google", "K3"), rec("s2048", "K4"), rec("selector1", "K5")], NOW), [])

    def test_key_size_selector_does_not_mask_a_stale_date_selector(self):
        # "s2048" looks like year 2048; if it were accepted it would hide the genuinely old s202301
        f = dkim_rotation_hints([rec("s202301", "K1"), rec("s2048", "K2")], NOW)
        self.assertEqual([x["code"] for x in f], ["DKIM_ROTATION_STALE"])

    def test_year_only_assumes_december_and_archive_keys_are_ignored(self):
        self.assertEqual(dkim_rotation_hints([rec("2025", "K1")], NOW), [])  # 11 months, not stale
        self.assertEqual([x["code"] for x in dkim_rotation_hints([rec("2023", "K1")], NOW)], ["DKIM_ROTATION_STALE"])
        self.assertEqual(dkim_rotation_hints([rec("s202001", "K", "archive-historical")], NOW), [])

    def test_hints_flow_into_the_dkim_score_area(self):
        from modules.scoring import build_score
        good = {"selector": "s202001", "live": True, "overall": "good", "status": "good", "alerts": [], "issues": []}
        r = good_result(DKIM_ENABLED=True, DKIM_ANALYSIS=[good], DKIM=[rec("s202001", "K")])
        self.assertEqual([f["code"] for f in build_score(r, {})["areas"]["DKIM"]["findings"]], ["DKIM_ROTATION_STALE"])


class AssessmentPipelineTests(unittest.TestCase):
    def zone(self):
        return {("example.com", "NS"): NS_OK, ("ns1.example.net", "A"): [addr("8.8.8.8")], ("ns2.example.org", "A"): [addr("1.1.1.1")],
                ("example.com", "MX"): [mx(0, ".")], ("_dmarc.example.com", "TXT"): [txt("v=DMARC1; p=reject")],
                ("example.com", "DS"): NOANSWER(), ("example.com", "DNSKEY"): NOANSWER(), ("example.com", "CAA"): NOANSWER()}

    def result(self, **over):
        return good_result(SPF="v=spf1 include:_spf.dead-vendor.net -all", DMARC_RECORD_DOMAIN="example.com", **over)

    def test_full_pipeline_flags_unregistered_include_and_caps_the_score(self):
        with zone_patch(self.zone()), mock.patch("modules.nameservers.dnsutil.direct_soa", lambda ip, n, timeout=4: (1, True, None)):
            out = assessment.assess(self.result(), "1.1.1.1", extended=True)
        areas = out["score"]["areas"]
        for name in ("Takeover risk", "SPF hardening", "Nameservers", "Non-sending hygiene", "DMARC reporting", "IPv6"):
            self.assertIn(name, areas)
        self.assertEqual([f["code"] for f in areas["Takeover risk"]["findings"]], ["TAKEOVER_SPF_INCLUDE"])
        self.assertNotIn("SPF_INCLUDE_MISSING", [f["code"] for f in areas["SPF hardening"]["findings"]])  # not double-counted
        self.assertTrue(areas["Non-sending hygiene"]["applicable"])  # null MX
        self.assertLessEqual(out["score"]["overall"], 69)

    def test_basic_mode_skips_all_new_checks(self):
        out = assessment.assess(self.result(), "1.1.1.1", extended=False)
        skipped = {n["area"] for n in out["score"]["not_assessed"]}
        self.assertTrue({"Takeover risk", "SPF hardening", "Nameservers", "Non-sending hygiene", "DMARC reporting"} <= skipped)

    def test_one_failing_new_check_does_not_break_the_scan(self):
        with zone_patch(self.zone()), mock.patch.object(assessment, "check_nameservers", side_effect=RuntimeError("boom")), \
                mock.patch.object(assessment, "walk_spf", side_effect=RuntimeError("boom")):
            out = assessment.assess(self.result(), "1.1.1.1", extended=True)
        self.assertFalse(out["score"]["areas"]["Nameservers"]["applicable"])
        self.assertIsInstance(out["score"]["overall"], int)


if __name__ == "__main__":
    unittest.main()
