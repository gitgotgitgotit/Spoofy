"""Offline tests (no network, no real DNS): DKIM discovery, DMARC, BIMI, inputs, report, spoofing."""
import contextlib
import io
import json
import os
import tempfile
import types
import unittest
from unittest import mock

import tests_stubs

tests_stubs.install()

import dns.exception  # noqa: E402
import dns.resolver  # noqa: E402

from modules import dkim as dkim_mod  # noqa: E402
from modules import report  # noqa: E402
from modules.bimi import BIMI  # noqa: E402
from modules.dkim import DKIM, load_header_signatures, looks_like_dkim  # noqa: E402
from modules.dmarc import DMARC  # noqa: E402
from modules.inputs import load_domains, normalize_domain  # noqa: E402
from modules.spoofing import apply_dkim_risk  # noqa: E402
from modules.txt import txt_value  # noqa: E402
from test_dkim_analysis import fake_rsa_record  # noqa: E402


class FakeTXT:
    def __init__(self, *chunks):
        self.strings = [c.encode() for c in chunks]


class FakeResolver:
    """zone: {(name, 'TXT'): [tuple_of_chunks, ...] | Exception}; anything else is NXDOMAIN."""

    def __init__(self, zone):
        self.zone, self.timeout, self.lifetime = zone, None, None

    def resolve(self, name, rtype):
        entry = self.zone.get((name.lower(), rtype), dns.resolver.NXDOMAIN())
        if isinstance(entry, Exception):
            raise entry
        return [FakeTXT(*chunks) for chunks in entry]


def patch_resolver(module, zone):
    return mock.patch.object(module, "get_resolver", lambda *a, **k: FakeResolver(zone))


class InputTests(unittest.TestCase):
    def test_normalisation(self):
        cases = {"Example.COM.": "example.com", "https://Example.com/path?x=1": "example.com",
                 "user@example.com": "example.com", "example.com:8443": "example.com",
                 "example.com # note": "example.com", "bücher.de": "xn--bcher-kva.de"}
        for raw, want in cases.items():
            self.assertEqual(normalize_domain(raw), want, raw)
        for bad in ("", "# comment", "localhost", "exa mple.com", "-bad.com", "a..b.com"):
            self.assertIsNone(normalize_domain(bad), bad)

    def test_load_domains_dedupes_and_reports_rejects(self):
        domains, rejected = load_domains(["a.com\n", "A.com.\n", "# c\n", "\n", "nope\n", "https://b.com/x\n"])
        self.assertEqual(domains, ["a.com", "b.com"])
        self.assertEqual(rejected, ["nope"])


class TxtTests(unittest.TestCase):
    def test_chunks_are_joined_without_spaces(self):
        self.assertEqual(txt_value(FakeTXT("v=DMARC1; rua=mailto:aa", "aa@x.com")), "v=DMARC1; rua=mailto:aaaa@x.com")


class DkimDiscoveryTests(unittest.TestCase):
    def test_filter_ignores_spf_and_dmarc_text(self):
        self.assertFalse(looks_like_dkim("v=spf1 include:_spf.x.com exp=explain.x.com -all"))
        self.assertFalse(looks_like_dkim("v=DMARC1; sp=none; pct=100"))
        self.assertFalse(looks_like_dkim("hello world p=3"))  # free text: the tag name is "hello world p"
        self.assertTrue(looks_like_dkim("v=DKIM1; k=rsa; p=ABC"))
        self.assertTrue(looks_like_dkim("k=rsa; p=ABC"))  # v= is optional

    def build(self, zone, api=None, use_api=True, **kw):
        kw.setdefault("selectors", ["good", "flaky", "spfish", "missing"])
        with patch_resolver(dkim_mod, zone), mock.patch.object(DKIM, "get_dkim_record_from_api", return_value=api or {}):
            return DKIM("example.com", "1.1.1.1", use_api=use_api, **kw)

    def test_timeouts_are_errors_not_absence_and_spf_text_is_not_a_key(self):
        good = fake_rsa_record(2048)
        zone = {("good._domainkey.example.com", "TXT"): [(good,)],
                ("flaky._domainkey.example.com", "TXT"): dns.exception.Timeout(),
                ("spfish._domainkey.example.com", "TXT"): [("v=spf1 exp=x.example.com -all",)]}
        d = self.build(zone)
        self.assertEqual(list(d.dns_records), ["good"])
        self.assertEqual(d.lookup_errors, {"flaky": "timeout"})  # missing (NXDOMAIN) is NOT an error
        self.assertEqual([r["source"] for r in d.records], ["dns"])

    def test_archive_only_keys_are_labelled_not_live(self):
        weak = fake_rsa_record(512)
        zone = {("flaky._domainkey.example.com", "TXT"): dns.exception.Timeout()}
        d = self.build(zone, api={"old": weak, "flaky": weak}, selectors=["flaky"])
        sources = {r["selector"]: r["source"] for r in d.records}
        self.assertEqual(sources, {"old": "archive-historical", "flaky": "archive-unverified"})
        self.assertTrue(all(not k["live"] for k in d.key_analysis))
        self.assertEqual(apply_dkim_risk("example.com", False, "x", d.key_analysis)[2], None)

    def test_live_dns_beats_archive(self):
        zone = {("k1._domainkey.example.com", "TXT"): [(fake_rsa_record(2048),)]}
        d = self.build(zone, api={"k1": fake_rsa_record(512)}, selectors=["k1"])
        self.assertEqual((d.records[0]["source"], d.key_analysis[0]["key_bits"]), ("dns", 2048))

    def test_archive_api_is_off_by_default(self):
        with patch_resolver(dkim_mod, {}), mock.patch.object(DKIM, "get_dkim_record_from_api") as api:
            DKIM("example.com", "1.1.1.1", selectors=["a"])
            api.assert_not_called()
            DKIM("example.com", "1.1.1.1", selectors=["a"], use_api=True)
            api.assert_called_once()

    def test_extra_selectors_and_untrusted_archive_names(self):
        d = self.build({}, selectors=["a"], extra_selectors=["mine", "bad selector!"])
        self.assertEqual(d.selectors[0], "mine")
        self.assertNotIn("bad selector!", d.selectors)
        fmt = DKIM.format_api_records(d, [{"selector": "../evil", "value": "x"}, {"selector": "ok", "value": "v=DKIM1; p=x", "lastSeenAt": None},
                                          {"selector": "n", "value": 5}])
        self.assertEqual(fmt, {"ok": "v=DKIM1; p=x"})

    def test_header_signatures(self):
        raw = ("From: a@example.com\r\nDKIM-Signature: v=1; a=rsa-sha1; c=relaxed/relaxed;\r\n"
               "\td=Example.com; s=sel1;\r\n\tb=AAAA\r\n\tBBBB\r\nDKIM-Signature: v=1; a=rsa-sha256; d=other.org; s=x\r\n\r\nbody")
        with tempfile.NamedTemporaryFile("w", suffix=".eml", delete=False) as fh:
            fh.write(raw)
        try:
            sigs = load_header_signatures(fh.name)
        finally:
            os.unlink(fh.name)
        self.assertEqual([(s["domain"], s["selector"], s["alerts"]) for s in sigs],
                         [("example.com", "sel1", ["SIGNATURE_SHA1"]), ("other.org", "x", [])])
        d = self.build({("sel1._domainkey.example.com", "TXT"): [(fake_rsa_record(2048),)]}, selectors=["a"], header_signatures=sigs)
        self.assertIn("sel1", d.dns_records)
        self.assertEqual(len(d.header_signatures), 1)  # the other.org signature is not for this domain


class DmarcTests(unittest.TestCase):
    def make(self, zone, domain):
        with patch_resolver(__import__("modules.dmarc", fromlist=["x"]), zone):
            return DMARC(domain, "1.1.1.1")

    def test_subdomain_record_beats_organizational_record(self):
        zone = {("_dmarc.sub.example.com", "TXT"): [("v=DMARC1; p=REJECT",)],
                ("_dmarc.example.com", "TXT"): [("v=DMARC1; p=none",)]}
        d = self.make(zone, "sub.example.com")
        self.assertEqual((d.policy, d.record_domain), ("reject", "sub.example.com"))  # also case-normalised

    def test_falls_back_to_organizational_domain(self):
        d = self.make({("_dmarc.example.com", "TXT"): [("v=DMARC1; p=none",)]}, "sub.example.com")
        self.assertEqual((d.policy, d.record_domain), ("none", "example.com"))

    def test_multiple_records_means_no_policy(self):
        d = self.make({("_dmarc.example.com", "TXT"): [("v=DMARC1; p=none",), ("v=DMARC1; p=reject",)]}, "example.com")
        self.assertTrue(d.multiple_records)
        self.assertIsNone(d.dmarc_record)

    def test_multi_string_record_is_not_split_by_a_space(self):
        d = self.make({("_dmarc.example.com", "TXT"): [("v=DMARC1; p=none; rua=mailto:dmarc-aggregate", "@example.com",)]}, "example.com")
        self.assertEqual(d.rua, "mailto:dmarc-aggregate@example.com")

    def test_non_dmarc_txt_is_ignored(self):
        d = self.make({("_dmarc.example.com", "TXT"): [("note about DMARC1 policy",)]}, "example.com")
        self.assertIsNone(d.dmarc_record)


class BimiTests(unittest.TestCase):
    def test_record_is_plain_string_and_urls_are_not_resplit(self):
        zone = {("default._bimi.example.com", "TXT"): [("v=BIMI1; l=https://x.com/logo.svg?a=1&l=2; a=https://x.com/vmc.pem",)]}
        with patch_resolver(__import__("modules.bimi", fromlist=["x"]), zone):
            b = BIMI("example.com", "1.1.1.1")
        self.assertIsInstance(b.bimi_record, str)
        self.assertEqual(b.get_bimi_details(), ("BIMI1", "https://x.com/logo.svg?a=1&l=2", "https://x.com/vmc.pem"))
        json.dumps({"BIMI_RECORD": b.bimi_record})  # must not raise


class ReportTests(unittest.TestCase):
    def capture(self, **kw):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            report.printer(DOMAIN="example.com", DOMAIN_TYPE="domain", DNS_SERVER="1.1.1.1", **kw)
        return buf.getvalue()

    def dkim_kw(self, *records):
        from modules.dkim_analysis import analyze_dkim_keys
        recs = [{"selector": s, "fqdn": f"{s}._domainkey.example.com", "source": src, "record": r} for s, r, src in records]
        return dict(DKIM_ENABLED=True, DKIM=recs, DKIM_ANALYSIS=analyze_dkim_keys(
            {r["selector"]: r["record"] for r in recs}, {r["selector"]: r["source"] for r in recs}))

    def test_no_dkim_message_when_dkim_not_enabled(self):
        out = self.capture(DKIM=None, DKIM_ANALYSIS=None)
        self.assertNotIn("DKIM", out)

    def test_not_found_message_when_enabled(self):
        out = self.capture(DKIM_ENABLED=True, DKIM=None)
        self.assertIn("No DKIM selectors found", out)
        self.assertIn("does not prove", out)

    def test_alerts_testing_mode_is_not_shown_as_plain_good(self):
        out = self.capture(**self.dkim_kw(("s", fake_rsa_record(2048, "t=y; h=sha1"), "dns")))
        self.assertIn("WARNING", out)
        self.assertIn("TESTING_MODE", out)
        self.assertIn("SHA1_ALLOWED", out)
        self.assertNotIn("GOOD", out)

    def test_weak_key_alert_and_archive_labelling(self):
        out = self.capture(**self.dkim_kw(("w", fake_rsa_record(512), "dns"), ("old", fake_rsa_record(768), "archive-historical")))
        self.assertIn("WEAK_KEY_512", out)
        self.assertNotIn("WEAK_KEY_768", out)  # the archive-only 768-bit key raises no live alert
        self.assertIn("not live", out)
        self.assertLess(out.index("w | rsa | 512"), out.index("old | rsa | 768"))  # worst live finding first

    def test_lookup_errors_are_reported(self):
        out = self.capture(DKIM_ENABLED=True, DKIM=None, DKIM_LOOKUP_ERRORS={"x": "timeout"})
        self.assertIn("lookup(s) failed", out)

    def test_json_survives_unserialisable_values_and_empty_results(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            report.output_json([{"a": object()}])
            report.output_json([])
        first, second = buf.getvalue().splitlines()
        self.assertEqual(len(json.loads(first)), 1)
        self.assertEqual(json.loads(second), [])

    def test_xlsx_and_csv_store_json_not_python_repr_and_append(self):
        rows = [{"DOMAIN": "a.com", "DKIM_ANALYSIS": [{"selector": "s", "alerts": ["WEAK_KEY_512"]}]}]
        with tempfile.TemporaryDirectory() as tmp:
            import pandas as pd
            x, c = os.path.join(tmp, "o.xlsx"), os.path.join(tmp, "o.csv")
            for _ in range(2):
                report.write_to_excel(rows, x)
                report.write_to_csv(rows, c)
            for df in (pd.read_excel(x), pd.read_csv(c)):
                self.assertEqual(len(df), 2)
                self.assertEqual(json.loads(df["DKIM_ANALYSIS"][0])[0]["alerts"], ["WEAK_KEY_512"])


class SpoofingDkimTests(unittest.TestCase):
    def analysis(self, bits, source="dns"):
        from modules.dkim_analysis import analyze_dkim_keys
        return analyze_dkim_keys({"s": fake_rsa_record(bits)}, {"s": source})

    def test_weak_live_key_overrides_not_spoofable(self):
        possible, kind, note = apply_dkim_risk("example.com", False, "Spoofing is not possible", self.analysis(512))
        self.assertIsNone(possible)
        self.assertIn("DKIM key forgery", kind)
        self.assertIn("512-bit", note)

    def test_existing_positive_verdict_is_kept(self):
        self.assertEqual(apply_dkim_risk("e.com", True, "Spoofing possible", self.analysis(768))[:2], (True, "Spoofing possible"))

    def test_1024_and_historical_keys_do_not_change_verdict(self):
        self.assertEqual(apply_dkim_risk("e.com", False, "t", self.analysis(1024)), (False, "t", None))
        self.assertEqual(apply_dkim_risk("e.com", False, "t", self.analysis(512, "archive-historical")), (False, "t", None))


class CliTests(unittest.TestCase):
    def test_api_is_opt_in_on_the_command_line(self):
        import spoofy
        seen = []

        def fake(domain, **kw):
            seen.append((kw.get("enable_dkim"), kw["dkim_options"]["use_api"]))
            return {"DOMAIN": domain}

        for extra, expected in (([], (True, False)), (["--dkim-api"], (True, True)), (["--dkim-no-api"], (True, False))):
            seen.clear()
            with mock.patch.object(spoofy, "process_domain", fake), mock.patch("sys.argv", ["spoofy", "-d", "a.com", "--dkim", "-o", "json", *extra]):
                with contextlib.redirect_stdout(io.StringIO()):
                    spoofy.main()
            self.assertEqual(seen, [expected], extra)
        seen.clear()  # --dkim-api alone turns DKIM scanning on
        with mock.patch.object(spoofy, "process_domain", fake), mock.patch("sys.argv", ["spoofy", "-d", "a.com", "--dkim-api", "-o", "json"]):
            with contextlib.redirect_stdout(io.StringIO()):
                spoofy.main()
        self.assertEqual(seen, [(True, True)])

    def test_fail_on_and_input_validation(self):
        import spoofy
        parser = spoofy.build_parser()
        args = parser.parse_args(["-d", "a.com", "--dkim", "--fail-on", "critical", "-o", "csv", "--dkim-selector", "x,y"])
        self.assertEqual((args.fail_on, args.o, args.dkim_selector), ("critical", "csv", ["x,y"]))

    def test_main_exit_codes_and_ordering(self):
        import spoofy

        def fake_process(domain, **kw):
            from modules.dkim_analysis import analyze_dkim_keys
            bits = 512 if domain == "weak.com" else 2048
            return {"DOMAIN": domain, "DKIM_ENABLED": True,
                    "DKIM_ANALYSIS": analyze_dkim_keys({"s": fake_rsa_record(bits)})}

        with tempfile.TemporaryDirectory() as tmp:
            lst = os.path.join(tmp, "d.txt")
            with open(lst, "w") as fh:
                fh.write("b.com\nweak.com\n# skip\nA.com\nb.com\n")
            out = os.path.join(tmp, "o.json")
            argv = ["spoofy", "-iL", lst, "--dkim", "--dkim-no-api", "-o", "json", "--out", out, "-t", "3"]
            with mock.patch.object(spoofy, "process_domain", fake_process), mock.patch("sys.argv", argv + ["--fail-on", "critical"]):
                with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stderr(io.StringIO()):
                    spoofy.main()
            self.assertEqual(ctx.exception.code, 2)
            with open(out) as fh:
                self.assertEqual([r["DOMAIN"] for r in json.load(fh)], ["b.com", "weak.com", "a.com"])  # input order, de-duplicated
            with mock.patch.object(spoofy, "process_domain", fake_process), mock.patch("sys.argv", argv):
                spoofy.main()  # no --fail-on: exit normally


if __name__ == "__main__":
    unittest.main()
