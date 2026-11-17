import unittest
from unittest.mock import patch

from modules.spf_parser import parse_spf, validate_spf
from modules.syntax import validate_record_syntax
from modules.spf import SPF
from modules.spf_intelligence import analyze_spf


class SPFParserTests(unittest.TestCase):
    def test_qualifiers_are_parsed(self):
        terms = parse_spf("v=spf1 -include:mail.example.com ~all")
        self.assertEqual((terms[0].qualifier, terms[0].mechanism), ("-", "include"))
        self.assertEqual((terms[1].qualifier, terms[1].mechanism), ("~", "all"))

    def test_valid_ip_networks(self):
        self.assertTrue(validate_spf("v=spf1 ip4:192.0.2.1/24 ip6:2001:db8::/32 -all"))
        self.assertFalse(validate_spf("v=spf1 ip4:999.999.999.999 -all"))
        self.assertFalse(validate_spf("v=spf1 ip6:2001:db8::/999 -all"))

    def test_valid_a_mx_cidr(self):
        self.assertTrue(validate_spf("v=spf1 a/24 mx:mail.example.com/24//64 -all"))
        self.assertTrue(validate_spf("v=spf1 include:_spf.google.com exists:%{i}._spf.example.com -all"))

    def test_qualifier_syntax_validation(self):
        for policy in ("+all", "-all", "~all", "?all"):
            self.assertTrue(validate_record_syntax(f"v=spf1 {policy}", "SPF"))

    def test_multiple_all_is_invalid(self):
        self.assertFalse(validate_spf("v=spf1 +all -all"))

    def test_all_must_be_last_mechanism(self):
        self.assertFalse(validate_spf("v=spf1 -all include:mail.example.com"))

    def test_unknown_modifier_is_ignored(self):
        self.assertTrue(validate_spf("v=spf1 include:_spf.google.com custom=value -all"))

    def test_ptr_does_not_accept_cidr(self):
        self.assertFalse(validate_spf("v=spf1 ptr/24 -all"))

    def test_all_must_be_last_mechanism(self):
        self.assertFalse(validate_spf("v=spf1 -all include:mail.example.com"))

    def test_unknown_modifier_is_ignored(self):
        self.assertTrue(validate_spf("v=spf1 include:_spf.google.com custom=value -all"))

    def test_ptr_does_not_accept_cidr(self):
        self.assertFalse(validate_spf("v=spf1 ptr/24 -all"))

    def test_txt_chunks_joined(self):
        class Rdata:
            strings = (b"v=spf1 include:mail.", b"example.com -all")
        from modules.spf import _txt_value
        self.assertEqual(_txt_value(Rdata()), "v=spf1 include:mail.example.com -all")

    def test_recursive_count_cycle_guard(self):
        spf = SPF.__new__(SPF)
        spf.domain = "root.example"
        spf.dns_server = "1.1.1.1"
        spf.spf_record = "v=spf1 include:a.example -all"
        with patch("modules.spf.get_resolver") as get_resolver:
            resolver = get_resolver.return_value
            class Answer:
                strings = (b"v=spf1 include:root.example include:b.example",)
            def resolve(target, kind):
                if target == "a.example":
                    return [Answer()]
                return []
            resolver.resolve.side_effect = resolve
            self.assertEqual(spf.get_spf_dns_queries(), 3)

    def test_analysis_handles_no_spf_terms(self):
        with patch("modules.spf_intelligence.domain_registration", return_value={"status":"unknown", "registrar":None, "created":None, "expires":None}), \
             patch("modules.spf_intelligence.ip_registration", return_value={"status":"unknown", "owner":None, "handle":None, "prefix":None, "country":None}):
            report = analyze_spf("example.com", "v=spf1 ip4:192.0.2.1 -all")
        self.assertTrue(report["record_valid"])
        self.assertEqual(report["dns_lookup_count"], 0)
        self.assertEqual(report["ips"][0]["ip"], "192.0.2.1")


if __name__ == "__main__":
    unittest.main()
