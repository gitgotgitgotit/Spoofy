import base64
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from modules.dkim_analysis import analyze_dkim_key, analyze_dkim_keys


def rsa_record(bits=2048, extra=""):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return f"v=DKIM1; k=rsa; p={base64.b64encode(der).decode()}; {extra}"


class DKIMStrengthTests(unittest.TestCase):
    def test_2048_bit_rsa_is_good(self):
        result = analyze_dkim_key("s1", rsa_record(2048))
        self.assertEqual(result["status"], "good")
        self.assertEqual(result["key_bits"], 2048)

    def test_1024_bit_rsa_is_weak(self):
        result = analyze_dkim_key("s1", rsa_record(1024))
        self.assertEqual(result["status"], "weak")
        self.assertEqual(result["key_bits"], 1024)

    def test_3072_bit_rsa_is_strong(self):
        result = analyze_dkim_key("s1", rsa_record(3072))
        self.assertEqual(result["status"], "strong")

    def test_ed25519_is_recognized(self):
        public_key = ed25519.Ed25519PrivateKey.generate().public_key()
        raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        record = f"v=DKIM1; k=ed25519; p={base64.b64encode(raw).decode()}"
        result = analyze_dkim_key("s1", record)
        self.assertEqual(result["status"], "strong")
        self.assertEqual(result["key_bits"], 256)

    def test_empty_key_is_revoked(self):
        result = analyze_dkim_key("s1", "v=DKIM1; k=rsa; p=")
        self.assertEqual(result["status"], "revoked")
        self.assertTrue(result["revoked"])

    def test_invalid_base64_is_invalid(self):
        result = analyze_dkim_key("s1", "v=DKIM1; k=rsa; p=not*base64")
        self.assertEqual(result["status"], "invalid")

    def test_sha1_permission_is_flagged(self):
        result = analyze_dkim_key("s1", rsa_record(extra="h=sha1:sha256"))
        self.assertTrue(any("SHA-1" in issue for issue in result["issues"]))

    def test_unsupported_key_type_is_reported(self):
        result = analyze_dkim_key("s1", "v=DKIM1; k=dsa; p=YWJj")
        self.assertEqual(result["status"], "unsupported")

    def test_duplicate_tags_are_invalid(self):
        result = analyze_dkim_key("s1", "v=DKIM1; k=rsa; p=; p=YWJj")
        self.assertEqual(result["status"], "invalid")


    def test_version_tag_must_be_first(self):
        result = analyze_dkim_key("s1", "k=rsa; v=DKIM1; p=YWJj")
        self.assertEqual(result["status"], "invalid")
        self.assertTrue(any("first tag" in issue for issue in result["issues"]))

    def test_mapping_analysis_is_sorted(self):
        results = analyze_dkim_keys({"z": "v=DKIM1; k=rsa; p=", "a": "v=DKIM1; k=rsa; p="})
        self.assertEqual([item["selector"] for item in results], ["a", "z"])




# ---------------------------------------------------------------------------
# Weak-key / flag / source tests. cryptography refuses to *generate* RSA keys
# under 1024 bits, so these build public keys directly from a random modulus of
# the exact bit length (no primes needed to analyse a public key).
# ---------------------------------------------------------------------------
import os

from modules import dkim_analysis as da


def fake_rsa_record(bits, extra="", exponent=65537):
    modulus = int.from_bytes(os.urandom(bits // 8), "big") | (1 << (bits - 1)) | 1
    der = rsa.RSAPublicNumbers(exponent, modulus).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return f"v=DKIM1; k=rsa; p={base64.b64encode(der).decode()}; {extra}"


class WeakKeyAlertTests(unittest.TestCase):
    def test_512_bit_key_is_critical_with_specific_alert(self):
        r = analyze_dkim_key("s", fake_rsa_record(512))
        self.assertEqual((r["status"], r["overall"], r["key_bits"]), ("critical", "critical", 512))
        self.assertIn("WEAK_KEY_512", r["alerts"])

    def test_768_bit_key_is_critical_with_specific_alert(self):
        r = analyze_dkim_key("s", fake_rsa_record(768))
        self.assertEqual((r["status"], r["overall"]), ("critical", "critical"))
        self.assertIn("WEAK_KEY_768", r["alerts"])
        self.assertNotIn("WEAK_KEY_512", r["alerts"])

    def test_smaller_than_512_is_still_critical(self):
        r = analyze_dkim_key("s", fake_rsa_record(384))
        self.assertEqual(r["overall"], "critical")
        self.assertIn("WEAK_KEY_512", r["alerts"])

    def test_1024_is_warning_not_critical(self):
        r = analyze_dkim_key("s", fake_rsa_record(1024))
        self.assertEqual((r["status"], r["overall"]), ("weak", "warning"))
        self.assertIn("KEY_1024", r["alerts"])

    def test_fallback_der_parser_sizes_keys_openssl_rejects(self):
        modulus = (1 << 399) | 12345 | 1
        der = rsa.RSAPublicNumbers(65537, modulus).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(da._rsa_numbers_from_der(der), (modulus, 65537))
        pkcs1 = rsa.RSAPublicNumbers(65537, modulus).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
        self.assertEqual(da._rsa_numbers_from_der(pkcs1), (modulus, 65537))

    def test_fallback_is_used_when_openssl_refuses_to_load(self):
        from unittest import mock
        with mock.patch.object(da.serialization, "load_der_public_key", side_effect=ValueError("too small")):
            r = analyze_dkim_key("s", fake_rsa_record(512))
        self.assertEqual((r["overall"], r["key_bits"]), ("critical", 512))
        with mock.patch.object(da.serialization, "load_der_public_key", side_effect=ValueError("broken")):
            r = analyze_dkim_key("s", fake_rsa_record(2048))
        self.assertEqual(r["status"], "invalid")  # a normal-sized key OpenSSL rejects is NOT called weak


class FlagAndHashTests(unittest.TestCase):
    def test_testing_mode_downgrades_good_key_to_warning(self):
        r = analyze_dkim_key("s", fake_rsa_record(2048, "t=y"))
        self.assertEqual((r["status"], r["overall"]), ("good", "warning"))
        self.assertIn("TESTING_MODE", r["alerts"])

    def test_sha1_downgrades_good_key_to_warning(self):
        r = analyze_dkim_key("s", fake_rsa_record(2048, "h=sha1:sha256"))
        self.assertEqual(r["overall"], "warning")
        self.assertIn("SHA1_ALLOWED", r["alerts"])

    def test_sha256_only_is_clean(self):
        r = analyze_dkim_key("s", fake_rsa_record(2048, "h=sha256"))
        self.assertEqual(r["overall"], "good")
        self.assertNotIn("SHA1_ALLOWED", r["alerts"])
        self.assertNotIn("NO_HASH_RESTRICTION", r["alerts"])

    def test_missing_h_is_a_note_not_a_warning(self):
        r = analyze_dkim_key("s", fake_rsa_record(2048))
        self.assertEqual(r["overall"], "good")
        self.assertIn("NO_HASH_RESTRICTION", r["alerts"])

    def test_weak_key_with_testing_mode_reports_both(self):
        r = analyze_dkim_key("s", fake_rsa_record(512, "t=y"))
        self.assertEqual(r["overall"], "critical")
        self.assertTrue({"WEAK_KEY_512", "TESTING_MODE"} <= set(r["alerts"]))

    def test_small_exponent_is_flagged(self):
        r = analyze_dkim_key("s", fake_rsa_record(2048, exponent=3))
        self.assertIn("SMALL_EXPONENT", r["alerts"])
        self.assertEqual(r["overall"], "warning")

    def test_tag_names_and_version_are_case_sensitive(self):
        upper = fake_rsa_record(2048).replace("p=", "P=")
        self.assertEqual(analyze_dkim_key("s", upper)["status"], "invalid")
        self.assertEqual(analyze_dkim_key("s", fake_rsa_record(2048).replace("DKIM1", "dkim1"))["status"], "invalid")

    def test_revoked_key_ignores_flags(self):
        r = analyze_dkim_key("s", "v=DKIM1; k=rsa; t=y; p=")
        self.assertEqual((r["status"], r["overall"]), ("revoked", "info"))


class SourceTests(unittest.TestCase):
    def test_archive_keys_are_not_live_findings(self):
        r = analyze_dkim_key("old", fake_rsa_record(512), source="archive-historical")
        self.assertFalse(r["live"])
        self.assertEqual(da.severity_rank(r), 0)
        self.assertEqual(da.forgeable_keys([r]), [])
        self.assertIn("historical", r["notes"][0].lower())

    def test_live_weak_key_is_forgeable_and_sorted_first(self):
        keys = analyze_dkim_keys({"a": fake_rsa_record(2048), "z": fake_rsa_record(512)})
        self.assertEqual([k["selector"] for k in da.forgeable_keys(keys)], ["z"])
        self.assertEqual(da.sort_by_severity(keys)[0]["selector"], "z")
        self.assertEqual(da.worst_live_rank(keys), 2)


if __name__ == "__main__":
    unittest.main()
