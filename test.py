import unittest
from modules.spoofing import Spoofing


class TestSpoofy(unittest.TestCase):
    def test_case_0(self):
        spoofing = Spoofing(
            domain="test_case_0.com",
            dmarc_record="No DMARC",
            p=None,
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp=None,
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 0)

    def test_case_1(self):
        spoofing = Spoofing(
            domain="test_case_1.com",
            dmarc_record="p=none, sp=none, aspf=r",
            p="none",
            aspf="r",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="none",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 1)

    def test_case_2(self):
        spoofing = Spoofing(
            domain="test_case_2.com",
            dmarc_record="p=none, sp=quarantine, aspf=r",
            p="none",
            aspf="r",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="quarantine",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 2)

    def test_case_3(self):
        spoofing = Spoofing(
            domain="test_case_3.com",
            dmarc_record="p=none",
            p="none",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp=None,
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 4)

    def test_case_4(self):
        spoofing = Spoofing(
            domain="test_case_4.com",
            dmarc_record="p=none",
            p="none",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp=None,
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 4)

    def test_case_5(self):
        spoofing = Spoofing(
            domain="test_case_5.com",
            dmarc_record="p=none, sp=quarantine",
            p="none",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="quarantine",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 5)

    def test_case_7(self):
        spoofing = Spoofing(
            domain="test_case_7.com",
            dmarc_record="p=none, sp=none, aspf=r",
            p="none",
            aspf="r",
            spf_record="v=spf1 ~all",
            spf_all="~all",
            spf_dns_queries=0,
            sp="none",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 7)

    def test_case_8(self):
        spoofing = Spoofing(
            domain="test_case_8.com",
            dmarc_record="p=none, sp=reject, aspf=s",
            p="none",
            aspf="s",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="reject",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_9(self):
        spoofing = Spoofing(
            domain="test_case_9.com",
            dmarc_record="p=none",
            p="none",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp=None,
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 4)

    def test_case_10(self):
        spoofing = Spoofing(
            domain="test_case_10.com",
            dmarc_record="p=none, aspf=r",
            p="none",
            aspf="r",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp=None,
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 4)

    def test_case_11(self):
        spoofing = Spoofing(
            domain="test_case_11.com",
            dmarc_record="p=none, aspf=s",
            p="none",
            aspf="s",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp=None,
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 4)

    def test_case_12(self):
        spoofing = Spoofing(
            domain="test_case_12.com",
            dmarc_record="p=none, sp=quarantine",
            p="none",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="quarantine",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 5)

    def test_case_13(self):
        spoofing = Spoofing(
            domain="test_case_13.com",
            dmarc_record="p=none, sp=reject",
            p="none",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="reject",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 5)

    def test_case_14(self):
        spoofing = Spoofing(
            domain="test_case_14.com",
            dmarc_record="p=none, sp=none",
            p="none",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="none",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 7)

    def test_case_15(self):
        spoofing = Spoofing(
            domain="test_case_15.com",
            dmarc_record="p=quarantine",
            p="quarantine",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp=None,
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_16(self):
        spoofing = Spoofing(
            domain="test_case_16.com",
            dmarc_record="p=reject",
            p="reject",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp=None,
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_17(self):
        spoofing = Spoofing(
            domain="test_case_17.com",
            dmarc_record="p=quarantine, sp=quarantine",
            p="quarantine",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="quarantine",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_18(self):
        spoofing = Spoofing(
            domain="test_case_18.com",
            dmarc_record="p=quarantine, sp=reject",
            p="quarantine",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="reject",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_19(self):
        spoofing = Spoofing(
            domain="test_case_19.com",
            dmarc_record="p=reject, sp=quarantine",
            p="reject",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="quarantine",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_20(self):
        spoofing = Spoofing(
            domain="test_case_20.com",
            dmarc_record="p=reject, sp=reject",
            p="reject",
            aspf=None,
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="reject",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_21(self):
        spoofing = Spoofing(
            domain="test_case_21.com",
            dmarc_record="p=none, sp=quarantine, aspf=s",
            p="none",
            aspf="s",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="quarantine",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_22(self):
        spoofing = Spoofing(
            domain="test_case_22.com",
            dmarc_record="p=none, sp=reject, aspf=s",
            p="none",
            aspf="s",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="reject",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_23(self):
        spoofing = Spoofing(
            domain="test_case_23.com",
            dmarc_record="p=quarantine, sp=none, aspf=s",
            p="quarantine",
            aspf="s",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="none",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_24(self):
        spoofing = Spoofing(
            domain="test_case_24.com",
            dmarc_record="p=quarantine, sp=quarantine, aspf=r",
            p="quarantine",
            aspf="r",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="quarantine",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_25(self):
        spoofing = Spoofing(
            domain="test_case_25.com",
            dmarc_record="p=reject, sp=reject, aspf=s",
            p="reject",
            aspf="s",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="reject",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_26(self):
        spoofing = Spoofing(
            domain="test_case_26.com",
            dmarc_record="p=reject, sp=none, aspf=s",
            p="reject",
            aspf="s",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="none",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_27(self):
        spoofing = Spoofing(
            domain="test_case_27.com",
            dmarc_record="p=reject, sp=quarantine, aspf=r",
            p="reject",
            aspf="r",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="quarantine",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_28(self):
        spoofing = Spoofing(
            domain="test_case_28.com",
            dmarc_record="p=reject, sp=quarantine, aspf=s",
            p="reject",
            aspf="s",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="quarantine",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_29(self):
        spoofing = Spoofing(
            domain="test_case_29.com",
            dmarc_record="p=reject, sp=reject, aspf=r",
            p="reject",
            aspf="r",
            spf_record="v=spf1 -all",
            spf_all="-all",
            spf_dns_queries=0,
            sp="reject",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 8)

    def test_case_30(self):
        spoofing = Spoofing(
            domain="test_case_30.com",
            dmarc_record="p=none, sp=none, aspf=r",
            p="none",
            aspf="r",
            spf_record="v=spf1 ?all",
            spf_all="?all",
            spf_dns_queries=0,
            sp="none",
            pct=100,
        )
        self.assertEqual(spoofing.spoofable, 0)


# --- Master_Table.xlsx regression suite -------------------------------------
#
# files/Master_Table.xlsx is the reference truth table the scoring logic in
# modules/spoofing.py is meant to implement: every (SPF mechanism, DMARC
# state) combination it lists, mapped to the correct spoofability code.
#
# The hand-written cases above only cover a slice of that table (mostly the
# "-all" mechanism). A 2026-08 audit found the implementation silently
# disagreed with 43 of the table's 198 rows (~22%) - including entire
# branches like "no SPF record" and "SPF has no 'all' mechanism" - with none
# of it caught by the existing tests. This suite runs every row so a future
# change to modules/spoofing.py can't regress without a test failing.

import os
import openpyxl

MASTER_TABLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files", "Master_Table.xlsx")

# The table itself is keyed by human-readable spreadsheet labels for the SPF
# "all" mechanism; map those to the spf_all values Spoofing actually receives
# at runtime (see modules/spf.py's get_spf_all_string()).
SPF_ALL_LABEL_MAP = {
    "-all": "-all",
    "all-": "-all",  # legacy duplicate label for the same hard-fail mechanism
    "all?": "?all",
    "all+": "+all",
    "all~": "~all",
    "No All": None,  # SPF record exists but has no "all" mechanism
    "No SPF": None,  # handled via spf_record=None instead of spf_all
}


def _parse_master_table_dmarc_cell(cell):
    """Parses a Master_Table.xlsx DMARC column value like
    'p=none, sp=quarantine, aspf=r' into (dmarc_record, p, sp, aspf, pct)."""
    if cell == "No DMARC":
        return None, None, None, None, None

    tags = {}
    for part in cell.split(","):
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip()] = value.strip()

    p = tags.get("p")
    sp = tags.get("sp")
    aspf = tags.get("aspf")
    pct = tags.get("pct")
    # Spoofing only checks dmarc_record for truthiness in the paths this
    # table exercises, so a minimal reconstructed record is sufficient.
    dmarc_record = "v=DMARC1; p=" + (p or "none")
    return dmarc_record, p, sp, aspf, pct


def _load_master_table_rows():
    """Loads (spf_label, dmarc_label, expected_code) rows from Master_Table.xlsx."""
    if not os.path.exists(MASTER_TABLE_PATH):
        return []
    workbook = openpyxl.load_workbook(MASTER_TABLE_PATH, data_only=True)
    sheet = workbook["Sheet1"]
    rows = []
    for spf_label, dmarc_label, expected in sheet.iter_rows(min_row=2, max_col=3, values_only=True):
        if spf_label is None:
            continue
        rows.append((spf_label, dmarc_label, expected))
    return rows


class TestSpoofingAgainstMasterTable(unittest.TestCase):
    """Every row of files/Master_Table.xlsx must produce the spoofability
    code the table specifies."""

    @classmethod
    def setUpClass(cls):
        cls.rows = _load_master_table_rows()
        if not cls.rows:
            raise unittest.SkipTest(f"Master_Table.xlsx not found at {MASTER_TABLE_PATH}")

    def test_all_master_table_rows(self):
        for spf_label, dmarc_label, expected in self.rows:
            spf_all = SPF_ALL_LABEL_MAP[spf_label]
            spf_record = None if spf_label == "No SPF" else "v=spf1 include:_spf.example.com " + spf_label
            dmarc_record, p, sp, aspf, pct = _parse_master_table_dmarc_cell(dmarc_label)

            with self.subTest(spf=spf_label, dmarc=dmarc_label):
                spoofing = Spoofing(
                    domain="master-table-test.com",
                    dmarc_record=dmarc_record,
                    p=p,
                    aspf=aspf,
                    spf_record=spf_record,
                    spf_all=spf_all,
                    spf_dns_queries=1,
                    sp=sp,
                    pct=pct,
                )
                self.assertEqual(
                    spoofing.spoofable,
                    expected,
                    f"SPF={spf_label!r} DMARC={dmarc_label!r}: expected {expected}, got {spoofing.spoofable}",
                )


if __name__ == "__main__":
    unittest.main()
