# modules/spoofing.py

import tldextract
from .syntax import validate_record_syntax


class Spoofing:
    def __init__(
        self,
        domain,
        dmarc_record,
        p,
        aspf,
        spf_record,
        spf_all,
        spf_dns_queries,
        sp,
        pct,
    ):
        self.domain = domain
        self.dmarc_record = dmarc_record
        self.p = p
        self.aspf = aspf
        self.spf_record = spf_record
        self.spf_all = spf_all
        self.spf_dns_queries = spf_dns_queries
        self.sp = sp
        self.pct = pct
        self.domain_type = self.get_domain_type()
        self.spoofable = self.is_spoofable()
        self.spoofing_possible, self.spoofing_type = self.evaluate_spoofing()

    def get_domain_type(self):
        """Determines whether the domain is a domain or subdomain."""
        subdomain = bool(tldextract.extract(self.domain).subdomain)
        return "subdomain" if subdomain else "domain"

    def is_spoofable(self):
        """Determines the spoofability based on DMARC and SPF data."""
        try:
            if self.pct and int(self.pct) != 100:
                return 3
            if self.spf_record is None:
                return self.evaluate_no_spf_record()
            if self.spf_dns_queries > 10 and self.p is None:
                return 0
            if self.spf_all == "2many":
                return 3 if self.p == "none" else 8
            if self.spf_all == "+all":
                # SPF authorizes any sender, so it gives no signal either way;
                # outcome depends on receiver-specific handling regardless of DMARC.
                return 4
            if self.spf_all and self.p is None:
                return 0
            if self.spf_all == "-all":
                if self.p == "none":
                    if self.sp == "none":
                        if self.aspf in ["r", "s"]:
                            return 1
                        return 7
                    if self.sp in ["quarantine", "reject"]:
                        if self.aspf == "r":
                            return 2
                        if self.aspf == "s":
                            return 8
                        return 5
                    return 4
                if self.p in ["quarantine", "reject"]:
                    if self.sp == "none":
                        # Subdomain policy is explicitly open regardless of the
                        # org's alignment mode - subdomains stay spoofable
                        # unless aspf=s specifically tightens that up.
                        if self.aspf == "s":
                            return 8
                        return 1
                    return 8
            if self.spf_all in ("?all", None):
                return self.evaluate_weak_or_missing_all()
            if self.spf_all == "~all":
                if self.p == "none":
                    if self.sp == "none":
                        return 7 if self.aspf in ["r", "s"] else 0
                    if self.sp in ["quarantine", "reject"]:
                        return 2
                    return 2 if self.aspf in ["r", "s"] else 0

                if self.p in ["quarantine", "reject"]:
                    if self.sp == "none":
                        return 8 if self.aspf in ["r", "s"] else 1
                    return 8
            if not self.spf_record:
                if not self.dmarc_record:
                    return 0
                if self.p == "none" and self.sp == "none" and self.aspf in ["r", "s"]:
                    return 2
                return 4 if self.p == "none" else 8
            return 8
        except Exception:
            spf_valid = validate_record_syntax(self.spf_record, "SPF")
            dmarc_valid = validate_record_syntax(self.dmarc_record, "DMARC")
            if (not spf_valid and not dmarc_valid) or (spf_valid and not dmarc_valid):
                return 0
            return 3 if not spf_valid and dmarc_valid and self.p == "none" else 8

    def evaluate_no_spf_record(self):
        """Spoofability when the domain has no SPF record at all.

        With no SPF, DKIM+DMARC alignment is the only thing that could stop a
        spoofed message, so almost every state defaults to "not possible to
        assess as spoofable via SPF" (8) except a small set of clearly weak
        configurations.
        """
        if self.p is None:
            return 0
        if self.p == "none":
            if self.sp == "none" and self.aspf in ("r", "s"):
                return 2
            if self.sp is None and self.aspf is None:
                return 4
            return 8
        return 8

    def evaluate_weak_or_missing_all(self):
        """Spoofability when SPF ends in '?all' (neutral) or has no 'all'
        mechanism at all. Both leave SPF unable to assert anything, so they
        share identical scoring.
        """
        if not self.dmarc_record:
            return 0
        if self.p == "none":
            if self.sp in ("none", None) and self.aspf == "r":
                return 0
            if self.sp in ("quarantine", "reject"):
                return 5
            return 4
        if self.p in ("quarantine", "reject"):
            if self.sp == "none":
                return 1 if self.aspf in ("r", "s") else 6
            if self.sp in ("quarantine", "reject"):
                return 8
            return 8
        return 8

    def evaluate_spoofing(self):
        """Evaluates and returns whether spoofing is possible and the type of spoofing."""
        spoofing_types = {
            0: f"Spoofing possible for {self.domain}.",
            1: f"Subdomain spoofing possible for {self.domain}.",
            2: f"Organizational domain spoofing possible for {self.domain}.",
            3: f"Spoofing might be possible for {self.domain}.",
            4: f"Spoofing might be possible (Mailbox dependent) for {self.domain}.",
            5: f"Organizational domain spoofing might be possible (Mailbox dependent) for {self.domain}.",
            6: f"Subdomain spoofing might be possible (Mailbox dependent) for {self.domain}.",
            7: f"Subdomain spoofing is possible and organizational domain spoofing might be possible for {self.domain}.",
            8: f"Spoofing is not possible for {self.domain}.",
        }

        spoofing_type = spoofing_types.get(
            self.spoofable, f"Unknown spoofing type for {self.domain}."
        )

        if self.spoofable in {0, 1, 3, 7}:
            spoofing_possible = True
        elif self.spoofable == 8:
            spoofing_possible = False
        else:
            spoofing_possible = None  # "maybe"

        return spoofing_possible, spoofing_type

    def __str__(self):
        return (
            f"Domain: {self.domain}\n"
            f"Domain Type: {self.domain_type}\n"
            f"Spoofing Possible: {self.spoofing_possible}\n"
            f"Spoofing Type: {self.spoofing_type}"
        )


def apply_dkim_risk(domain, spoofing_possible, spoofing_type, dkim_analysis):
    """Fold weak *live* DKIM keys into the spoofing verdict.

    Spoofing's SPF/DMARC table does not model DKIM. A factorable live RSA key
    (<1024 bits) lets an attacker forge DKIM signatures aligned with the domain,
    which satisfies DMARC even under p=reject, so a "not spoofable" verdict
    would be wrong. Archive-only (historical) keys are ignored.

    Returns (spoofing_possible, spoofing_type, note). note is None when no
    weak live key exists. A False verdict becomes None ("maybe"); True/None
    verdicts keep their value and only gain the note.
    """
    from .dkim_analysis import forgeable_keys

    weak = forgeable_keys(dkim_analysis)
    if not weak:
        return spoofing_possible, spoofing_type, None
    worst = min(weak, key=lambda item: item.get("key_bits") or 0)
    note = (f"Live DKIM selector '{worst['selector']}' uses a {worst['key_bits']}-bit RSA key that can be factored; "
            "DKIM signatures aligned with this domain may be forgeable, bypassing DMARC.")
    if spoofing_possible is False:
        return None, f"Spoofing might be possible for {domain} via DKIM key forgery. {note}", note
    return spoofing_possible, spoofing_type, note
