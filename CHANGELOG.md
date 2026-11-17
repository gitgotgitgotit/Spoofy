# Changelog

## 1.4.0

New DNS-only checks, all feeding the score (skipped with `--basic`):
- **Takeover risk**: SPF include / nameserver / DKIM-CNAME targets on unregistered domains (critical); dangling DKIM CNAMEs.
- **SPF hardening**: bounded SPF walk with RFC 7208 void-lookup counting, `ptr`, oversized ranges, includes with no record, record length.
- **Nameservers**: count, resolvability, network diversity, lame delegations and SOA serial sync (queries each NS directly).
- **Non-sending hygiene**: SPF `-all`, DMARC reject and wildcard DKIM revocation for null-MX / no-mail domains.
- **DMARC reporting**: external destination authorisation, address syntax, `ruf` privacy note, record length.
- **DKIM rotation hints**: reused keys across selectors, stale date-named selectors (heuristic).
- `DKIM` scans now also probe NXDOMAIN selectors for dangling CNAMEs (one extra query per missed selector); result field `DKIM_DANGLING_CNAMES`.
- `TODO.md` added (lookalike domains, active TLS probe, etc.).

## 1.3.1

- The archive.prove.email DKIM lookup is now **off by default** (it sends the target domain to a third party). Enable it with `--dkim-api`. `--dkim-no-api` is still accepted and does nothing.

## 1.3.0

- **Configuration score (0-100, grade A-F)** on every scan: weighted per-area scores, caps for spoofable/critical states,
  "not scored" list for areas that do not apply. Heuristic; see README. `--min-score N` exits 2 below N.
- **New DNS-only checks**: DNSSEC (DS/DNSKEY, bogus chain via CD retry, signature expiry, deprecated algorithms; trusts the
  resolver AD flag), MX (dangling/CNAME/non-public/IP-literal/null MX), CAA (tree climbing, issuance restriction),
  TLS-RPT (syntax and destinations), IPv6 (AAAA on MX, SPF `ip6` coverage, forward-confirmed reverse DNS).
- **DMARC alignment** analysis (`aspf`/`adkim`, policy strength, `pct`, `sp`, aligned-mechanism availability). Adds `DMARC_ADKIM`.
- `--basic` skips the extra checks. Result adds `SCORE`, `SCORE_OVERALL`, `SCORE_GRADE`, `CHECKS`.
- Not included yet: MTA-STS policy fetch, DANE/TLSA, BIMI certificate validation (need HTTPS/SMTP), DKIM rotation (needs history), HTML report.

## 1.2.0

### DKIM
- Explicit alerts for weak RSA keys: `WEAK_KEY_512` (<=512), `WEAK_KEY_768` (513-768), `WEAK_KEY_SUB1024`; 1024 is `KEY_1024` (warning). Keys too small for the local OpenSSL are sized with a DER fallback instead of being reported "invalid".
- `t=y` (testing) and `h=` permitting SHA-1 now downgrade the result to WARNING (new `overall` field) instead of printing under a green "GOOD". Missing `h=` is noted. Small RSA exponents flagged.
- Tag names and `v=DKIM1` are case-sensitive, as in RFC 6376.
- Archive (archive.prove.email) keys are verified against live DNS and labelled `dns` / `archive-historical` / `archive-unverified`; only `dns` keys count as findings. Archive selector names are validated before being used in DNS queries.
- DNS timeouts/SERVFAIL are tracked and reported (`DKIM_LOOKUP_ERRORS`) instead of silently looking like "no key".
- Discovery filter parses tags instead of matching `"p="` (which matched SPF `exp=` / DMARC `sp=`).
- New: `--dkim-no-api`, `--dkim-selector`, `--dkim-header FILE` (also flags `a=rsa-sha1`), `--fail-on weak|critical`.
- `DKIM` result field is now a structured list (no `[*]`/`\r\n` presentation text); `DKIM_ENABLED` added.
- "No DKIM selectors" message only shows with `--dkim`, and says absence is not proof.
- A live <1024-bit RSA key downgrades a "not spoofable" verdict to "might be possible".

### Other fixes
- BIMI record is a plain string (was an rdata object that broke `-o json`); tags parsed properly.
- DMARC: checks `_dmarc.<domain>` before the organizational domain (RFC 7489 6.6.3); multiple records => no policy; multi-string TXT no longer gets a space injected; `p`/`sp`/`aspf` case-insensitive. New fields `DMARC_MULTIPLE_RECORDS`, `DMARC_RECORD_DOMAIN`.
- dns.py: removed system-resolver `socket.gethostbyname`; SOA checks fall back to the registered domain for subdomains.
- Output: input order preserved, `-iL` normalised/de-duplicated (URLs, e-mails, comments, case, trailing dots), `-o csv`, `--out`, spreadsheet cells hold JSON instead of Python reprs, JSON uses `default=str` and prints `[]` for no results.

### Deliberately NOT changed
- The SPF/DMARC verdict table (`modules/spoofing.py`), including how an absent `aspf` is treated: it was derived empirically and covered by `test.py`. Treating absent `aspf` as the RFC default `r` would change verdicts.

### Tests
- `test_dkim_analysis.py` (512/768/flags/source), `test_offline_modules.py` (new; uses `tests_stubs.py` when dnspython/tldextract are absent).
