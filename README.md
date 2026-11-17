<h1 align="center">
<br>
<img src=/files/Spoofy_logo.png height="375" border="2px solid #555">
<br>
Spoofy
</h1>

[![forthebadge](https://forthebadge.com/images/badges/made-with-python.svg)](https://www.python.org/)
[![forthebadge](https://forthebadge.com/images/badges/contains-tasty-spaghetti-code.svg)](https://www.thewholesomedish.com/spaghetti/)
[![forthebadge](https://forthebadge.com/images/badges/it-works-why.svg)](https://www.youtube.com/watch?v=kyti25ol438)

## WHAT

`Spoofy` is a program that checks if a list of domains can be spoofed based on SPF and DMARC records. You may be asking, "Why do we need another tool that can check if a domain can be spoofed?"

Well, Spoofy is different and here is why:

> 1. Authoritative lookups on all lookups with known fallback (Cloudflare DNS)
> 2. Accurate bulk lookups
> 3. Custom, manually tested spoof logic (No guessing or speculating, real world test results)
> 4. SPF DNS query counter
> 5. Optional DKIM selector enumeration via API

## PASSING TESTS

[![Spoofy CI](https://github.com/MattKeeley/Spoofy/actions/workflows/ci.yml/badge.svg)](https://github.com/MattKeeley/Spoofy/actions/workflows/ci.yml)

## SECURITY SCORE

Every scan ends with a 0-100 configuration-strength score and a grade (A >= 90, B >= 80, C >= 70, D >= 60, else F).
It is a **heuristic**, not an industry standard.

| Area | Weight | What is checked (DNS only) |
| ---- | ------ | -------------------------- |
| DMARC | 20 | record present, single record, valid `p=`, `rua=` |
| SPF | 15 | present, single record, `all` qualifier, 10-lookup limit |
| DKIM | 15 | key strength/flags of live selectors (needs `--dkim`) |
| DMARC alignment | 12 | `aspf`/`adkim`, policy strength, `pct`, `sp`, whether any aligned mechanism exists |
| DNSSEC | 10 | DS/DNSKEY, chain (resolver AD flag), bogus chain, signature expiry, algorithms |
| MX | 8 | resolution, dangling hosts, CNAMEs, non-public addresses, null MX |
| CAA | 5 | issuance restriction, inherited policy, iodef |
| TLS-RPT | 4 | record syntax and reporting destinations |
| IPv6 | 3 | MX AAAA, SPF `ip6` coverage, reverse DNS |
| Takeover risk | 10 | SPF includes, nameserver hosts and DKIM selector CNAMEs on unregistered domains; dangling DKIM CNAMEs |
| SPF hardening | 6 | void lookups (>2), `ptr`, huge `ip4`/`ip6` ranges, includes with no SPF record, oversized record |
| Non-sending hygiene | 6 | only for null-MX / no-mail domains: SPF `-all`, DMARC `p=reject`, revoked wildcard DKIM |
| Nameservers | 5 | at least two, resolvable, different networks, authoritative (lame check), matching SOA serials |
| DMARC reporting | 3 | external `rua`/`ruf` authorisation (`_report._dmarc`), address syntax, `ruf` privacy, length |
| BIMI | 2 | only when deployed (enforced DMARC, HTTPS logo, `a=` present) |

Each area starts at 100 and loses 40/25/12/5 points per critical/high/medium/low finding. The overall score is the
weighted mean of the areas that apply; areas that do not apply (DKIM not scanned, BIMI/TLS-RPT not deployed, no IPv6,
`--basic`) are listed as "not scored" instead of being penalised. Caps: a spoofable verdict caps the score at 59, a
possible one at 79, and any critical finding at 69.

DKIM also gets two rotation hints from DNS alone: the same public key under several selectors, and date-named selectors
(`s202301`) whose newest date is old. Both are heuristics; DNS cannot reveal a key's real age.

Limits: "unregistered" means the registered domain returns NXDOMAIN for NS at scan time. DNSSEC trusts the recursive resolver's AD flag (it does not re-validate the chain itself); BIMI certificates,
MTA-STS policy files and DANE/TLSA are not assessed yet (they need HTTPS/SMTP, not just DNS); DKIM key age cannot be
learned from DNS.

## HOW TO USE

`Spoofy` requires **Python 3+**. Python 2 is not supported. Usage is shown below:

```console
Usage:
    ./spoofy.py -d [DOMAIN] -o [stdout, xls, csv, or json] -t [NUMBER_OF_THREADS] [--dkim]
    OR
    ./spoofy.py -iL [DOMAIN_LIST] -o [stdout, xls, csv, or json] -t [NUMBER_OF_THREADS] [--dkim]

Options:
    -d      : Process a single domain.
    -iL     : Provide a file containing a list of domains to process.
    -o      : Specify the output format: stdout (default), xls (.xlsx), csv, or json.
    --out   : Output file for xls/csv/json (default output.xlsx / output.csv; json prints to stdout).
    -t      : Set the number of threads to use (default: 4).
    --dkim  : Enumerate DKIM selectors and analyze public-key strength (RSA bits, Ed25519, revoked/malformed keys).
              Alerts: WEAK_KEY_512 / WEAK_KEY_768 (critical), KEY_1024 (warning), SHA1_ALLOWED (h= permits sha1),
              TESTING_MODE (t=y), SMALL_EXPONENT. A key with t=y or SHA-1 is shown as WARNING, never plain GOOD.
    --dkim-api           : Also query archive.prove.email for historical selectors (off by default: it receives the target domain). Implies --dkim.
    --dkim-selector SEL  : Extra selector to check (repeatable / comma-separated). Implies --dkim.
    --dkim-header FILE   : Raw e-mail/header dump; selectors are read from its DKIM-Signature (d=, s=) and
                           a=rsa-sha1 is flagged. Implies --dkim. Far more reliable than guessing selectors.
    --fail-on weak|critical : Exit status 2 if a live DKIM key is that bad (weak = warning or worse;
                           critical = RSA < 1024 bits). For CI/cron use.
    --basic : Skip the extra DNS checks (DNSSEC, MX, CAA, TLS-RPT, IPv6) to cut DNS traffic; score covers SPF/DMARC/alignment/DKIM/BIMI only.
    --min-score N : Exit with status 2 if any domain scores below N (0-100).
    --verbose-spf : Inspect SPF dependencies, domain registration (RDAP), IP allocation and BGP origin data.

Examples:
    ./spoofy.py -d example.com -t 10
    ./spoofy.py -d example.com --dkim
    ./spoofy.py -d example.com --dkim --dkim-wordlist custom-selectors.txt
    ./spoofy.py -d example.com --dkim --dkim-header message.eml --fail-on critical
    ./spoofy.py -iL domains.txt -o xls
    ./spoofy.py -iL domains.txt -o csv --out results.csv --dkim
    ./spoofy.py -iL domains.txt -o json --dkim
    ./spoofy.py -d example.com --verbose-spf
    ./spoofy.py -iL domains.txt -o json --verbose-spf

Install Dependencies:
    pip3 install -r requirements.txt
```


## SPF INTELLIGENCE

Use `--verbose-spf` to inspect the domains and IP addresses referenced by an SPF
record. Spoofy validates SPF mechanisms and IP/CIDR syntax, follows `include:`
and `redirect=` dependencies with recursion protection, reports the DNS lookup
budget, identifies known email providers, and optionally enriches domain/IP data
using RDAP and RIPEstat. RDAP/BGP lookups require Internet access and may be
rate-limited; unavailable data is reported as `unknown`, not treated as proof
that a domain or IP is unregistered or inactive.

Example:

```console
./spoofy.py -d example.com --verbose-spf
```

## HOW DO YOU KNOW ITS SPOOFABLE

(The spoofability table lists every combination of SPF and DMARC configurations that impact deliverability to the inbox, except for DKIM modifiers. With `--dkim`, one DKIM case is layered on top: a *live* RSA key under 1024 bits can be factored and DKIM forged, so a "not spoofable" verdict is downgraded to "might be possible". Archive-only (historical) keys never change the verdict.)
[Download Here](/files/Master_Table.xlsx)

## METHODOLOGY

The creation of the spoofability table involved listing every relevant SPF and DMARC configuration, combining them, and then conducting SPF and DMARC information collection using an early version of Spoofy on a large number of US government domains. Testing if an SPF and DMARC combination was spoofable or not was done using the email security pentesting suite at [emailspooftest](https://emailspooftest.com/) using Microsoft 365. However, the initial testing was conducted using Protonmail and Gmail, but these services were found to utilize reverse lookup checks that affected the results, particularly for subdomain spoof testing. As a result, Microsoft 365 was used for the testing, as it offered greater control over the handling of mail.

After the initial testing using Microsoft 365, some combinations were retested using Protonmail and Gmail due to the differences in their handling of banners in emails. Protonmail and Gmail can place spoofed mail in the inbox with a banner or in spam without a banner, leading to some SPF and DMARC combinations being reported as "Mailbox Dependent" when using Spoofy. In contrast, Microsoft 365 places both conditions in spam. The testing and data collection process took several days to complete, after which a good master table was compiled and used as the basis for the Spoofy spoofability logic.

## DISCLAIMER

> This tool is only for testing and academic purposes and can only be used where
> strict consent has been given. Do not use it for illegal purposes! It is the
> end user’s responsibility to obey all applicable local, state and federal laws.
> Developers assume no liability and are not responsible for any misuse or damage
> caused by this tool and software.

## LICENSE

This project is licensed under the Creative Commons Zero v1.0 Universal - see the [LICENSE](LICENSE) file for details
