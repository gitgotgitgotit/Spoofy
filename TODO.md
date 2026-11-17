# TODO

## Planned
- **Lookalike / typosquat domains** (opt-in, e.g. `--lookalikes`): generate typo, homoglyph, TLD-swap and hyphen variants of the
  target and report any that publish MX or SPF records (spoofing / phishing risk). Needs a query budget and a cap, because
  it multiplies DNS traffic by hundreds per domain.
- **Active TLS testing of MX hosts** (opt-in, e.g. `--tls-probe`): STARTTLS on port 25 for TLS versions, certificate expiry and
  hostname match. Candidate back ends: shell out to `testssl.sh --starttls smtp` / `sslyze` if installed, or a small built-in
  `smtplib` probe. Caveats: many ISPs/clouds block outbound port 25; it is active probing of third-party servers (needs
  authorisation); slow, so it needs a timeout and a concurrency cap.

## Needs HTTPS or SMTP (not DNS-only)
- MTA-STS policy fetch and validation; DANE/TLSA; BIMI SVG (Tiny PS) and VMC/CMC certificate validation.

## Needs stored history
- DKIM key age / rotation monitoring, change detection between scans (`--baseline old.json` is the cheap first step),
  scheduled re-scans, expiry alerts.

## Other ideas
- DNSBL checks (only with a resolver the user configures: Spamhaus refuses public resolvers).
- Query authoritative nameservers directly instead of a recursive resolver, to avoid stale cached answers.
- JUnit / SARIF output for CI; HTML report.
