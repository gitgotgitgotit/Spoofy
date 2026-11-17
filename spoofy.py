#! /usr/bin/env python3

# spoofy.py
import argparse
import sys
import threading
from queue import Queue
from modules.dns import DNS
from modules.assessment import assess
from modules.dkim import DKIM, load_header_signatures
from modules.dkim_analysis import FAIL_ON_RANK, worst_live_rank
from modules.inputs import load_domains, normalize_domain
from modules.spoofing import Spoofing, apply_dkim_risk
from modules.spf_intelligence import analyze_spf
from modules import report

print_lock = threading.Lock()


def process_domain(domain, enable_dkim=False, dkim_wordlist=None, verbose_spf=False, dkim_options=None, extended=True):
    """Process a domain to gather DNS, SPF, DMARC, and BIMI records. Optionally enumerate DKIM selectors if enabled."""
    dns_info = DNS(domain)
    # DNS.__init__ already resolves SPF/DMARC/BIMI while picking a working
    # nameserver (see modules/dns.py) - reuse those instead of re-querying
    # everything from scratch, which was doubling DNS traffic per domain.
    spf = dns_info.spf_record
    dmarc = dns_info.dmarc_record
    bimi_info = dns_info.bimi_record

    spf_record = spf.spf_record
    spf_all = spf.all_mechanism
    spf_dns_query_count = spf.spf_dns_query_count
    spf_too_many_dns_queries = spf.too_many_dns_queries

    dmarc_record = dmarc.dmarc_record
    dmarc_p = dmarc.policy
    dmarc_pct = dmarc.pct
    dmarc_aspf = dmarc.aspf
    dmarc_sp = dmarc.sp
    dmarc_fo = dmarc.fo
    dmarc_rua = dmarc.rua

    dkim_record = None
    dkim_analysis = None
    dkim_errors = None
    dkim_signatures = None
    dkim_dangling = None
    if enable_dkim:
        options = dkim_options or {}
        dkim = DKIM(domain, dns_info.dns_server, selectors_file=dkim_wordlist,
                    use_api=options.get("use_api", False),
                    extra_selectors=options.get("selectors"),
                    header_signatures=options.get("header_signatures"))
        dkim_record = dkim.dkim_record
        dkim_analysis = dkim.key_analysis
        dkim_errors = dkim.lookup_errors
        dkim_signatures = dkim.header_signatures
        dkim_dangling = dkim.dangling_cnames

    bimi_record = bimi_info.bimi_record
    bimi_version = bimi_info.version
    bimi_location = bimi_info.location
    bimi_authority = bimi_info.authority

    spoofing_info = Spoofing(
        domain,
        dmarc_record,
        dmarc_p,
        dmarc_aspf,
        spf_record,
        spf_all,
        spf_dns_query_count,
        dmarc_sp,
        dmarc_pct,
    )

    domain_type = spoofing_info.domain_type
    spoofing_possible = spoofing_info.spoofing_possible
    spoofing_type = spoofing_info.spoofing_type

    # A factorable live DKIM key can bypass an otherwise strict SPF/DMARC verdict.
    spoofing_possible, spoofing_type, dkim_note = apply_dkim_risk(
        domain, spoofing_possible, spoofing_type, dkim_analysis)

    spf_intelligence = analyze_spf(domain, spf_record, dns_info.dns_server) if verbose_spf and spf_record else None

    result = {
        "DOMAIN": domain,
        "DOMAIN_TYPE": domain_type,
        "DNS_SERVER": dns_info.dns_server,
        "SPF": spf_record,
        "SPF_MULTIPLE_ALLS": spf_all,
        "SPF_NUM_DNS_QUERIES": spf_dns_query_count,
        "SPF_TOO_MANY_DNS_QUERIES": spf_too_many_dns_queries,
        "SPF_INTELLIGENCE": spf_intelligence,
        "SPF_MULTIPLE_RECORDS": spf.multiple_spf_records,
        "DMARC": dmarc_record,
        "DMARC_MULTIPLE_RECORDS": dmarc.multiple_records,
        "DMARC_RECORD_DOMAIN": dmarc.record_domain,
        "DMARC_POLICY": dmarc_p,
        "DMARC_PCT": dmarc_pct,
        "DMARC_ASPF": dmarc_aspf,
        "DMARC_ADKIM": dmarc.adkim,
        "DMARC_SP": dmarc_sp,
        "DMARC_FORENSIC_REPORT": dmarc_fo,
        "DMARC_AGGREGATE_REPORT": dmarc_rua,
        "DKIM_ENABLED": enable_dkim,
        "DKIM": dkim_record,
        "DKIM_ANALYSIS": dkim_analysis,
        "DKIM_LOOKUP_ERRORS": dkim_errors,
        "DKIM_SIGNATURES": dkim_signatures,
        "DKIM_DANGLING_CNAMES": dkim_dangling,
        "BIMI_RECORD": bimi_record,
        "BIMI_VERSION": bimi_version,
        "BIMI_LOCATION": bimi_location,
        "BIMI_AUTHORITY": bimi_authority,
        "SPOOFING_POSSIBLE": spoofing_possible,
        "SPOOFING_TYPE": spoofing_type,
        "SPOOFING_DKIM_NOTE": dkim_note,
    }
    assessment = assess(result, dns_info.dns_server, extended=extended)
    result["SCORE_OVERALL"] = assessment["score"]["overall"]
    result["SCORE_GRADE"] = assessment["score"]["grade"]
    result["SCORE"] = assessment["score"]
    result["CHECKS"] = assessment["checks"]
    return result


def worker(domain_queue, print_lock, output, results, enable_dkim=False, dkim_wordlist=None,
           verbose_spf=False, dkim_options=None, extended=True):
    """Worker function to process domains and output results."""
    while True:
        item = domain_queue.get()
        if item is None:
            domain_queue.task_done()
            return
        index, domain = item
        try:
            result = process_domain(domain, enable_dkim=enable_dkim, dkim_wordlist=dkim_wordlist,
                                    verbose_spf=verbose_spf, dkim_options=dkim_options, extended=extended)
        except Exception as exc:
            result = {"DOMAIN": domain, "ERROR": f"{type(exc).__name__}: {exc}"}
        try:
            with print_lock:
                results.append((index, result))  # always kept: needed for --fail-on and ordered file output
                if output == "stdout":
                    if result.get("ERROR"):
                        report.output_message("[!]", f"{domain}: {result['ERROR']}", "error")
                    else:
                        report.printer(**result)
        except Exception as exc:
            # A formatting/output failure must not kill a worker and strand
            # queued domains behind Queue.join().
            with print_lock:
                report.output_message("[!]", f"{domain}: output error: {type(exc).__name__}: {exc}", "error")
        finally:
            domain_queue.task_done()


def build_parser():
    parser = argparse.ArgumentParser(
        description="Process domains to gather DNS, SPF, DMARC, and BIMI records. Use --dkim to enable DKIM selector enumeration."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", type=str, help="Single domain to process.")
    group.add_argument("-iL", type=str, help="File containing a list of domains (URLs/e-mails/comments tolerated).")
    parser.add_argument("-o", type=str, choices=["stdout", "xls", "csv", "json"], default="stdout",
                        help="Output format (default: stdout). xls writes an .xlsx workbook.")
    parser.add_argument("--out", type=str, default=None,
                        help="Output file for xls/csv/json (default: output.xlsx / output.csv; json prints to stdout).")
    parser.add_argument("-t", type=int, default=4, help="Number of threads to use (default: 4)")
    parser.add_argument("--dkim", action="store_true",
                        help="Enable DKIM selector enumeration (wordlist via DNS; add --dkim-api for the archive.prove.email lookup) and key-strength analysis")
    parser.add_argument("--dkim-wordlist", type=str, default=None,
                        help="Path to a custom DKIM selector wordlist, one selector per line "
                             "(default: files/dkim_selectors.txt). Only used with --dkim.")
    parser.add_argument("--dkim-api", action="store_true",
                        help="Also query archive.prove.email for historical selectors. Off by default because the target "
                             "domain is sent to that third party. Implies --dkim.")
    parser.add_argument("--dkim-no-api", action="store_true", help=argparse.SUPPRESS)  # deprecated no-op: the API is already off
    parser.add_argument("--dkim-selector", action="append", default=[], metavar="SELECTOR",
                        help="Extra selector to check (repeatable or comma-separated). Implies --dkim.")
    parser.add_argument("--dkim-header", type=str, default=None, metavar="FILE",
                        help="Raw e-mail / header dump: selectors are read from its DKIM-Signature headers "
                             "(d=, s=) and a=rsa-sha1 is flagged. Implies --dkim.")
    parser.add_argument("--fail-on", choices=sorted(FAIL_ON_RANK), default=None,
                        help="Exit with status 2 if a live DKIM key is at least this bad "
                             "(weak = warning or critical, critical = <1024-bit RSA). Needs DKIM data.")
    parser.add_argument("--basic", action="store_true",
                        help="Skip the extra DNS checks (DNSSEC, MX, CAA, TLS-RPT, IPv6) to cut DNS traffic; the score then covers "
                             "SPF/DMARC/alignment/DKIM/BIMI only.")
    parser.add_argument("--min-score", type=int, default=None, metavar="N",
                        help="Exit with status 2 if any domain's configuration score is below N (0-100).")
    parser.add_argument("--verbose-spf", action="store_true",
                        help="Analyze SPF mechanisms, DNS dependencies, domain registration and IP allocation (RDAP).")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.t < 1:
        parser.error("-t/--threads must be at least 1")
    if args.dkim_header or args.dkim_selector or args.dkim_api:
        args.dkim = True
    if args.min_score is not None and not 0 <= args.min_score <= 100:
        parser.error("--min-score must be between 0 and 100")
    if args.fail_on and not args.dkim:
        parser.error("--fail-on needs --dkim")

    extra_selectors = [sel.strip() for item in args.dkim_selector for sel in item.split(",") if sel.strip()]
    header_signatures = []
    if args.dkim_header:
        try:
            header_signatures = load_header_signatures(args.dkim_header)
        except OSError as exc:
            parser.error(f"cannot read --dkim-header file: {exc}")
        if not header_signatures:
            print(f"[!] no usable DKIM-Signature (d=, s=) found in {args.dkim_header}", file=sys.stderr)
    dkim_options = {"use_api": args.dkim_api, "selectors": extra_selectors,
                    "header_signatures": header_signatures}

    if args.d:
        domain = normalize_domain(args.d)
        domains, rejected = ([domain], []) if domain else ([], [args.d])
    else:
        try:
            with open(args.iL, "r", encoding="utf-8") as file:
                domains, rejected = load_domains(file)
        except OSError as exc:
            parser.error(f"cannot read -iL file: {exc}")
    for bad in rejected:
        print(f"[!] skipping invalid domain: {bad!r}", file=sys.stderr)
    if not domains:
        print("[!] no valid domains to process", file=sys.stderr)
        sys.exit(1)

    domain_queue = Queue()
    results = []
    for index, domain in enumerate(domains):
        domain_queue.put((index, domain))

    threads = []
    for _ in range(min(args.t, len(domains))):
        thread = threading.Thread(
            target=worker,
            args=(domain_queue, print_lock, args.o, results, args.dkim, args.dkim_wordlist, args.verbose_spf, dkim_options, not args.basic),
        )
        thread.start()
        threads.append(thread)

    domain_queue.join()

    for _ in range(len(threads)):
        domain_queue.put(None)
    domain_queue.join()
    for thread in threads:
        thread.join()

    ordered = [result for _, result in sorted(results, key=lambda pair: pair[0])]  # input order, not thread order
    if args.o == "xls":
        file_name = args.out or "output.xlsx"
        report.write_to_excel(ordered, file_name)
        print(f"Results written to {file_name}", file=sys.stderr)
    elif args.o == "csv":
        file_name = args.out or "output.csv"
        report.write_to_csv(ordered, file_name)
        print(f"Results written to {file_name}", file=sys.stderr)
    elif args.o == "json":
        report.output_json(ordered, args.out)

    failed = False
    if args.fail_on:
        threshold = FAIL_ON_RANK[args.fail_on]
        offenders = [r["DOMAIN"] for r in ordered if worst_live_rank(r.get("DKIM_ANALYSIS")) >= threshold]
        if offenders:
            print(f"[!] --fail-on {args.fail_on}: DKIM findings on {', '.join(offenders)}", file=sys.stderr)
            failed = True
    if args.min_score is not None:
        # error results have no score: treat them as failing rather than crash or pass silently
        low = [f"{r['DOMAIN']} ({r.get('SCORE_OVERALL', 'error')})" for r in ordered
               if r.get("SCORE_OVERALL", -1) < args.min_score]
        if low:
            print(f"[!] --min-score {args.min_score}: below threshold: {', '.join(low)}", file=sys.stderr)
            failed = True
    if failed:
        sys.exit(2)


if __name__ == "__main__":
    main()
