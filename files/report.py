# modules/report.py

import os
import pandas as pd
import json
from colorama import init, Fore, Style

from .dkim_analysis import sort_by_severity

# Initialize colorama
init()


def output_message(symbol, message, level="info"):
    """Generic function to print messages with different colors and symbols based on the level."""
    colors = {
        "good": Fore.GREEN + Style.BRIGHT,
        "warning": Fore.YELLOW + Style.BRIGHT,
        "bad": Fore.RED + Style.BRIGHT,
        "indifferent": Fore.BLUE + Style.BRIGHT,
        "error": Fore.RED + Style.BRIGHT + "!!! ",
        "info": Fore.WHITE + Style.BRIGHT,
    }
    color = colors.get(level, Fore.WHITE + Style.BRIGHT)
    print(color + f"{symbol} {message}" + Style.RESET_ALL)


def _flatten_row(row):
    """Spreadsheet cells can't hold dicts/lists: store them as JSON text instead of Python reprs."""
    return {k: (json.dumps(v, default=str) if isinstance(v, (dict, list, tuple)) else v) for k, v in row.items()}


def _write_table(data, file_name, reader, writer):
    new_df = pd.DataFrame([_flatten_row(row) for row in data])
    if os.path.exists(file_name) and os.path.getsize(file_name) > 0:
        new_df = pd.concat([reader(file_name), new_df], ignore_index=True)
    writer(new_df, file_name)


def write_to_excel(data, file_name="output.xlsx"):
    """Writes results to an Excel file, appending if the file exists."""
    _write_table(data, file_name, pd.read_excel, lambda df, f: df.to_excel(f, index=False))


def write_to_csv(data, file_name="output.csv"):
    """Writes results to a CSV file, appending if the file exists."""
    _write_table(data, file_name, pd.read_csv, lambda df, f: df.to_csv(f, index=False))


def output_json(results, file_name=None):
    """Print (or write) results as JSON. default=str keeps one odd value from losing the whole batch."""
    text = json.dumps(list(results), default=str)
    if file_name:
        with open(file_name, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        print(text)


_OVERALL_LEVEL = {"critical": "bad", "warning": "warning", "good": "good", "strong": "good", "info": "info"}


def _print_dkim(domain, records, kwargs):
    analysis = sort_by_severity(kwargs.get("DKIM_ANALYSIS"))
    errors = kwargs.get("DKIM_LOOKUP_ERRORS") or {}
    if records:
        output_message("[*]", "DKIM selectors:", "info")
        for rec in records:
            value = rec["record"]
            value = value[:128] + "...(trimmed)" if len(value) > 128 else value
            output_message("   ", f"{rec['fqdn']} ({rec['source']}) -> {value}", "info")
        for key in analysis:
            overall = key.get("overall", "warning")
            live = key.get("live", True)
            level = _OVERALL_LEVEL.get(overall, "warning") if live else "info"
            symbol = "[~]" if not live else "[+]" if overall in ("good", "strong") else "[!]"
            bits = f"{key['key_bits']} bits" if key.get("key_bits") else "size unknown"
            tag = "" if live else f" ({key.get('source')}, not live)"
            alerts = [a for a in key.get("alerts", []) if a != "NO_HASH_RESTRICTION"]
            suffix = f" | ALERTS: {', '.join(alerts)}" if alerts and live else ""
            output_message(symbol, f"DKIM strength: {key['selector']} | {key.get('key_type') or 'unknown'} | {bits} | "
                                   f"{overall.upper()}{tag}{suffix}", level)
            for issue in key.get("issues", []):
                output_message("   ", issue, "warning" if live else "info")
            for note in key.get("notes", []):
                output_message("   ", f"Note: {note}", "info")
            if live:
                for recommendation in key.get("recommendations", []):
                    output_message("   ", f"Recommendation: {recommendation}", "info")
    else:
        output_message("[?]", f"No DKIM selectors found on {domain}. The wordlist/archive only covers common names, so this "
                              "does not prove DKIM is unused; try --dkim-selector or --dkim-header with a real message.", "warning")
    for sig in kwargs.get("DKIM_SIGNATURES") or []:
        flagged = " | ALERT: signature uses rsa-sha1" if sig.get("alerts") else ""
        output_message("[*]", f"Sample message signature: d={sig['domain']} s={sig['selector']} a={sig.get('algorithm') or 'unknown'}{flagged}",
                       "bad" if sig.get("alerts") else "info")
    if errors:
        shown = ", ".join(f"{sel} ({why})" for sel, why in sorted(errors.items())[:5])
        more = f" and {len(errors) - 5} more" if len(errors) > 5 else ""
        output_message("[!]", f"{len(errors)} DKIM selector lookup(s) failed (timeout/SERVFAIL), so results may be incomplete: {shown}{more}", "warning")


_SEVERITY_LEVEL = {"critical": "bad", "high": "bad", "medium": "warning", "low": "warning", "info": "info"}


def _print_score(score):
    """Print the configuration score, per-area results and every non-info finding with its fix."""
    caps = score.get("caps") or []
    level = "good" if score["overall"] >= 80 else "warning" if score["overall"] >= 60 else "bad"
    output_message("[*]", f"SECURITY SCORE: {score['overall']}/100 (grade {score['grade']}) - heuristic configuration-strength score", level)
    for cap in caps:
        output_message("   ", f"Capped at {cap['max']}: {cap['reason']}", "warning")
    areas = score.get("areas", {})
    assessed = sorted(((n, a) for n, a in areas.items() if a["applicable"]), key=lambda item: (item[1]["score"], item[0]))
    for name, area in assessed:
        area_level = "good" if area["score"] >= 80 else "warning" if area["score"] >= 60 else "bad"
        output_message("[+]" if area["score"] >= 80 else "[!]", f"{name}: {area['score']}/100", area_level)
        for item in area["findings"]:
            if item["severity"] == "info":
                continue
            output_message("   ", f"[{item['severity']}] {item['title']}", _SEVERITY_LEVEL[item["severity"]])
            if item.get("fix"):
                output_message("   ", f"    Fix: {item['fix']}", "info")
    notes = sum(1 for _, a in assessed for f in a["findings"] if f["severity"] == "info")
    if notes:
        output_message("   ", f"{notes} informational note(s) (see -o json)", "info")
    skipped = [f"{n['area']} ({n['reason']})" for n in score.get("not_assessed", [])]
    if skipped:
        output_message("[~]", "Not scored: " + "; ".join(skipped), "info")


def printer(**kwargs):
    """Utility function to print the results of DMARC, SPF, and BIMI checks in the original format."""
    domain = kwargs.get("DOMAIN")
    subdomain = kwargs.get("DOMAIN_TYPE") == "subdomain"
    dns_server = kwargs.get("DNS_SERVER")
    spf_record = kwargs.get("SPF")
    spf_all = kwargs.get("SPF_MULTIPLE_ALLS")
    spf_dns_query_count = kwargs.get("SPF_NUM_DNS_QUERIES")
    dmarc_record = kwargs.get("DMARC")
    p = kwargs.get("DMARC_POLICY")
    pct = kwargs.get("DMARC_PCT")
    aspf = kwargs.get("DMARC_ASPF")
    sp = kwargs.get("DMARC_SP")
    fo = kwargs.get("DMARC_FORENSIC_REPORT")
    rua = kwargs.get("DMARC_AGGREGATE_REPORT")
    dkim_record = kwargs.get("DKIM")  # list of {selector, fqdn, source, record}
    bimi_record = kwargs.get("BIMI_RECORD")
    vbimi = kwargs.get("BIMI_VERSION")
    location = kwargs.get("BIMI_LOCATION")
    authority = kwargs.get("BIMI_AUTHORITY")
    spoofable = kwargs.get("SPOOFING_POSSIBLE")
    spoofing_type = kwargs.get("SPOOFING_TYPE")

    output_message("[*]", f"Domain: {domain}", "indifferent")
    output_message("[*]", f"Is subdomain: {subdomain}", "indifferent")
    output_message("[*]", f"DNS Server: {dns_server}", "indifferent")

    if spf_record:
        output_message("[*]", f"SPF record: {spf_record}", "info")
        if kwargs.get("SPF_MULTIPLE_RECORDS"):
            output_message("[!]", "Multiple SPF records found; RFC 7208 treats this as permerror.", "warning")
        if spf_all is None:
            output_message("[*]", "SPF does not contain an `All` item.", "info")
        elif spf_all == "2many":
            output_message(
                "[?]", "SPF record contains multiple `All` items.", "warning"
            )
        else:
            output_message("[*]", f"SPF all record: {spf_all}", "info")
        output_message(
            "[*]",
            f"SPF DNS query count: {spf_dns_query_count}"
            if spf_dns_query_count <= 10
            else f"Too many SPF DNS query lookups {spf_dns_query_count}.",
            "info",
        )
    else:
        if kwargs.get("SPF_MULTIPLE_RECORDS"):
            output_message("[!]", "Multiple SPF records found; RFC 7208 treats this as permerror.", "warning")
        else:
            output_message("[?]", "No SPF record found.", "warning")

    intelligence = kwargs.get("SPF_INTELLIGENCE")
    if intelligence:
        output_message("[*]", "SPF INTELLIGENCE", "indifferent")
        output_message("[*]", f"Syntax valid: {intelligence['record_valid']}", "good" if intelligence["record_valid"] else "warning")
        output_message("[*]", f"DNS lookup budget: {intelligence['dns_lookup_count']}/10 ({intelligence['dns_lookups_remaining']} remaining)", "warning" if intelligence["dns_lookup_count"] > 10 else "info")
        for item in intelligence["domains"]:
            output_message("[+]" if item["dns_status"] == "resolved" else "[!]",
                           f"{item['source']}: {item['domain']} | DNS={item['dns_status']} | SPF={item['spf_status']} | RDAP={item['registration']} | Provider={item['provider'] or 'unknown'}",
                           "good" if item["dns_status"] == "resolved" else "warning")
            if item.get("registrar"):
                output_message("   ", f"Registrar: {item['registrar']} | Created: {item['created']} | Expires: {item['expires']}", "info")
        for item in intelligence["ips"]:
            output_message("[*]", f"IP: {item['ip']} | Owner: {item['owner'] or 'unknown'} | Registry: {item['handle'] or 'unknown'} | RDAP range: {item['prefix'] or 'unknown'} | BGP prefix: {item.get('bgp_prefix') or 'unknown'} | ASN: {', '.join((f"AS{x.get('asn')} ({x.get('holder', 'unknown')})" if isinstance(x, dict) else f'AS{x}' for x in item.get('asns', []))) or 'unknown'} | Announced: {item.get('bgp_announced') if item.get('bgp_announced') is not None else 'unknown'} | Country: {item['country'] or 'unknown'}", "info")
        for warning in intelligence["warnings"]:
            output_message("[!]", warning, "warning")

    if dmarc_record:
        output_message("[*]", f"DMARC record: {dmarc_record}", "info")
        record_domain = kwargs.get("DMARC_RECORD_DOMAIN")
        if record_domain and record_domain != domain:
            output_message("[*]", f"DMARC record inherited from organizational domain {record_domain}.", "info")
        output_message(
            "[*]", f"Found DMARC policy: {p}" if p else "No DMARC policy found.", "info"
        )
        output_message(
            "[*]", f"Found DMARC pct: {pct}" if pct else "No DMARC pct found.", "info"
        )
        output_message(
            "[*]",
            f"Found DMARC aspf: {aspf}" if aspf else "No DMARC aspf found.",
            "info",
        )
        output_message(
            "[*]",
            f"Found DMARC subdomain policy: {sp}"
            if sp
            else "No DMARC subdomain policy found.",
            "info",
        )
        output_message(
            "[*]",
            f"Forensics reports will be sent: {fo}"
            if fo
            else "No DMARC forensics report location found.",
            "indifferent",
        )
        output_message(
            "[*]",
            f"Aggregate reports will be sent to: {rua}"
            if rua
            else "No DMARC aggregate report location found.",
            "indifferent",
        )
    elif kwargs.get("DMARC_MULTIPLE_RECORDS"):
        output_message("[!]", "Multiple DMARC records found; RFC 7489 says DMARC is not applied.", "warning")
    else:
        output_message("[?]", "No DMARC record found.", "warning")

    if kwargs.get("DKIM_ENABLED"):
        _print_dkim(domain, dkim_record, kwargs)

    if bimi_record:
        output_message("[*]", f"BIMI record: {bimi_record}", "info")
        output_message("[*]", f"BIMI version: {vbimi}", "info")
        output_message("[*]", f"BIMI location: {location}", "info")
        output_message("[*]", f"BIMI authority: {authority}", "info")

    if spoofing_type:
        # spoofable=True is bad news (green="good" would be misleading);
        # spoofable=False is the safe/desired outcome; None means "maybe".
        if spoofable is True:
            symbol, level = "[-]", "bad"
        elif spoofable is False:
            symbol, level = "[+]", "good"
        else:
            symbol, level = "[?]", "warning"
        output_message(symbol, spoofing_type, level)
    if kwargs.get("SPOOFING_DKIM_NOTE") and not (spoofing_type or "").endswith(kwargs["SPOOFING_DKIM_NOTE"]):
        output_message("[!]", kwargs["SPOOFING_DKIM_NOTE"], "bad")

    if kwargs.get("SCORE"):
        _print_score(kwargs["SCORE"])

    print()  # Padding
