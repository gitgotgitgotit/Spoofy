# modules/spf_hardening.py
"""SPF hardening findings from a walk: void lookups, ptr, huge ranges, broken includes, length."""

from .findings import check_result, finding

MAX_VOID = 2
LONG_RECORD = 450  # a TXT answer much beyond ~512 bytes needs EDNS0/TCP; many resolvers/firewalls mishandle it


def check_spf_hardening(spf_record, walk, skip_targets=()):
    if not spf_record:
        return check_result("SPF hardening", False, "no SPF record")
    findings, skip = [], set(skip_targets)
    if walk["ptr"]:
        findings.append(finding("medium", "SPF_PTR", "SPF uses the ptr mechanism: deprecated (RFC 7208 5.5), slow and unreliable; some receivers ignore it",
                                "Replace ptr with explicit ip4:/ip6:/a:/mx: mechanisms."))
    if walk["void_lookups"] > MAX_VOID:
        findings.append(finding("high", "SPF_VOID_LOOKUPS",
                                f"SPF triggers {walk['void_lookups']} void lookups (NXDOMAIN/empty answers; limit is {MAX_VOID}): receivers return permerror",
                                "Remove mechanisms and includes that point at names that no longer exist."))
    for inc in walk["includes"]:
        if inc["target"] in skip:
            continue  # already reported (more severely) by the takeover check
        if inc["status"] == "nxdomain":
            findings.append(finding("high", "SPF_INCLUDE_MISSING", f"include/redirect target {inc['target']} does not exist: SPF evaluation fails (permerror)",
                                    "Remove it or restore the record.", inc["target"]))
        elif inc["status"] == "no-spf":
            findings.append(finding("high", "SPF_INCLUDE_NO_RECORD", f"include/redirect target {inc['target']} has no SPF record: SPF evaluation fails (permerror)",
                                    "Remove it or ask the provider for the correct include name.", inc["target"]))
    for rng in walk["ip_ranges"]:
        if rng["qualifier"] != "+":
            continue
        net, prefix = rng["network"], rng["prefix"]
        if prefix == 0:
            findings.append(finding("critical", "SPF_ALLOW_ALL_RANGE", f"{net} authorises every address on the internet (equivalent to +all)",
                                    "Replace with the real sending ranges.", net))
        elif (rng["version"] == 4 and prefix <= 8) or (rng["version"] == 6 and prefix < 20):
            findings.append(finding("high", "SPF_HUGE_RANGE", f"{net} (in {rng['owner']}) authorises an enormous address range", "Narrow it to the actual senders.", net))
        elif (rng["version"] == 4 and prefix < 16) or (rng["version"] == 6 and prefix < 32):
            findings.append(finding("medium", "SPF_LARGE_RANGE", f"{net} (in {rng['owner']}) authorises a very large address range", "Narrow it to the actual senders.", net))
    if len(spf_record) > LONG_RECORD:
        findings.append(finding("low", "SPF_LONG_RECORD", f"SPF record is {len(spf_record)} characters: oversized TXT answers are mishandled by some resolvers/firewalls",
                                "Remove unused mechanisms or restructure with includes."))
    if walk["truncated"]:
        findings.append(finding("info", "SPF_WALK_TRUNCATED", "Very deep SPF include tree: only the first records were inspected"))
    for err in walk["errors"]:
        findings.append(finding("info", "SPF_WALK_PARSE", f"Could not parse SPF during walk ({err})"))
    return check_result("SPF hardening", True, None, {"void_lookups": walk["void_lookups"], "ptr": walk["ptr"], "lookups": walk["lookups"]}, findings)
