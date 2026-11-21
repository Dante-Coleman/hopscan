import argparse
import json
import sys
from dataclasses import asdict
from email.message import Message

from colorama import Back, Fore, Style, init

from core.analyzer import analyze_email
from core.asn_tiers import ASN_TIER_NAMES
from core.loader import load_email
from core.models import AnalysisResult
from core.parser import extract_headers, extract_received_hops
from core.utils import GeoLookup

LEVEL_COLORS = {
    "good": Fore.GREEN, "ok": Fore.GREEN, "warn": Fore.YELLOW, "bad": Fore.RED, "severe": Fore.RED,
}


def section(title: str) -> None:
    print()
    print(Fore.WHITE + Back.BLACK + Style.BRIGHT + title + Style.RESET_ALL)


def label(text: str) -> str:
    return f"{Fore.MAGENTA}{Style.BRIGHT}{text}:{Style.RESET_ALL}"


def color_result(value) -> str:
    val = (value or "none").lower()
    if val == "pass":
        color = Fore.GREEN
    elif val in ("fail", "softfail", "none", "neutral"):
        color = Fore.RED
    else:
        color = Fore.YELLOW
    return f"{color}{val.capitalize()}{Style.RESET_ALL}"


def print_report(result: AnalysisResult) -> None:
    section("EXTRACTED HEADERS:")
    for header in result.headers:
        print(f"{Fore.CYAN}{Style.BRIGHT}{header.name}:{Style.RESET_ALL} {header.value}")

    section("RECEIVED HOPS (newest first):")
    for hop in result.received_hops:
        print(f"{Fore.GREEN}{Style.BRIGHT}Hop {hop.index + 1}:{Style.RESET_ALL}")
        print(f"Raw: {hop.raw}")
        if hop.timestamp:
            print(f"Timestamp: {hop.timestamp}")
        if not hop.ips:
            print("IP Candidates: None found\n")
            continue
        if hop.non_public_ips:
            print(f"  Private/Reserved IPs: {', '.join(i.ip for i in hop.non_public_ips)}")
        if not hop.public_ips:
            print("  Public IPs: None found\n")
            continue
        print("  Public IPs:")
        for info in hop.public_ips:
            asn = f"AS{info.asn_num} {info.asn_org}" if info.asn_num else "None"
            tier = f" ({ASN_TIER_NAMES[info.asn_tier]})" if info.asn_tier else ""
            print(f"    {Fore.GREEN}{info.ip}{Style.RESET_ALL} -> Country: {info.country or 'None'}, "
                  f"City: {info.city or 'None'}, ASN: {asn}{tier}")
            print(f"        AbuseIPDB Lookup: https://abuseipdb.com/check/{info.ip}")
        print()

    section("ANALYSIS RESULTS:")
    auth = result.auth_results
    if not auth.trusted:
        source = " (no trusted results)"
    else:
        source = f" (from {auth.authserv_id or 'receiving server, no authserv-id'})"
    print(f"{label('Authentication Results')} SPF: {color_result(auth.spf)} | "
          f"DKIM: {color_result(auth.dkim_summary)} | DMARC: {color_result(auth.dmarc)}{source}")
    for d in (d for d in auth.dkim if d.result != "none"):
        print(f"  DKIM signature: {color_result(d.result)} d={d.domain or '?'}")
    if auth.ignored_headers:
        print(f"  {Fore.YELLOW}Ignored {auth.ignored_headers} Authentication-Results header(s) "
              f"not added by the receiving server.{Style.RESET_ALL}")

    tt_color = Fore.RED if result.time_travel else Fore.GREEN
    print(f"{label('Time Travel Detected')} {tt_color}{result.time_travel}{Style.RESET_ALL}")
    from_display = f'"{result.from_display_name}" ' if result.from_display_name else ""
    print(f"{label('From Domain')} {from_display}{result.from_domain}")
    print(f"{label('Reply-To Domain')} {result.reply_to_domain}")
    print(f"{label('Return-Path Domain')} {result.return_path_domain}")
    print(f"{label('Sender Domain')} {result.sender_domain}")

    section("FINDINGS:")
    for f in result.findings:
        color = Fore.GREEN if f.points > 0 else Fore.RED if f.points < 0 else ""
        print(f"  {color}{f.points:+d}{Style.RESET_ALL}  {f.detail}")

    color = LEVEL_COLORS.get(result.verdict_level, "")
    print()
    print(f"{Fore.WHITE}{Back.BLACK}{Style.BRIGHT}SCORE:{Style.RESET_ALL} {result.score}")
    print(f"{Fore.WHITE}{Back.BLACK}{Style.BRIGHT}VERDICT:{Style.RESET_ALL} {color}{Style.BRIGHT}{result.verdict}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{Back.BLACK}{Style.BRIGHT}DETAILS:{Style.RESET_ALL} {color}{result.verdict_description}{Style.RESET_ALL}")


def to_json(result: AnalysisResult) -> str:
    data = asdict(result)
    data["auth_results"]["dkim_summary"] = result.auth_results.dkim_summary
    return json.dumps(data, indent=2, default=str)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="hopscan - email header analyzer")
    parser.add_argument("email_file", help="Path to a .eml or .txt email file")
    parser.add_argument("--json", action="store_true", help="Print results as JSON instead of the colored report")
    parser.add_argument("--trusted-authserv", action="append", default=[], metavar="ID",
                        help="authserv-id of your mail provider (e.g. mx.google.com). Only Authentication-Results "
                             "headers with this ID are trusted. Repeatable. Default: trust only the topmost header.")
    parser.add_argument("--db-dir", help="Folder containing the GeoLite2 databases (default: ./databases "
                                         "or $HOPSCAN_DB_DIR)")
    parser.add_argument("--no-geo", action="store_true", help="Skip GeoIP/ASN lookups")
    args = parser.parse_args(argv)

    init(autoreset=True, strip=True if args.json else None)

    try:
        msg: Message = load_email(args.email_file)
    except OSError as exc:
        print(f"error: can't read {args.email_file}: {exc.strerror or exc}", file=sys.stderr)
        return 2

    headers = extract_headers(msg)
    if not headers:
        print(f"error: no email headers found in {args.email_file}", file=sys.stderr)
        return 2
    hops = extract_received_hops(msg)

    geo = None if args.no_geo else GeoLookup(args.db_dir)
    try:
        result = analyze_email(msg, headers, hops, geo=geo, trusted_authserv=args.trusted_authserv)
    finally:
        if geo is not None:
            geo.close()

    if args.json:
        print(to_json(result))
    else:
        if geo is not None and not geo.available:
            print(f"{Fore.YELLOW}warning: GeoLite2 databases not found; skipping location/ASN lookups.{Style.RESET_ALL}",
                  file=sys.stderr)
        print_report(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
