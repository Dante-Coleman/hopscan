import argparse
import json
import sys
from dataclasses import asdict
from email.message import Message
from typing import Optional

from colorama import Fore, Style, init

from core.analyzer import analyze_email
from core.asn_tiers import ASN_TIER_NAMES
from core.loader import load_email
from core.models import AnalysisResult
from core.parser import extract_headers, extract_received_hops
from core.utils import GeoLookup

LEVEL_COLORS = {
    "good": Fore.GREEN, "ok": Fore.GREEN, "warn": Fore.YELLOW, "bad": Fore.RED, "severe": Fore.RED,
}
CATEGORY_TITLES = [
    ("auth", "Authentication"),
    ("identity", "Sender identity"),
    ("links", "Links"),
    ("attachments", "Attachments"),
    ("content", "Content"),
    ("route", "Route"),
]
WIDTH = 72
MAX_LINKS_SHOWN = 15


def bold(text: str) -> str:
    return f"{Style.BRIGHT}{text}{Style.RESET_ALL}"


def dim(text: str) -> str:
    return f"{Style.DIM}{text}{Style.RESET_ALL}"


def section(title: str, note: str = "") -> None:
    print()
    print(f"{Fore.CYAN}{Style.BRIGHT}{title}{Style.RESET_ALL}" + (f"  {dim(note)}" if note else ""))
    print(f"{Fore.CYAN}{'-' * WIDTH}{Style.RESET_ALL}")


def row(name: str, value: str, width: int = 13) -> None:
    print(f"  {name.ljust(width)}{value}")


def color_result(value: Optional[str]) -> str:
    val = (value or "none").lower()
    if val == "pass":
        color = Fore.GREEN
    elif val in ("fail", "softfail"):
        color = Fore.RED
    else:
        color = Fore.YELLOW
    return f"{color}{val.upper().ljust(8)}{Style.RESET_ALL}"


def alignment(aligned: Optional[bool]) -> str:
    if aligned is None:
        return dim("alignment n/a")
    if aligned:
        return f"{Fore.GREEN}aligned with From{Style.RESET_ALL}"
    return f"{Fore.YELLOW}NOT aligned with From{Style.RESET_ALL}"


def points(p: int) -> str:
    text = (f"{p:+d}" if p else ".").rjust(4)
    color = Fore.GREEN if p > 0 else Fore.RED if p < 0 else Style.DIM
    return f"{color}{text}{Style.RESET_ALL}"


def print_verdict(result: AnalysisResult) -> None:
    color = LEVEL_COLORS.get(result.verdict_level, "")
    print()
    print(f"{color}{'=' * WIDTH}{Style.RESET_ALL}")
    print(f"  {color}{Style.BRIGHT}VERDICT: {result.verdict}{Style.RESET_ALL}   {dim(f'score {result.score}')}")
    print(f"  {result.verdict_description}")
    print(f"{color}{'=' * WIDTH}{Style.RESET_ALL}")


def print_sender(result: AnalysisResult) -> None:
    section("SENDER")
    row("From", result.from_header or "-")
    row("Reply-To", result.reply_to_domain or "-")
    row("Return-Path", result.return_path_domain or "-")
    if result.sender_domain:
        row("Sender", result.sender_domain)
    row("Subject", result.subject or "-")
    row("Date", result.date or "-")


def print_auth(result: AnalysisResult) -> None:
    auth = result.auth_results
    if not auth.trusted:
        note = "no trusted results"
    else:
        note = f"checked by {auth.authserv_id or 'the receiving server (no authserv-id)'}"
    section("AUTHENTICATION", note)
    if not auth.trusted:
        print(f"  {Fore.YELLOW}No Authentication-Results header from the receiving server.{Style.RESET_ALL}")
    else:
        spf_domain = f"mailfrom {auth.spf_domain}" if auth.spf_domain else ""
        print(f"  SPF    {color_result(auth.spf)} {spf_domain.ljust(32)} "
              f"{alignment(auth.spf_aligned) if auth.spf == 'pass' else ''}")
        signatures = [d for d in auth.dkim if d.result != "none"]
        if not signatures:
            print(f"  DKIM   {color_result(auth.dkim_summary)}")
        for d in signatures:
            domain = f"d={d.domain}" if d.domain else ""
            print(f"  DKIM   {color_result(d.result)} {domain.ljust(32)} "
                  f"{alignment(d.aligned) if d.result == 'pass' else ''}")
        dmarc_domain = f"header.from {auth.dmarc_domain}" if auth.dmarc_domain else ""
        print(f"  DMARC  {color_result(auth.dmarc)} {dmarc_domain}")
    if auth.ignored_headers:
        print(f"  {Fore.YELLOW}Ignored {auth.ignored_headers} Authentication-Results header(s) that the "
              f"receiving server didn't add (they could be forged).{Style.RESET_ALL}")


def print_findings(result: AnalysisResult) -> None:
    section("FINDINGS", "points: + reassuring, - suspicious, . info only")
    if not result.findings:
        print("  None.")
    for category, title in CATEGORY_TITLES:
        items = [f for f in result.findings if f.category == category]
        if not items:
            continue
        print(f"  {bold(title)}")
        for f in items:
            print(f"   {points(f.points)}  {f.detail}")


def print_links(result: AnalysisResult) -> None:
    links = [l for l in result.content.links if l.host]
    if not links:
        return
    hosts = list(dict.fromkeys(l.host for l in links))
    section("LINKS", f"{len(links)} link(s) to {len(hosts)} domain(s); none were visited")
    for host in hosts[:MAX_LINKS_SHOWN]:
        count = sum(1 for l in links if l.host == host)
        print(f"  {host}" + (dim(f"  x{count}") if count > 1 else ""))
    if len(hosts) > MAX_LINKS_SHOWN:
        print(dim(f"  ... and {len(hosts) - MAX_LINKS_SHOWN} more (use --json for all)"))


def print_attachments(result: AnalysisResult) -> None:
    attachments = result.content.attachments
    if not attachments:
        return
    section("ATTACHMENTS", "none were opened")
    for att in attachments:
        extra = " [password-protected]" if att.encrypted else ""
        print(f"  {att.filename}  {dim(f'{att.content_type}, {att.size:,} bytes')}{extra}")
        for member in att.archive_members[:10]:
            print(f"      > {member}")


def print_route(result: AnalysisResult, verbose: bool) -> None:
    hops = result.received_hops
    section("ROUTE", "newest hop first; hops near the bottom can be forged by the sender")
    if not hops:
        print("  No Received headers.")
    for hop in hops:
        when = hop.timestamp.strftime("%Y-%m-%d %H:%M:%S %z") if hop.timestamp else "no timestamp"
        hosts = " ".join(filter(None, [f"from {hop.from_host}" if hop.from_host else "",
                                       f"by {hop.by_host}" if hop.by_host else ""]))
        print(f"  {bold(str(hop.index + 1).rjust(2))}  {when}  {hosts}")
        for info in hop.public_ips:
            place = ", ".join(filter(None, [info.city, info.country])) or "location unknown"
            asn = f"AS{info.asn_num} {info.asn_org}" if info.asn_num else ""
            tier = f" ({ASN_TIER_NAMES[info.asn_tier]})" if info.asn_tier else ""
            print(f"      {Fore.GREEN}{info.ip}{Style.RESET_ALL}  {place}  {asn}{tier}")
            if verbose:
                print(dim(f"      https://abuseipdb.com/check/{info.ip}"))
        if hop.non_public_ips:
            print(dim(f"      private/reserved: {', '.join(i.ip for i in hop.non_public_ips)}"))
        if verbose:
            print(dim(f"      raw: {hop.raw}"))


def print_headers(result: AnalysisResult) -> None:
    section("ALL HEADERS")
    for header in result.headers:
        print(f"  {Fore.CYAN}{header.name}:{Style.RESET_ALL} {header.value}")


def print_report(result: AnalysisResult, verbose: bool = False) -> None:
    print_verdict(result)
    print_sender(result)
    print_auth(result)
    print_findings(result)
    print_links(result)
    print_attachments(result)
    print_route(result, verbose)
    if verbose:
        print_headers(result)
    print()


def to_json(result: AnalysisResult) -> str:
    data = asdict(result)
    data["auth_results"]["dkim_summary"] = result.auth_results.dkim_summary
    data["auth_results"]["dkim_aligned"] = result.auth_results.dkim_aligned
    return json.dumps(data, indent=2, default=str)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="hopscan - email header and phishing analyzer")
    parser.add_argument("email_file", help="Path to a .eml or .txt email file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Also show every header, raw Received lines and AbuseIPDB links")
    parser.add_argument("--json", action="store_true", help="Print results as JSON instead of the colored report")
    parser.add_argument("--trusted-authserv", action="append", default=[], metavar="ID",
                        help="authserv-id of your mail provider (e.g. mx.google.com). Only Authentication-Results "
                             "headers with this ID are trusted. Repeatable. Default: trust only the topmost header.")
    parser.add_argument("--db-dir", help="Folder containing the GeoLite2 databases (default: ./databases "
                                         "or $HOPSCAN_DB_DIR)")
    parser.add_argument("--no-geo", action="store_true", help="Skip GeoIP/ASN lookups")
    args = parser.parse_args(argv)

    # Don't crash on characters the console can't show (e.g. Windows code pages).
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
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
        print_report(result, verbose=args.verbose)
    return 0


if __name__ == "__main__":
    sys.exit(main())
