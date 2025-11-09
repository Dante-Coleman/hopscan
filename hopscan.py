import argparse
from email.message import Message
from colorama import init, Fore, Back, Style
from core.loader import load_email
from core.parser import extract_headers, extract_received_hops
from core.analyzer import analyze_email

init(autoreset=True) # Auto reset colorama styles after each print.

def color_result(value):
    if not value:
        value = "none"
    val = value.lower()
    if val == "pass":
        return f"{Fore.GREEN}{val.capitalize()}{Style.RESET_ALL}"
    elif val in ("fail", "none", "neutral"):
        return f"{Fore.RED}{val.capitalize()}{Style.RESET_ALL}"
    else:
        return f"{Fore.YELLOW}{val.capitalize()}{Style.RESET_ALL}"

def main():
    """Main function to run HopScan from command line."""
    parser = argparse.ArgumentParser(
        description="HopScan - Email header analyzer"
    )
    parser.add_argument("email_file", help="Path to .eml or .txt email file")
    args = parser.parse_args()
    msg: Message = load_email(args.email_file)
    
    print()
    print(Fore.WHITE + Back.BLACK + Style.BRIGHT + "EXTRACTED HEADERS:" + Style.RESET_ALL)
    all_headers = extract_headers(msg)
    for header in all_headers:
        print(f"{Fore.CYAN}{Style.BRIGHT}{header.name}:{Style.RESET_ALL} {header.value}")

    print()
    print(Fore.WHITE + Back.BLACK + Style.BRIGHT + "RECEIVED HOPS:" + Style.RESET_ALL)
    hops = extract_received_hops(msg)
    for hop in hops:
        print(f"{Fore.GREEN}{Style.BRIGHT}Hop {hop.index + 1}:{Style.RESET_ALL}")
        print(f"Raw: {hop.raw}")
        if hop.timestamp:
            print(f"Timestamp: {hop.timestamp}")
        if hop.ip_candidates:
            print(f"IP Candidates: {', '.join(hop.ip_candidates)}")
            if hop.private_ips:
                print(f"  Private IPs: {', '.join(hop.private_ips)}")
            if hop.valid_ips:
                print("  Valid Public IPs:")
                for i, ip in enumerate(hop.valid_ips):
                    country = hop.country[i] if i < len(hop.country) else None
                    city = hop.city[i] if i < len(hop.city) else None
                    asn_num = hop.asn_num[i] if i < len(hop.asn_num) else None
                    asn = hop.asn[i] if i < len(hop.asn) else None
                    abuseipdb_url = f"https://abuseipdb.com/check/{ip}"

                    print(
                        f"    {Fore.GREEN}{ip}{Style.RESET_ALL} -> Country: {country or 'None'}, "
                        f"City: {city or 'None'}, ASN: {asn_num or 'None'}|{asn or 'None'}"
                    )
                    print(f"        AbuseIPDB Lookup: {Fore.RED}{abuseipdb_url}{Style.RESET_ALL}")
                print()
            else:
                print("  Valid Public IPs: None found\n")
        else:
            print("IP Candidates: None found\n")

    result = analyze_email(msg, all_headers, hops)

    print()
    print(Fore.WHITE + Back.BLACK + Style.BRIGHT + "ANALYSIS RESULTS:" + Style.RESET_ALL)

    print(
        f"{Fore.MAGENTA}{Style.BRIGHT}Time Travel Detected:{Style.RESET_ALL}"
        f"{Fore.RED if result.flags['time_travel'] else Fore.GREEN} {result.flags['time_travel']}{Style.RESET_ALL}"
    )

    auth = result.auth_results
    spf = color_result(getattr(auth, "spf", "none"))
    dkim = color_result(getattr(auth, "dkim", "none"))
    dmarc = color_result(getattr(auth, "dmarc", "none"))
    print(
        f"{Fore.MAGENTA}{Style.BRIGHT}Authentication Results:{Style.RESET_ALL} "
        f"SPF: {spf} | DKIM: {dkim} | DMARC: {dmarc}"
    )
    
    print(f"{Fore.MAGENTA}{Style.BRIGHT}From Domain:{Style.RESET_ALL} {result.from_domain}")
    print(f"{Fore.MAGENTA}{Style.BRIGHT}Reply-To Domain:{Style.RESET_ALL} {result.reply_to_domain}")
    print(f"{Fore.MAGENTA}{Style.BRIGHT}Return-Path Domain:{Style.RESET_ALL} {result.return_path_domain}")
    print(f"{Fore.MAGENTA}{Style.BRIGHT}Sender Domain:{Style.RESET_ALL} {result.sender_domain}")

    print()
    print(f"{Fore.WHITE}{Back.BLACK}{Style.BRIGHT}SCORE:{Style.RESET_ALL} {result.score}")
    print(f"{Fore.WHITE}{Back.BLACK}{Style.BRIGHT}VERDICT:{Style.RESET_ALL} {result.flags['verdict']}")
    print(f"{Fore.WHITE}{Back.BLACK}{Style.BRIGHT}DETAILS:{Style.RESET_ALL} {result.flags['verdict_description']}")

if __name__ == "__main__":
    main()