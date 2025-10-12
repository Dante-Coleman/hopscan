import argparse
from core.loader import load_email
from core.parser import extract_headers, extract_received_hops
from email.message import Message

def main():
    parser = argparse.ArgumentParser(
        description="HopScan - Email header analyzer"
    )
    parser.add_argument("email_file", help="Path to .eml or .txt email file")
    args = parser.parse_args()

    msg: Message = load_email(args.email_file)
    print("\n=== Extracted Headers: ===")
    all_headers = extract_headers(msg)
    for header in all_headers:
        print(f"{header.name}: {header.value}")

    print("\n=== Received Hops: ===")
    hops = extract_received_hops(msg)
    for hop in hops:
        print(f"\nHop {hop.index + 1}:")
        print(f"Raw: {hop.raw}")
        if hop.timestamp:
            print(f"Timestamp: {hop.timestamp}")
        if hop.ip_candidates:
            print(f"IP Candidates: {', '.join(hop.ip_candidates)}")
        else:
            print("IP Candidates: None found")

if __name__ == "__main__":
    main()