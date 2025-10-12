import argparse
from core.loader import load_email

def main():
    parser = argparse.ArgumentParser(
        description="HopScan - Email header analyzer"
    )
    parser.add_argument("email_file", help="Path to .eml or .txt email file")
    args = parser.parse_args()

    headers = load_email(args.email_file)
    print("Email Headers:")
    for name, value in headers.items():
        print(f"{name}: {value}")

if __name__ == "__main__":
    main()
