import re
from datetime import datetime
from typing import List, Optional
from colorama import init, Fore, Back, Style
from .asn_tiers import asn_tiers
from .models import AnalysisResult, ReceivedHop, AuthResults
from .utils import extract_domain_from_address, get_valid_ipv4_geolocation, get_valid_ipv4_asn, get_valid_ipv4_asn_num

# Scoring dictionary.
FLAG_SCORES = {
    "time_travel": -50,
    "no_spf": -3,
    "spf_fail": -20,
    "no_dkim": -3,
    "dkim_fail": -20,
    "no_dmarc": -3,
    "dmarc_fail": -20,
    "valid_auth": +15, # All-pass bonus.
    "asn_tier_1": +5,
    "asn_tier_2": +2,
    "asn_tier_3": -3,
}

def detect_time_travel(hops: List[ReceivedHop]) -> bool:
    """Checks for time travel in Received hops and returns boolean."""
    for i in range(len(hops) - 1):
        current = hops[i].timestamp
        nxt = hops[i + 1].timestamp
        if current and nxt:
            if current < nxt:
                return True
    return False

def parse_auth_headers(headers: List[str]) -> AuthResults:
    """Parses headers and returns AuthResults."""
    auth_results = AuthResults()
    mechanisms = {
        "spf=": "spf",
        "dkim=": "dkim",
        "dmarc=": "dmarc",
    }
    for header_line in headers:
        normalized = re.sub(r'\r?\n\s+', ' ', header_line.lower().strip())
        auth_results.raw.append(header_line)

        # Split by semicolon to isolate each mechanism.
        parts = [p.strip() for p in normalized.split(';') if '=' in p]

        for part in parts:
            for key, field_name in mechanisms.items():
                if key in part:
                    # Extract the value only for that mechanism.
                    m = re.search(rf"{key}\s*([a-z\-]+)", part)
                    if not m:
                        setattr(auth_results, field_name, "none")
                        continue
                    val = m.group(1)

                    # Normalize values.
                    if val.startswith("pass") and not val.startswith("bestguess"):
                        setattr(auth_results, field_name, "pass")
                    elif "fail" in val:
                        setattr(auth_results, field_name, "fail")
                    else:
                        setattr(auth_results, field_name, "none")
    return auth_results

def extract_domains(msg) -> dict:
    """Extracts domains from headers using utils function and returns dictionary."""
    domain_fields = {
        "from_domain": extract_domain_from_address(msg.get("From")),
        "reply_to_domain": extract_domain_from_address(msg.get("Reply-To")),
        "return_path_domain": extract_domain_from_address(msg.get("Return-Path")),
        "sender_domain": extract_domain_from_address(msg.get("Sender")),
    }
    return domain_fields

def calculate_score(result: AnalysisResult) -> int:
    """Calculates score based on flags and auth results."""
    score = 0
    flags = result.flags

    # Check flags and apply scores.
    for flag, value in flags.items():
        if value and flag in FLAG_SCORES:
            score += FLAG_SCORES[flag]

    # Check auth results and apply scores.
    auth = result.auth_results
    if auth:
        if not auth.spf or auth.spf == "none":
            score += FLAG_SCORES["no_spf"]
        elif auth.spf == "fail":
            score += FLAG_SCORES["spf_fail"]

        if not auth.dkim or auth.dkim == "none":
            score += FLAG_SCORES["no_dkim"]
        elif auth.dkim == "fail":
            score += FLAG_SCORES["dkim_fail"]

        if not auth.dmarc or auth.dmarc == "none":
            score += FLAG_SCORES["no_dmarc"]
        elif auth.dmarc == "fail":
            score += FLAG_SCORES["dmarc_fail"]

        if all(v == "pass" for v in [auth.spf, auth.dkim, auth.dmarc] if v):
            score += FLAG_SCORES["valid_auth"]

    # Adjust score based on ASN tiers (one score per hop).
    for hop in result.received_hops:
        if hop.asn_tier:
            # Filter out None values.
            valid_tiers = [t for t in hop.asn_tier if t is not None]
            if valid_tiers:
                # Choose the most favorable tier (lowest number).
                best_tier = min(valid_tiers)
                if best_tier == 1:
                    score += FLAG_SCORES["asn_tier_1"]
                elif best_tier == 2:
                    score += FLAG_SCORES["asn_tier_2"]
                elif best_tier == 3:
                    score += FLAG_SCORES["asn_tier_3"]
    
    result.score = score
    return score

def analyze_email(msg, headers: List, hops: List[ReceivedHop]) -> AnalysisResult:
    """Main analyzer function that processes email and returns AnalysisResult."""
    result = AnalysisResult()
    result.headers = headers
    result.received_hops = hops

    # Was time travel detected?
    result.flags["time_travel"] = detect_time_travel(hops)

    # What geolocations were found?
    for hop in result.received_hops:
        for ip in hop.valid_ips:
            geo = get_valid_ipv4_geolocation(ip)
            if geo:
                city, country = geo
                hop.city = city
                hop.country = country
            else:
                hop.city = None
                hop.country = None

    # What ASN numbers and orgs were found? What tiers are they?
    for hop in result.received_hops:
        hop.asn.clear()
        hop.asn_num.clear()
        hop.asn_tier.clear()

        for ip in hop.valid_ips:
            asn = get_valid_ipv4_asn(ip)
            hop.asn.append(asn if asn else None)

            asn_num = get_valid_ipv4_asn_num(ip)
            hop.asn_num.append(asn_num if asn_num else None)

            if asn_num:
                try:
                    hop.asn_tier.append(asn_tiers.get(int(asn_num), None))
                except ValueError:
                    hop.asn_tier.append(None)
            else:
                hop.asn_tier.append(None)

    # What were the auth results?
    auth_headers = [h.value for h in headers if h.name.lower() == "authentication-results"]
    result.auth_results = parse_auth_headers(auth_headers)

    # What domains were extracted?
    domains = extract_domains(msg)
    result.from_domain = domains["from_domain"]
    result.reply_to_domain = domains["reply_to_domain"]
    result.return_path_domain = domains["return_path_domain"]
    result.sender_domain = domains["sender_domain"]

    # Run score calculator.
    score = calculate_score(result)
    result.score = score

    # Determines verdict based on score.
    if score >= 15:
        verdict = Fore.GREEN + Style.BRIGHT + "High Confidence"
        description = Fore.GREEN + "All authentication passed or strong signals of legitimacy."
    elif 0 <= score < 15:
        verdict = Fore.GREEN + Style.BRIGHT + "Mostly Safe"
        description = Fore.GREEN + "No critical issues, but missing or weak auth mechanisms."
    elif -20 <= score < 0:
        verdict = Fore.YELLOW + Style.BRIGHT + "Suspicious"
        description = Fore.YELLOW + "Missing or failed authentication, or mild anomalies detected."
    elif -40 <= score < -20:
        verdict = Fore.RED + Style.BRIGHT + "Risky"
        description = Fore.RED + "Multiple authentication problems or header inconsistencies."
    else:  # Score < -40.
        verdict = Fore.RED + Style.BRIGHT + "Likely Spoofed"
        description = Fore.RED + "Severe header anomalies and authentication failures."

    result.flags["verdict"] = verdict
    result.flags["verdict_description"] = description

    return result