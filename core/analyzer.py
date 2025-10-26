from datetime import datetime
from typing import List, Optional
from .models import AnalysisResult, ReceivedHop, AuthResults
from .utils import extract_domain_from_address

#Scoring dict
FLAG_SCORES = {
    "time_travel": -25,
    "no_spf": -12,
    "spf_fail": -15,
    "no_dkim": -12,
    "dkim_fail": -15,
    "no_dmarc": -12,
    "dmarc_fail": -15,
    "private_hops": -5,
    "valid_auth": +20, #All-pass bonus
}

#Time travel check
def detect_time_travel(hops: List[ReceivedHop]) -> bool:
    for i in range(len(hops) - 1):
        current = hops[i].timestamp
        nxt = hops[i + 1].timestamp
        if current and nxt:
            if current < nxt:
                return True
    return False

#Authentication results
def parse_auth_headers(headers: List[str]) -> AuthResults:
    auth_results = AuthResults()

    mechanisms = {
        "spf=": "spf",
        "dkim=": "dkim",
        "dmarc=": "dmarc",
    }

    for header_line in headers:
        normalized = header_line.lower().strip()

        for key, field_name in mechanisms.items():
            if key in normalized:
                if "pass" in normalized:
                    setattr(auth_results, field_name, "pass")
                elif "fail" in normalized:
                    setattr(auth_results, field_name, "fail")
                else:
                    setattr(auth_results, field_name, "none")
                
        auth_results.raw.append(header_line)

    return auth_results

#Domain extraction
def extract_domains(msg) -> dict:
    domain_fields = {
        "from_domain": extract_domain_from_address(msg.get("From")),
        "reply_to_domain": extract_domain_from_address(msg.get("Reply-To")),
        "return_path_domain": extract_domain_from_address(msg.get("Return-Path")),
        "sender_domain": extract_domain_from_address(msg.get("Sender")),
    }
    return domain_fields

#Score calculator
def calculate_score(result: AnalysisResult) -> int:
    score = 0
    flags = result.flags

    #flag scoring
    for flag, value in flags.items():
        if value and flag in FLAG_SCORES:
            score += FLAG_SCORES[flag]

    #auth scoring
    auth = result.auth_results
    if auth:
        if not auth.spf:
            score += FLAG_SCORES["no_spf"]
        elif auth.spf == "fail":
            score += FLAG_SCORES["spf_fail"]

        if not auth.dkim:
            score += FLAG_SCORES["no_dkim"]
        elif auth.dkim == "fail":
            score += FLAG_SCORES["dkim_fail"]

        if not auth.dmarc:
            score += FLAG_SCORES["no_dmarc"]
        elif auth.dmarc == "fail":
            score += FLAG_SCORES["dmarc_fail"]

        if all(v == "pass" for v in [auth.spf, auth.dkim, auth.dmarc] if v):
            score += FLAG_SCORES["valid_auth"]

    result.score = score
    return score

#Main analyzer
def analyze_email(msg, headers: List, hops: List[ReceivedHop]) -> AnalysisResult:
    result = AnalysisResult()
    result.headers = headers
    result.received_hops = hops

    #Time travel
    result.flags["time_travel"] = detect_time_travel(hops)

    #Auth results
    auth_headers = [h.value for h in headers if h.name.lower() == "authentication-results"]
    result.auth_results = parse_auth_headers(auth_headers)

    #Domain extraction
    domains = extract_domains(msg)
    result.from_domain = domains["from_domain"]
    result.reply_to_domain = domains["reply_to_domain"]
    result.return_path_domain = domains["return_path_domain"]
    result.sender_domain = domains["sender_domain"]

    #Scoring
    score = calculate_score(result)
    result.score = score

    #Classification
    if score >= 10:
        verdict = "High Confidence"
        description = "All authentication passed or strong signals of legitimacy."
    elif 0 <= score < 10:
        verdict = "Mostly Safe"
        description = "No critical issues, but missing or weak auth mechanisms."
    elif -25 <= score < 0:
        verdict = "Suspicious"
        description = "Missing or failed authentication, or mild anomalies detected."
    elif -50 <= score < -25:
        verdict = "Risky"
        description = "Multiple authentication problems or header inconsistencies."
    else:  # score < -50
        verdict = "Likely Spoofed"
        description = "Severe header anomalies and authentication failures."

    result.flags["verdict"] = verdict
    result.flags["verdict_description"] = description

    return result