import re
from datetime import timedelta
from typing import Iterable, List, Optional

from .asn_tiers import asn_tiers
from .content import extract_content
from .heuristics import run_heuristics
from .models import AnalysisResult, AuthResults, DkimResult, ReceivedHop
from .scoring import CAP_CATEGORIES, CAP_THRESHOLD, add
from .utils import GeoLookup, decode_header, domains_aligned, extract_domain_from_address, parse_address

# Receiving servers' clocks are rarely perfectly in sync, so small backwards
# jumps between hops are normal and are not flagged.
TIME_TRAVEL_TOLERANCE = timedelta(minutes=5)

VERDICTS = [
    # (minimum score, level, verdict, description)
    (15, "good", "High Confidence: Legitimate",
     "Authentication passed, is aligned with the From domain, and no phishing indicators were found. "
     "Still make sure that domain is one you expect."),
    (0, "ok", "Likely Safe",
     "No critical issues, but some authentication is missing or weak."),
    (-20, "warn", "Suspicious",
     "Failed or missing authentication, or phishing indicators were found. Be careful with links and attachments."),
    (-40, "bad", "Likely Risky",
     "Several authentication problems or phishing indicators. Don't click links or open attachments."),
    (None, "severe", "High Confidence: Fraudulent",
     "Strong signs of spoofing or phishing. Don't interact with this email; report or delete it."),
]
_CAPPED_LEVEL = "warn"


def detect_time_travel(hops: List[ReceivedHop], tolerance: timedelta = TIME_TRAVEL_TOLERANCE) -> Optional[timedelta]:
    """
    Hops are listed newest first, so each hop should be later than the one below it.
    Returns the largest backwards jump beyond the tolerance, or None.
    """
    worst = None
    for newer, older in zip(hops, hops[1:]):
        if newer.timestamp and older.timestamp:
            gap = older.timestamp - newer.timestamp
            if gap > tolerance and (worst is None or gap > worst):
                worst = gap
    return worst


def _strip_comments(text: str) -> str:
    """Remove RFC 5322 (comments), including nested ones."""
    previous = None
    while previous != text:
        previous = text
        text = re.sub(r"\([^()]*\)", " ", text)
    return text


_METHOD = re.compile(r"^\s*([a-z0-9_-]+)\s*=\s*([a-z0-9_-]+)")
_PROPERTY = re.compile(r"\b([a-z]+)\.([a-z0-9_-]+)\s*=\s*\"?([^\s;\"]+)")


def parse_auth_header(value: str) -> AuthResults:
    """Parse one Authentication-Results header (RFC 8601)."""
    auth = AuthResults(raw=[value])
    text = _strip_comments(" ".join(value.split()).lower())
    parts = [p.strip() for p in text.split(";")]
    if not parts or not parts[0]:
        return auth
    # Microsoft 365 omits the authserv-id, so the first part may already be a result.
    if _METHOD.match(parts[0]):
        results = parts
    else:
        auth.authserv_id = parts[0].split()[0]
        results = parts[1:]

    for part in results:
        m = _METHOD.match(part)
        if not m:
            continue
        method, result = m.groups()
        props = {f"{p}.{k}": v for p, k, v in _PROPERTY.findall(part)}
        if method == "spf":
            auth.spf = result
            mailfrom = props.get("smtp.mailfrom")
            auth.spf_domain = mailfrom.rsplit("@", 1)[-1] if mailfrom else props.get("smtp.helo")
        elif method == "dkim":
            domain = props.get("header.d")
            if not domain and props.get("header.i"):
                domain = props["header.i"].rsplit("@", 1)[-1]
            auth.dkim.append(DkimResult(result=result, domain=domain if domain not in (None, "", "none") else None))
        elif method == "dmarc":
            auth.dmarc = result
            auth.dmarc_domain = props.get("header.from")
    return auth


def select_auth_results(values: List[str], trusted_authserv: Iterable[str] = ()) -> AuthResults:
    """
    Choose which Authentication-Results headers to believe.

    Anyone can put an Authentication-Results header in an email before sending
    it. Only headers added by your own receiving server can be trusted:
      - with trusted_authserv given, use the headers whose authserv-id matches;
      - otherwise use only the topmost header, which the final receiving server added.
    """
    trusted_ids = {t.lower() for t in trusted_authserv}
    parsed = [parse_auth_header(v) for v in values]

    if trusted_ids:
        chosen = [p for p in parsed if p.authserv_id in trusted_ids]
    else:
        chosen = parsed[:1]

    if not chosen:
        return AuthResults(ignored_headers=len(parsed))

    merged = AuthResults(authserv_id=chosen[0].authserv_id, trusted=True,
                         ignored_headers=len(parsed) - len(chosen))
    for p in chosen:
        merged.raw.extend(p.raw)
        merged.dkim.extend(p.dkim)
        if p.spf and not merged.spf:
            merged.spf, merged.spf_domain = p.spf, p.spf_domain
        if p.dmarc and not merged.dmarc:
            merged.dmarc, merged.dmarc_domain = p.dmarc, p.dmarc_domain
    return merged


def apply_alignment(auth: AuthResults, from_domain: Optional[str]) -> None:
    """
    Alignment = the domain that passed the check is the same organization as
    the From address. A pass without alignment only proves the message came
    from *some* domain (often an email service), not from the one you see.
    """
    if auth.spf_domain:
        auth.spf_aligned = domains_aligned(auth.spf_domain, from_domain)
    for d in auth.dkim:
        d.aligned = domains_aligned(d.domain, from_domain) if d.domain else None


def enrich_hops(hops: List[ReceivedHop], geo: Optional[GeoLookup]) -> None:
    """Add location and ASN info to each public IP. ASN tier is informational only."""
    if geo is None:
        return
    for hop in hops:
        for info in hop.public_ips:
            info.city, info.country = geo.location(info.ip)
            info.asn_num, info.asn_org = geo.asn(info.ip)
            if info.asn_num is not None:
                info.asn_tier = asn_tiers.get(info.asn_num)


def score_auth(result: AnalysisResult) -> None:
    auth = result.auth_results
    if not auth.trusted:
        extra = f" ({auth.ignored_headers} untrusted header(s) ignored)" if auth.ignored_headers else ""
        add(result, "no_auth_results", "No Authentication-Results from the receiving server" + extra + ".", "auth")
        return

    spf = auth.spf or "none"
    if spf == "pass" and auth.spf_aligned:
        add(result, "spf_pass_aligned", f"SPF passed for {auth.spf_domain}, which matches the From domain.", "auth")
    elif spf == "pass":
        add(result, "spf_pass_unaligned",
            f"SPF passed for {auth.spf_domain or 'the envelope sender'}, which is not the From domain "
            f"(normal for email services).", "auth")
    elif spf == "softfail":
        add(result, "spf_softfail", "SPF softfail: the sending server isn't clearly authorized.", "auth")
    elif spf == "fail":
        add(result, "spf_fail", "SPF failed: the sending server is not authorized for the envelope domain.", "auth")
    elif spf in ("temperror", "permerror"):
        add(result, "spf_error", f"SPF {spf}: the check could not be completed.", "auth")
    else:
        add(result, "spf_none", f"SPF result was {spf}.", "auth")

    dkim = auth.dkim_summary or "none"
    aligned = [d for d in auth.dkim if d.result == "pass" and d.aligned]
    passing = [d for d in auth.dkim if d.result == "pass"]
    if aligned:
        add(result, "dkim_pass_aligned", f"DKIM signature from {aligned[0].domain} passed and matches the From domain.",
            "auth")
    elif passing:
        add(result, "dkim_pass_unaligned",
            f"DKIM signature from {passing[0].domain or 'an unknown domain'} passed, but it is not the From domain.",
            "auth")
    elif dkim == "fail":
        add(result, "dkim_fail", "DKIM signature failed: the message was altered or the signature is forged.", "auth")
    else:
        add(result, "dkim_none", f"DKIM result was {dkim}.", "auth")

    dmarc = auth.dmarc or "none"
    if dmarc == "pass":
        add(result, "dmarc_pass", f"DMARC passed for {auth.dmarc_domain or result.from_domain}.", "auth")
    elif dmarc == "fail":
        add(result, "dmarc_fail", "DMARC failed: the From domain could not be verified.", "auth")
    elif dmarc in ("temperror", "permerror"):
        add(result, "dmarc_error", f"DMARC {dmarc}: the check could not be completed.", "auth")
    else:
        add(result, "dmarc_none", f"DMARC result was {dmarc} (the From domain may have no DMARC policy).", "auth")


def decide_verdict(result: AnalysisResult) -> None:
    result.score = sum(f.points for f in result.findings)
    capped = any(f.category in CAP_CATEGORIES and f.points <= CAP_THRESHOLD for f in result.findings)
    for minimum, level, verdict, description in VERDICTS:
        if minimum is None or result.score >= minimum:
            if capped and level in ("good", "ok"):
                continue  # A strong phishing indicator outweighs good authentication.
            result.verdict_level, result.verdict, result.verdict_description = level, verdict, description
            return


def analyze_email(msg, headers: List, hops: List[ReceivedHop],
                  geo: Optional[GeoLookup] = None,
                  trusted_authserv: Iterable[str] = ()) -> AnalysisResult:
    """Main analyzer: enriches hops, scores the message, and returns an AnalysisResult."""
    result = AnalysisResult(headers=headers, received_hops=hops)

    enrich_hops(hops, geo)

    result.subject = decode_header(msg.get("Subject")) or None
    result.date = decode_header(msg.get("Date")) or None
    result.from_header = decode_header(msg.get("From")) or None
    result.from_display_name, result.from_domain = parse_address(msg.get("From"))
    result.reply_to_domain = extract_domain_from_address(msg.get("Reply-To"))
    result.return_path_domain = extract_domain_from_address(msg.get("Return-Path"))
    result.sender_domain = extract_domain_from_address(msg.get("Sender"))

    auth_values = [h.value for h in headers if h.name.lower() == "authentication-results"]
    result.auth_results = select_auth_results(auth_values, trusted_authserv)
    apply_alignment(result.auth_results, result.from_domain)
    score_auth(result)

    result.content = extract_content(msg)
    run_heuristics(result)

    gap = detect_time_travel(hops)
    if gap is not None:
        result.time_travel = True
        add(result, "time_travel",
            f"Received timestamps go backwards by {gap} (more than {TIME_TRAVEL_TOLERANCE} of clock drift).", "route")

    decide_verdict(result)
    return result
