import re
from datetime import timedelta
from typing import Iterable, List, Optional

from .asn_tiers import asn_tiers
from .models import AnalysisResult, AuthResults, DkimResult, Finding, ReceivedHop
from .utils import GeoLookup, domains_aligned, extract_domain_from_address, org_domain, parse_address

# Receiving servers' clocks are rarely perfectly in sync, so small backwards
# jumps between hops are normal and are not flagged.
TIME_TRAVEL_TOLERANCE = timedelta(minutes=5)

SCORES = {
    "no_auth_results": -10,
    "spf_pass": +5,
    "spf_softfail": -5,
    "spf_fail": -15,
    "spf_none": -3,
    "spf_error": -3,
    "dkim_pass_aligned": +5,
    "dkim_fail": -15,
    "dkim_none": -3,
    "dmarc_pass": +10,
    "dmarc_fail": -30,
    "dmarc_none": -5,
    "dmarc_error": -5,
    "display_name_spoof": -25,
    "reply_to_mismatch": -10,
    "return_path_mismatch": -5,
    "time_travel": -10,
}

VERDICTS = [
    # (minimum score, level, verdict, description)
    (15, "good", "High Confidence: Legitimate",
     "Authentication passed and is aligned with the From domain. Still make sure that domain is one you expect."),
    (0, "ok", "Likely Safe",
     "No critical issues, but some authentication is missing or weak."),
    (-20, "warn", "Suspicious",
     "Missing or failed authentication, or mild anomalies detected."),
    (-40, "bad", "Likely Risky",
     "Multiple authentication problems or header inconsistencies."),
    (None, "severe", "High Confidence: Fraudulent",
     "Authentication failures combined with signs of spoofing."),
]


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


def _add(result: AnalysisResult, name: str, detail: str) -> None:
    result.findings.append(Finding(name=name, points=SCORES[name], detail=detail))


def score_auth(result: AnalysisResult) -> None:
    auth = result.auth_results
    if not auth.trusted:
        extra = f" ({auth.ignored_headers} untrusted header(s) ignored)" if auth.ignored_headers else ""
        _add(result, "no_auth_results", "No Authentication-Results from the receiving server" + extra + ".")
        return

    spf = auth.spf or "none"
    if spf == "pass":
        _add(result, "spf_pass", f"SPF passed for {auth.spf_domain or 'the envelope sender'}.")
    elif spf == "softfail":
        _add(result, "spf_softfail", "SPF softfail: the sending server isn't clearly authorized.")
    elif spf == "fail":
        _add(result, "spf_fail", "SPF failed: the sending server is not authorized for the envelope domain.")
    elif spf in ("temperror", "permerror"):
        _add(result, "spf_error", f"SPF {spf}: the check could not be completed.")
    else:
        _add(result, "spf_none", f"SPF result was {spf}.")

    dkim = auth.dkim_summary or "none"
    aligned = [d for d in auth.dkim if d.result == "pass" and domains_aligned(d.domain, result.from_domain)]
    if aligned:
        _add(result, "dkim_pass_aligned", f"DKIM signature from {aligned[0].domain} passed and matches the From domain.")
    elif dkim == "fail":
        _add(result, "dkim_fail", "DKIM signature failed: the message was altered or the signature is forged.")
    elif dkim != "pass":
        _add(result, "dkim_none", f"DKIM result was {dkim}.")
    # A passing but unaligned DKIM signature (e.g. an email service's own domain) scores nothing.

    dmarc = auth.dmarc or "none"
    if dmarc == "pass":
        _add(result, "dmarc_pass", f"DMARC passed for {auth.dmarc_domain or result.from_domain}.")
    elif dmarc == "fail":
        _add(result, "dmarc_fail", "DMARC failed: the From domain could not be verified.")
    elif dmarc in ("temperror", "permerror"):
        _add(result, "dmarc_error", f"DMARC {dmarc}: the check could not be completed.")
    else:
        _add(result, "dmarc_none", f"DMARC result was {dmarc} (the From domain may have no DMARC policy).")


_EMBEDDED_ADDRESS = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")


def score_identity(result: AnalysisResult) -> None:
    """Checks on the From, Reply-To, and Return-Path headers."""
    from_domain = result.from_domain

    # "support@paypal.com" <attacker@example.net>
    if result.from_display_name and from_domain:
        m = _EMBEDDED_ADDRESS.search(result.from_display_name)
        if m and not domains_aligned(m.group(1).lower(), from_domain):
            _add(result, "display_name_spoof",
                 f"Display name shows {m.group(0)} but the real address is at {from_domain}.")

    if result.reply_to_domain and from_domain and not domains_aligned(result.reply_to_domain, from_domain):
        _add(result, "reply_to_mismatch",
             f"Replies go to {result.reply_to_domain}, not the From domain {from_domain}.")

    # Email services often use their own bounce domain, which is fine when DMARC passes.
    if (result.auth_results.dmarc != "pass" and result.return_path_domain and from_domain
            and not domains_aligned(result.return_path_domain, from_domain)):
        _add(result, "return_path_mismatch",
             f"Return-Path domain {result.return_path_domain} doesn't match From domain {from_domain}.")


def decide_verdict(result: AnalysisResult) -> None:
    result.score = sum(f.points for f in result.findings)
    for minimum, level, verdict, description in VERDICTS:
        if minimum is None or result.score >= minimum:
            result.verdict_level, result.verdict, result.verdict_description = level, verdict, description
            return


def analyze_email(msg, headers: List, hops: List[ReceivedHop],
                  geo: Optional[GeoLookup] = None,
                  trusted_authserv: Iterable[str] = ()) -> AnalysisResult:
    """Main analyzer: enriches hops, scores the message, and returns an AnalysisResult."""
    result = AnalysisResult(headers=headers, received_hops=hops)

    enrich_hops(hops, geo)

    result.from_display_name, result.from_domain = parse_address(msg.get("From"))
    result.reply_to_domain = extract_domain_from_address(msg.get("Reply-To"))
    result.return_path_domain = extract_domain_from_address(msg.get("Return-Path"))
    result.sender_domain = extract_domain_from_address(msg.get("Sender"))

    auth_values = [h.value for h in headers if h.name.lower() == "authentication-results"]
    result.auth_results = select_auth_results(auth_values, trusted_authserv)

    score_auth(result)
    score_identity(result)

    gap = detect_time_travel(hops)
    if gap is not None:
        result.time_travel = True
        _add(result, "time_travel",
             f"Received timestamps go backwards by {gap} (more than {TIME_TRAVEL_TOLERANCE} of clock drift).")

    decide_verdict(result)
    return result
