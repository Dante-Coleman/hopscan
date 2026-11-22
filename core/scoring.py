"""Point values for every finding. Negative = suspicious, positive = reassuring, 0 = informational."""
from .models import AnalysisResult, Finding

SCORES = {
    # Authentication
    "no_auth_results": -10,
    "spf_pass_aligned": +5,
    "spf_pass_unaligned": 0,
    "spf_softfail": -5,
    "spf_fail": -15,
    "spf_none": -3,
    "spf_error": -3,
    "dkim_pass_aligned": +5,
    "dkim_pass_unaligned": 0,
    "dkim_fail": -15,
    "dkim_none": -3,
    "dmarc_pass": +10,
    "dmarc_fail": -30,
    "dmarc_none": -5,
    "dmarc_error": -5,
    # Sender identity
    "display_name_spoof": -25,
    "brand_display_name": -20,
    "lookalike_from_domain": -20,
    "punycode_from_domain": -15,
    "reply_to_mismatch": -10,
    "return_path_mismatch": -5,
    # Route
    "time_travel": -10,
    # Links
    "link_text_mismatch": -10,
    "brand_lookalike_link": -15,
    "ip_url": -10,
    "punycode_url": -10,
    "userinfo_url": -10,
    "shortener_url": -5,
    "suspicious_tld_url": -5,
    # HTML
    "credential_form": -20,
    "html_form": -10,
    "script": -5,
    "meta_refresh": -5,
    # Attachments
    "dangerous_attachment": -30,
    "double_extension": -20,
    "risky_attachment": -15,
    "encrypted_archive": -15,
    # Wording
    "pressure_language_strong": -10,
    "pressure_language": -5,
}

# A finding this bad in one of these categories means the message can't be
# called safe, no matter how well it authenticates. Attackers can pass SPF,
# DKIM and DMARC for domains they own.
CAP_CATEGORIES = {"identity", "links", "attachments", "content"}
CAP_THRESHOLD = -15


def add(result: AnalysisResult, name: str, detail: str, category: str) -> None:
    result.findings.append(Finding(name=name, points=SCORES[name], detail=detail, category=category))
