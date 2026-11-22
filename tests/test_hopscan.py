import email
import json
from email import policy
from pathlib import Path

import pytest

import hopscan
from core.analyzer import analyze_email, parse_auth_header
from core.loader import load_email
from core.parser import extract_headers, extract_received_hops
from core.utils import extract_ips, org_domain

FIXTURES = Path(__file__).parent / "fixtures"


def analyze(name, **kwargs):
    msg = load_email(str(FIXTURES / name))
    return analyze_email(msg, extract_headers(msg), extract_received_hops(msg), geo=None, **kwargs)


def names(result):
    return {f.name for f in result.findings}


# --- Regression tests for the bugs found in review ---

def test_no_auth_results_is_not_safe():
    r = analyze("no_auth.eml")
    assert "no_auth_results" in names(r)
    assert r.score < 0
    assert r.verdict == "Suspicious"


def test_forged_auth_header_below_real_one_is_ignored():
    r = analyze("forged_auth.eml")
    auth = r.auth_results
    assert auth.authserv_id == "mx.victim.com"
    assert (auth.spf, auth.dkim_summary, auth.dmarc) == ("fail", "fail", "fail")
    assert auth.ignored_headers == 1
    assert "reply_to_mismatch" in names(r)
    assert r.verdict == "High Confidence: Fraudulent"


def test_trusted_authserv_selects_matching_header():
    r = analyze("forged_auth.eml", trusted_authserv=["MX.VICTIM.COM"])
    assert r.auth_results.dmarc == "fail"
    r = analyze("forged_auth.eml", trusted_authserv=["mx.nobody.example"])
    assert not r.auth_results.trusted
    assert "no_auth_results" in names(r)


def test_small_clock_skew_is_not_time_travel():
    r = analyze("clock_skew.eml")
    assert not r.time_travel
    assert r.verdict == "High Confidence: Legitimate"


def test_large_clock_jump_is_time_travel():
    raw = (FIXTURES / "clock_skew.eml").read_text().replace("10:00:02", "11:30:00")
    msg = email.message_from_string(raw, policy=policy.default)
    r = analyze_email(msg, extract_headers(msg), extract_received_hops(msg))
    assert r.time_travel
    assert "time_travel" in names(r)


def test_bogus_and_reserved_ips():
    hops = extract_received_hops(load_email(str(FIXTURES / "bogus_ips.eml")))
    ips = [i.ip for h in hops for i in h.ips]
    assert "3.6.4.1" not in ips      # Software version, not in brackets.
    assert "999.1.1.1" not in ips    # Not a valid address.
    assert "127.0.0.1" in ips and "100.64.3.4" in ips
    assert all(not i.is_public for h in hops for i in h.ips)


def test_ipv6_extraction():
    hops = extract_received_hops(load_email(str(FIXTURES / "m365_display_spoof.eml")))
    ips = {i.ip: i.is_public for h in hops for i in h.ips}
    assert ips["2603:10b6:5:1a2::11"] is True
    assert ips["2001:db8::25"] is False  # Documentation range.
    assert "15.20.7633.27" not in ips    # Exchange build number.


# --- Realistic messages ---

def test_gmail_legit():
    r = analyze("gmail_legit.eml")
    assert (r.auth_results.spf, r.auth_results.dkim_summary, r.auth_results.dmarc) == ("pass", "pass", "pass")
    assert r.auth_results.dkim[0].domain == "gmail.com"
    assert r.verdict == "High Confidence: Legitimate"
    assert r.received_hops[1].public_ips[0].ip == "209.85.220.41"
    assert not r.time_travel


def test_m365_display_name_spoof():
    r = analyze("m365_display_spoof.eml")
    assert r.auth_results.authserv_id is None
    assert r.auth_results.spf == "pass"
    assert r.auth_results.dmarc == "none"
    assert "display_name_spoof" in names(r)
    assert r.score < -20


# --- Unit tests ---

@pytest.mark.parametrize("domain, expected", [
    ("mail.example.com", "example.com"),
    ("example.com", "example.com"),
    ("a.b.example.co.uk", "example.co.uk"),
    (None, None),
])
def test_org_domain(domain, expected):
    assert org_domain(domain) == expected


def test_auth_header_comments_and_multiple_dkim():
    a = parse_auth_header(
        "mx.example.org; dkim=fail (bad sig; really) header.d=evil.example; "
        "dkim=pass header.d=example.com; spf=softfail smtp.mailfrom=x@example.com"
    )
    assert [d.result for d in a.dkim] == ["fail", "pass"]
    assert a.dkim_summary == "pass"
    assert a.spf == "softfail" and a.spf_domain == "example.com"


def test_extract_ips_prefers_brackets():
    assert [str(i) for i in extract_ips("from x (y [203.0.113.5]) by z (Exim 4.96.1.2)")] == ["203.0.113.5"]


def test_cli_json_and_missing_file(capsys):
    assert hopscan.main([str(FIXTURES / "gmail_legit.eml"), "--json", "--no-geo"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] == "High Confidence: Legitimate"
    assert hopscan.main(["does-not-exist.eml"]) == 2


# --- Alignment ---

def test_alignment_shown_for_spf_and_dkim():
    r = analyze("newsletter_esp.eml")
    auth = r.auth_results
    assert auth.spf == "pass" and auth.spf_aligned is False
    assert {d.domain: d.aligned for d in auth.dkim} == {"example-shop.com": True, "sendgrid.info": False}
    assert auth.dkim_aligned is True
    assert "spf_pass_unaligned" in names(r)
    assert r.verdict == "High Confidence: Legitimate"  # ESP click-tracking links aren't flagged.


def test_gmail_spf_aligned():
    r = analyze("gmail_legit.eml")
    assert r.auth_results.spf_aligned is True
    assert "spf_pass_aligned" in names(r)


# --- Phishing heuristics ---

def test_phishing_heuristics():
    r = analyze("phish_credential.eml")
    expected = {
        "brand_display_name", "lookalike_from_domain", "reply_to_mismatch",
        "link_text_mismatch", "brand_lookalike_link", "ip_url", "shortener_url", "suspicious_tld_url",
        "credential_form", "dangerous_attachment", "double_extension", "risky_attachment",
        "encrypted_archive", "pressure_language_strong",
    }
    assert expected <= names(r)
    assert r.verdict == "High Confidence: Fraudulent"


def test_strong_indicator_caps_verdict_despite_passing_auth():
    msg = load_email(str(FIXTURES / "gmail_legit.eml"))
    msg.make_mixed()
    msg.add_attachment(b"<html></html>", maintype="text", subtype="html", filename="invoice.html")
    r = analyze_email(msg, extract_headers(msg), extract_received_hops(msg))
    assert r.score > 0  # Authentication (+20) outweighs the attachment (-15) on points...
    assert r.verdict == "Suspicious"  # ...but a strong phishing indicator caps the verdict.


@pytest.mark.parametrize("domain, brand", [
    ("paypal.com", None),
    ("paypal-secure.example", "PayPal"),
    ("paypa1.example", "PayPal"),
    ("rnicrosoft-login.example", "Microsoft"),
    ("ups-delivery.example", "UPS"),
    ("groups.example", None),
    ("pineapple.example", None),
    ("youtube.com", None),
    ("mail.google.com", None),
])
def test_brand_in_domain(domain, brand):
    from core.heuristics import brand_in_domain
    assert brand_in_domain(domain) == brand


def test_plain_names_are_not_brands():
    from core.heuristics import brand_in_display_name
    assert brand_in_display_name("Chase Miller") is None
    assert brand_in_display_name("Microsoft Account Team") == "Microsoft"


def test_cli_report_runs(capsys):
    assert hopscan.main([str(FIXTURES / "phish_credential.eml"), "--no-geo", "-v"]) == 0
    out = capsys.readouterr().out
    assert "VERDICT" in out and "ALL HEADERS" in out and "aligned with From" in out
