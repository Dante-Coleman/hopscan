"""
Static phishing heuristics. Everything here works offline on the message
itself: no links are visited and no attachments are opened or run.
"""
import ipaddress
import re
from typing import Dict, List, Optional

from .brands import BRANDS
from .models import AnalysisResult, Link
from .scoring import add
from .utils import domains_aligned, org_domain

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "v.gd", "lnkd.in", "qrco.de",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "link", "cam", "rest", "gq", "tk", "ml", "cf", "ga", "icu",
    "sbs", "cfd", "lol", "quest", "buzz", "cyou", "monster", "support", "country", "work",
}

# Files that run code when opened.
DANGEROUS_EXTENSIONS = {
    "exe", "scr", "com", "pif", "cpl", "msi", "msix", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "hta", "lnk", "jar", "iso", "img", "vhd", "vhdx", "appx", "reg", "dll", "xll",
}
# Files often used for phishing pages, macros or HTML smuggling.
RISKY_EXTENSIONS = {
    "html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml", "one", "docm", "xlsm", "pptm", "dotm", "xlam",
}
DOCUMENT_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "csv", "rtf"}

# Wording that pressures the reader into acting fast or handing over details.
PRESSURE_PHRASES = [
    "urgent", "immediately", "within 24 hours", "within 48 hours", "action required", "final notice",
    "account suspended", "account will be suspended", "account has been suspended", "account has been locked",
    "account will be closed", "unusual activity", "unusual sign-in", "suspicious activity",
    "verify your account", "verify your identity", "confirm your account", "confirm your identity",
    "update your payment", "update your billing", "payment failed", "payment declined",
    "password expires", "password will expire", "password has expired", "reset your password",
    "mailbox is full", "storage is full", "quota exceeded", "wire transfer", "gift card", "gift cards",
    "tax refund", "you have won", "claim your", "bitcoin", "outstanding invoice", "overdue invoice",
    "you have received a document", "shared a document with you", "new voicemail", "delivery failed",
    "package could not be delivered", "do not share this", "keep this confidential",
]

_EMBEDDED_ADDRESS = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
_DOMAIN_TEXT = re.compile(r"(?i)^(?:https?://)?(?:[\w-]+@)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d+)?(?:[/?#]\S*)?$")
_LOOKALIKE = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a"})


def _examples(items: List[str], limit: int = 3) -> str:
    unique = list(dict.fromkeys(items))
    shown = ", ".join(unique[:limit])
    return shown + (f" (+{len(unique) - limit} more)" if len(unique) > limit else "")


def _normalize_label(label: str) -> str:
    return label.translate(_LOOKALIKE).replace("rn", "m").replace("vv", "w")


def brand_in_domain(domain: Optional[str]) -> Optional[str]:
    """
    Return the brand a domain seems to be imitating, or None.
    A domain the brand really owns is not imitating it.
    """
    if not domain:
        return None
    domain = domain.lower()
    org = org_domain(domain)
    if any(org in info["domains"] for info in BRANDS.values()):
        return None
    labels = [p for label in domain.split(".") for p in label.split("-") if p]
    for brand, info in BRANDS.items():
        for token in info["tokens"]:
            for label in labels:
                for candidate in {label, _normalize_label(label)}:
                    if candidate == token or (len(token) >= 6 and candidate.startswith(token)):
                        return brand
    return None


def brand_in_display_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    lower = name.lower()
    for brand, info in BRANDS.items():
        for word in info["display"]:
            if re.search(rf"\b{re.escape(word)}\b", lower):
                return brand
    return None


def _brand_owns(brand: str, domain: Optional[str]) -> bool:
    return bool(domain) and org_domain(domain) in BRANDS[brand]["domains"]


def check_identity(result: AnalysisResult) -> None:
    """Checks on the From, Reply-To, and Return-Path headers."""
    from_domain = result.from_domain

    # "support@paypal.com" <attacker@example.net>
    spoofed = False
    if result.from_display_name and from_domain:
        m = _EMBEDDED_ADDRESS.search(result.from_display_name)
        if m and not domains_aligned(m.group(1).lower(), from_domain):
            spoofed = True
            add(result, "display_name_spoof",
                f"Display name shows {m.group(0)} but the real address is at {from_domain}.", "identity")

    # "PayPal Support" <help@random-shop.example>
    brand = brand_in_display_name(result.from_display_name)
    if brand and not spoofed and from_domain and not _brand_owns(brand, from_domain):
        add(result, "brand_display_name",
            f'Display name "{result.from_display_name}" suggests {brand}, but the email is from {from_domain}.',
            "identity")

    if from_domain:
        lookalike = brand_in_domain(from_domain)
        if lookalike:
            add(result, "lookalike_from_domain",
                f"From domain {from_domain} looks like {lookalike} but isn't one of its domains.", "identity")
        if any(label.startswith("xn--") for label in from_domain.split(".")):
            add(result, "punycode_from_domain",
                f"From domain {from_domain} uses punycode, which can hide look-alike characters.", "identity")

    if result.reply_to_domain and from_domain and not domains_aligned(result.reply_to_domain, from_domain):
        add(result, "reply_to_mismatch",
            f"Replies go to {result.reply_to_domain}, not the From domain {from_domain}.", "identity")

    # Email services often use their own bounce domain, which is fine when DMARC passes.
    if (result.auth_results.dmarc != "pass" and result.return_path_domain and from_domain
            and not domains_aligned(result.return_path_domain, from_domain)):
        add(result, "return_path_mismatch",
            f"Return-Path domain {result.return_path_domain} doesn't match From domain {from_domain}.", "identity")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def check_links(result: AnalysisResult) -> None:
    hits: Dict[str, List[str]] = {}

    def hit(name: str, example: str):
        hits.setdefault(name, []).append(example)

    for link in result.content.links:
        host = link.host
        if not host:
            continue
        if link.source == "html" and link.text:
            m = _DOMAIN_TEXT.match(link.text.strip())
            if m and not domains_aligned(m.group(1).lower(), host):
                hit("link_text_mismatch", f"{m.group(1).lower()} -> {host}")
        if _is_ip(host):
            hit("ip_url", host)
        if any(label.startswith("xn--") for label in host.split(".")):
            hit("punycode_url", host)
        if link.has_userinfo:
            hit("userinfo_url", link.url[:80])
        if org_domain(host) in SHORTENERS:
            hit("shortener_url", host)
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            hit("suspicious_tld_url", host)
        brand = brand_in_domain(host)
        if brand:
            hit("brand_lookalike_link", f"{host} ({brand})")

    descriptions = {
        "link_text_mismatch": "Link text shows one site but the link goes to another: {}.",
        "brand_lookalike_link": "Links to look-alike domains of well-known brands: {}.",
        "ip_url": "Links point straight to an IP address instead of a domain: {}.",
        "punycode_url": "Links use punycode domains, which can hide look-alike characters: {}.",
        "userinfo_url": "Links hide the real destination after an @ sign: {}.",
        "shortener_url": "Links use URL shorteners that hide the destination: {}.",
        "suspicious_tld_url": "Links use domain endings popular with phishing sites: {}.",
    }
    for name, template in descriptions.items():
        if name in hits:
            add(result, name, template.format(_examples(hits[name])), "links")


def check_html(result: AnalysisResult) -> None:
    c = result.content
    if c.has_form and c.has_password_field:
        add(result, "credential_form", "The email contains a form with a password field.", "content")
    elif c.has_form:
        add(result, "html_form", "The email contains a fill-in form; legitimate emails rarely do.", "content")
    if c.has_script:
        add(result, "script", "The email contains JavaScript.", "content")
    if c.has_meta_refresh:
        add(result, "meta_refresh", "The email's HTML tries to redirect to another page automatically.", "content")


def _extensions(filename: str) -> List[str]:
    parts = filename.lower().strip().rstrip(".").split(".")
    return [p.strip() for p in parts[1:]]


def check_attachments(result: AnalysisResult) -> None:
    dangerous, risky, double, encrypted = [], [], [], []
    for att in result.content.attachments:
        names = [att.filename] + [f"{att.filename} > {m}" for m in att.archive_members]
        for name in names:
            exts = _extensions(name.rsplit(" > ", 1)[-1])
            if not exts:
                continue
            final = exts[-1]
            if final in DANGEROUS_EXTENSIONS:
                dangerous.append(name)
            elif final in RISKY_EXTENSIONS:
                risky.append(name)
            if len(exts) >= 2 and exts[-2] in DOCUMENT_EXTENSIONS and final not in DOCUMENT_EXTENSIONS:
                double.append(name)
        if att.encrypted:
            encrypted.append(att.filename)

    if dangerous:
        add(result, "dangerous_attachment",
            f"Attachment can run code when opened: {_examples(dangerous)}.", "attachments")
    if double:
        add(result, "double_extension",
            f"Attachment name disguises its real file type: {_examples(double)}.", "attachments")
    if risky:
        add(result, "risky_attachment",
            f"Attachment type is often used for phishing pages or macros: {_examples(risky)}.", "attachments")
    if encrypted:
        password_hint = " The email text mentions a password." if "password" in result.content.text.lower() else ""
        add(result, "encrypted_archive",
            f"Password-protected archive, which hides its contents from scanners: {_examples(encrypted)}."
            + password_hint, "attachments")


def check_wording(result: AnalysisResult) -> None:
    text = " ".join(f"{result.subject or ''} {result.content.text}".lower().split())
    found = [p for p in PRESSURE_PHRASES if re.search(rf"\b{re.escape(p)}\b", text)]
    if len(found) >= 4:
        add(result, "pressure_language_strong",
            f"Heavy use of pressure or credential wording: {_examples(found, 5)}.", "content")
    elif len(found) >= 2:
        add(result, "pressure_language",
            f"Uses pressure or credential wording: {_examples(found, 5)}.", "content")


def run_heuristics(result: AnalysisResult) -> None:
    check_identity(result)
    check_links(result)
    check_html(result)
    check_attachments(result)
    check_wording(result)
