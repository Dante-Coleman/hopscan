import ipaddress
import os
import re
import sys
from datetime import datetime
from email.header import decode_header as _decode_header
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path
from typing import List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_DIR = ROOT_DIR / "databases"

# Received headers record the connecting IP in square brackets, e.g.
# "(mail.example.com [203.0.113.5])", or (Microsoft) alone in parentheses,
# e.g. "(2603:10b6:5:1a2::11)". Parentheses can also hold software versions
# like "(Postfix 3.6.4.1)", so a parenthesized IP must be the whole group.
_IP_GROUP = re.compile(r"\[([^\[\]]*)\]|\(\s*([0-9A-Fa-f:.]+)\s*\)")
_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
_IPV6 = re.compile(r"(?<![\w:.])((?:IPv6:)?[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:\d{1,3}(?:\.\d{1,3}){3})?)(?![\w:.])")


def _candidates(text: str) -> List[str]:
    found = []
    for match in _IPV4.finditer(text):
        found.append(match.group(1))
    for match in _IPV6.finditer(text):
        token = match.group(1)
        if token.startswith("IPv6:"):
            token = token[5:]
        found.append(token)
    return found


def extract_ips(text: str) -> List[ipaddress._BaseAddress]:
    """
    Find IPv4 and IPv6 addresses in a Received header.

    Addresses in [brackets], or alone in (parentheses), are preferred because
    that is where MTAs record the connecting IP. Bare dotted strings elsewhere are often
    software versions (e.g. "Postfix 3.6.4.1"), so they are only used when no
    bracketed address exists.

    Returns unique, syntactically valid addresses in order of appearance.
    """
    groups = [square or paren for square, paren in _IP_GROUP.findall(text)]
    bracketed = [c for group in groups for c in _candidates(group)]
    raw = bracketed if bracketed else _candidates(text)

    seen = set()
    result = []
    for token in raw:
        try:
            addr = ipaddress.ip_address(token)
        except ValueError:
            continue
        if addr.is_unspecified or addr in seen:
            continue
        seen.add(addr)
        result.append(addr)
    return result


def is_public_ip(addr: ipaddress._BaseAddress) -> bool:
    """True for globally routable addresses (excludes private, loopback, link-local, CGNAT, etc.)."""
    return addr.is_global and not addr.is_multicast


class GeoLookup:
    """
    Wraps the MaxMind GeoLite2 City and ASN databases.

    Each database is opened once and reused. If geoip2 or a database file is
    missing, lookups return None instead of failing.
    """

    def __init__(self, db_dir: Optional[Path] = None):
        db_dir = Path(db_dir or os.environ.get("HOPSCAN_DB_DIR") or DEFAULT_DB_DIR)
        self.city_path = _find_db(db_dir, "GeoLite2-City")
        self.asn_path = _find_db(db_dir, "GeoLite2-ASN")
        self._city = self._open(self.city_path)
        self._asn = self._open(self.asn_path)

    @staticmethod
    def _open(path: Optional[Path]):
        if path is None:
            return None
        try:
            import geoip2.database
            return geoip2.database.Reader(str(path))
        except Exception as exc:  # Missing package or corrupt file.
            print(f"warning: could not open {path}: {exc}", file=sys.stderr)
            return None

    @property
    def available(self) -> bool:
        return self._city is not None or self._asn is not None

    def location(self, ip: str) -> Tuple[Optional[str], Optional[str]]:
        """Returns (city, country)."""
        if self._city is None:
            return None, None
        try:
            r = self._city.city(ip)
            return r.city.name or None, r.country.name or None
        except Exception:
            return None, None

    def asn(self, ip: str) -> Tuple[Optional[int], Optional[str]]:
        """Returns (asn_number, asn_organization)."""
        if self._asn is None:
            return None, None
        try:
            r = self._asn.asn(ip)
            return r.autonomous_system_number, r.autonomous_system_organization
        except Exception:
            return None, None

    def close(self):
        for reader in (self._city, self._asn):
            if reader is not None:
                reader.close()


def _find_db(db_dir: Path, edition: str) -> Optional[Path]:
    """
    Find the newest <edition>.mmdb under db_dir. Handles both MaxMind's dated
    folders (GeoLite2-City_20251028/GeoLite2-City.mmdb) and a flat layout.
    """
    if not db_dir.is_dir():
        return None
    matches = sorted(db_dir.glob(f"{edition}*/{edition}.mmdb")) + sorted(db_dir.glob(f"{edition}.mmdb"))
    return matches[-1] if matches else None


def decode_header(value: str) -> str:
    """Decode an RFC 2047 encoded-word header value (handles multi-part values)."""
    if value is None:
        return ""
    parts = _decode_header(str(value))
    out = []
    for bytes_or_str, encoding in parts:
        if isinstance(bytes_or_str, bytes):
            try:
                out.append(bytes_or_str.decode(encoding or "utf-8", errors="replace"))
            except LookupError:
                out.append(bytes_or_str.decode("utf-8", errors="replace"))
        else:
            out.append(bytes_or_str)
    return "".join(out).strip()


def parse_email_date(date_str: str) -> Optional[datetime]:
    """Parse an RFC 5322 date string. Returns None if it can't be parsed or has no timezone."""
    if not date_str:
        return None
    try:
        dt = parsedate_to_datetime(date_str.strip())
    except (TypeError, ValueError, IndexError):
        return None
    if dt.tzinfo is None:
        return None  # Can't compare naive and aware datetimes safely.
    return dt


def parse_address(addr: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Returns (display_name, domain) from an address header like From: or Reply-To:."""
    if not addr:
        return None, None
    name, email_addr = parseaddr(str(addr))
    domain = email_addr.rsplit("@", 1)[-1].lower().rstrip(">") if "@" in email_addr else None
    return (name or None), (domain or None)


def extract_domain_from_address(addr: Optional[str]) -> Optional[str]:
    """Return the domain from an RFC 5322 address string (From:, Reply-To:, etc.)."""
    return parse_address(addr)[1]


# Common multi-label public suffixes. This is an approximation of the Public
# Suffix List, which is what DMARC really uses to find the organizational domain.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "co.kr", "co.in", "co.za",
    "com.br", "com.mx", "com.ar", "com.cn", "com.hk", "com.sg", "com.tr", "com.tw",
}


def org_domain(domain: Optional[str]) -> Optional[str]:
    """Approximate organizational domain: mail.example.co.uk -> example.co.uk."""
    if not domain:
        return None
    labels = domain.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def domains_aligned(a: Optional[str], b: Optional[str]) -> bool:
    """DMARC-style relaxed alignment: same organizational domain."""
    return bool(a and b) and org_domain(a) == org_domain(b)
