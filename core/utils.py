import re
import socket
import geoip2.database
from datetime import datetime
from typing import List, Optional, Tuple
from pathlib import Path
from email.header import decode_header as _decode_header
from email.utils import parsedate_to_datetime, parseaddr

def extract_ipv4s(text: str) -> list[str]:
    """
    Find potential IPv4 addresses.

    text: Input text to search for IPv4 addresses.

    Returns: List of strings of potential IPv4 addresses.
    """
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    return pattern.findall(text)

def is_valid_ipv4(ip: str) -> bool:
    """
    Validate if given string is a valid IPv4 address.

    ip: IPv4 address string to validate.

    Returns: True if valid, False if invalid.
    """
    try:
        socket.inet_aton(ip)
        octets = ip.split('.')
        if len(octets) != 4:
            return False
        return all(0 <= int(octet) <= 255 for octet in octets)
    except (OSError, ValueError):
        return False

current_dir = Path(__file__).parent
root_dir = current_dir.parent
db_city_path = root_dir / "databases" / "GeoLite2-City_20251028" / "GeoLite2-City.mmdb"
db_country_path = root_dir / "databases" / "GeoLite2-Country_20251028" / "GeoLite2-Country.mmdb"
db_asn_path = root_dir / "databases" / "GeoLite2-ASN_20251101" / "GeoLite2-ASN.mmdb"

def get_valid_ipv4_geolocation(ip: str) -> Optional[tuple]:
    for valid_ip in [ip]:
        try:
            with geoip2.database.Reader(db_city_path) as city_reader:
                city_response = city_reader.city(valid_ip)
                city = city_response.city.name or None
            with geoip2.database.Reader(db_country_path) as country_reader:
                country_response = country_reader.country(valid_ip)
                country = country_response.country.name or None
            return city, country
        except Exception:
            continue

def get_valid_ipv4_asn(ip: str) -> Optional[str]:
    for valid_ip in [ip]:
        try:
            with geoip2.database.Reader(db_asn_path) as asn_reader:
                asn_response = asn_reader.asn(valid_ip)
                asn = asn_response.autonomous_system_organization
                return str(asn)
        except Exception:
            continue
    
def is_private_ipv4(addr: str) -> bool:
    """Detect RFC1918 private IPv4 ranges."""
    try:
        parts = [int(p) for p in addr.split('.')]
        a, b = parts[0], parts[1]
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        return False
    except Exception:
        return False

def decode_header(value: str) -> str:
    """
    Decode an RFC2047 encoded-word header (handles multi-part decode).
    """
    if value is None:
        return ""
    parts = _decode_header(value)
    out = []
    for bytes_or_str, encoding in parts:
        if isinstance(bytes_or_str, bytes):
            try:
                out.append(bytes_or_str.decode(encoding or 'utf-8', errors='replace'))
            except Exception:
                out.append(bytes_or_str.decode('utf-8', errors='replace'))
        else:
            out.append(bytes_or_str)
    return ''.join(out).strip() 

def parse_email_date(date_str: str) -> Optional[datetime]:
    """Safely parse email date strings to datetime (UTC-aware if available)."""
    if not date_str:
        return None
    try:
        dt = parsedate_to_datetime(date_str)
        return dt
    except (TypeError, ValueError, IndexError):
        return None
    
def extract_domain_from_address(addr: str) -> Optional[str]:
    """Return domain from an RFC5322 address string (From:, Reply-To:, etc.)."""
    if not addr:
        return None
    name, email_addr = parseaddr(addr)
    if not email_addr:
        return None
    if '@' in email_addr:
        return email_addr.split('@')[-1].lower()
    return None