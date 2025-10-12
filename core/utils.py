import re
import socket
from email.header import decode_header as _decode_header
from email.utils import parsedate_to_datetime, parseaddr
from typing import List, Optional, Tuple
from datetime import datetime

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