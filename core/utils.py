import re
import socket

def extract_ipv4_addresses(text: str) -> list[str]:
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
