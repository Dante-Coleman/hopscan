from email.message import Message
from typing import List

from .models import Header, IPInfo, ReceivedHop
from .utils import decode_header, extract_ips, is_public_ip, parse_email_date


def extract_headers(msg: Message) -> List[Header]:
    """Return all headers in original order. Repeated headers (Received) each appear in order."""
    return [Header(name=name, value=decode_header(value)) for name, value in msg.items()]


def extract_received_hops(msg: Message) -> List[ReceivedHop]:
    """
    Extract Received headers top to bottom as they appear in the message.
    The topmost header is the most recent hop (added by the receiving server).
    """
    hops = []
    for idx, raw in enumerate(msg.get_all("Received") or []):
        decoded = " ".join(decode_header(raw).split())  # Unfold whitespace.
        hop = ReceivedHop(raw=decoded, index=idx)
        for addr in extract_ips(decoded):
            hop.ips.append(IPInfo(ip=str(addr), version=addr.version, is_public=is_public_ip(addr)))
        # The timestamp follows the LAST semicolon (RFC 5321 section 4.4).
        if ";" in decoded:
            hop.timestamp = parse_email_date(decoded.rsplit(";", 1)[1])
        hops.append(hop)
    return hops
