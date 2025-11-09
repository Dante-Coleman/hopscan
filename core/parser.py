import re
from email.message import Message
from typing import List
from collections import OrderedDict
from .models import Header, ReceivedHop
from .utils import decode_header, extract_ipv4s, parse_email_date, is_private_ipv4


def extract_headers(msg: Message) -> List[Header]:
    """
    Return all headers in original order as a list of Header dataclasses.
    For repeated headers (Received), each appears in order.
    """
    headers = []
    for name, value in msg.items():
        decoded_value = decode_header(value)
        headers.append(Header(name=name, value=decoded_value))
    return headers

def extract_received_hops(msg: Message) -> List[ReceivedHop]:
    """
    Extract Received headers in order. Stores them top to bottom as they appear in the raw message.
    Preserves order and captures timestamps and ips found.
    """
    received = msg.get_all('Received') or []
    hops = []
    for idx, raw in enumerate(received):
        decoded = decode_header(raw)
        hop = ReceivedHop(raw=decoded, index=idx)
        ipv4s = extract_ipv4s(decoded)
        hop.ip_candidates = ipv4s
        for ip in ipv4s:
            if is_private_ipv4(ip):
                hop.private_ips.append(ip)
            else:
                hop.valid_ips.append(ip)
        m = re.search(r';\s*(.+)$', decoded)
        if m:
            date_str = m.group(1).strip()
            dt = parse_email_date(date_str)
            hop.timestamp = dt
        hops.append(hop)
    return hops