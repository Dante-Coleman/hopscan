from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any

@dataclass
class Header:
    name: str
    value: str

@dataclass
class ReceivedHop:
    raw: str
    index: int
    ip_candidates: List[str] = field(default_factory=list)
    valid_ips: List[str] = field(default_factory=list)
    private_ips: List[str] = field(default_factory=list)
    invalid_ips: List[str] = field(default_factory=list)
    timestamp: Optional[datetime] = None
    city: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None

@dataclass
class AuthResults:
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    raw: List[str] = field(default_factory=list)

@dataclass
class AnalysisResult:
    headers: List[Header] = field(default_factory=list)
    received_hops: List[ReceivedHop] = field(default_factory=list)
    from_domain: Optional[str] = None
    return_path_domain: Optional[str] = None
    reply_to_domain: Optional[str] = None
    sender_domain: Optional[str] = None
    auth_results: AuthResults = field(default_factory=AuthResults)
    flags: Dict[str, Any] = field(default_factory=dict)
    score: int = 0