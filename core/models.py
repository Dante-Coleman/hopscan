from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class Header:
    name: str
    value: str


@dataclass
class IPInfo:
    """One IP address seen in a Received header, plus any lookup data."""
    ip: str
    version: int
    is_public: bool
    city: Optional[str] = None
    country: Optional[str] = None
    asn_num: Optional[int] = None
    asn_org: Optional[str] = None
    asn_tier: Optional[int] = None


@dataclass
class ReceivedHop:
    raw: str
    index: int  # 0 = topmost header = the most recent hop.
    ips: List[IPInfo] = field(default_factory=list)
    timestamp: Optional[datetime] = None

    @property
    def public_ips(self) -> List[IPInfo]:
        return [i for i in self.ips if i.is_public]

    @property
    def non_public_ips(self) -> List[IPInfo]:
        return [i for i in self.ips if not i.is_public]


@dataclass
class DkimResult:
    result: str
    domain: Optional[str] = None  # header.d=


@dataclass
class AuthResults:
    """Results from the Authentication-Results header(s) we chose to trust."""
    authserv_id: Optional[str] = None
    spf: Optional[str] = None
    spf_domain: Optional[str] = None  # smtp.mailfrom=
    dkim: List[DkimResult] = field(default_factory=list)
    dmarc: Optional[str] = None
    dmarc_domain: Optional[str] = None  # header.from=
    trusted: bool = False  # False when no header was usable.
    ignored_headers: int = 0  # Authentication-Results headers we did not trust.
    raw: List[str] = field(default_factory=list)

    @property
    def dkim_summary(self) -> Optional[str]:
        """'pass' if any signature passed, else 'fail' if any failed, else the first result."""
        results = [d.result for d in self.dkim]
        if not results:
            return None
        if "pass" in results:
            return "pass"
        if "fail" in results:
            return "fail"
        return results[0]


@dataclass
class Finding:
    """One scored observation, so the verdict can explain itself."""
    name: str
    points: int
    detail: str


@dataclass
class AnalysisResult:
    headers: List[Header] = field(default_factory=list)
    received_hops: List[ReceivedHop] = field(default_factory=list)
    from_domain: Optional[str] = None
    from_display_name: Optional[str] = None
    return_path_domain: Optional[str] = None
    reply_to_domain: Optional[str] = None
    sender_domain: Optional[str] = None
    auth_results: AuthResults = field(default_factory=AuthResults)
    time_travel: bool = False
    findings: List[Finding] = field(default_factory=list)
    score: int = 0
    verdict: str = ""
    verdict_level: str = ""  # good / ok / warn / bad / severe
    verdict_description: str = ""
