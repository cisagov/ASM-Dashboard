# Standard Python Libraries
from datetime import datetime
from typing import Any, Dict, List, Optional

# Third-Party Libraries
from pydantic import BaseModel


# Reusing the previously defined models
class ServiceStat(BaseModel):
    id: str
    value: int
    label: str


class PortStat(BaseModel):
    id: int
    value: int
    label: str


class VulnerabilityStat(BaseModel):
    id: str
    value: int
    label: str


class SeverityCountStat(BaseModel):
    id: str
    value: int
    label: str


class Domain(BaseModel):
    id: str
    createdAt: datetime
    updatedAt: datetime
    syncedAt: Optional[datetime]
    ip: Optional[str]
    fromRootDomain: Optional[str]
    subdomainSource: Optional[str]
    ipOnly: Optional[bool]
    reverseName: Optional[str]
    name: Optional[str]
    screenshot: Optional[str]
    country: Optional[str]
    asn: Optional[str]
    cloudHosted: Optional[bool]
    fromCidr: Optional[bool]
    isFceb: Optional[bool]
    ssl: Optional[dict]
    censysCertificatesResults: Optional[dict]
    trustymailResults: Optional[dict]


class LatestVulnerability(BaseModel):
    id: str
    createdAt: datetime
    updatedAt: datetime
    lastSeen: Optional[datetime]
    title: str
    cve: Optional[str]
    cwe: Optional[str]
    cpe: Optional[str]
    description: Optional[str]
    references: List[str]
    cvss: Optional[float]
    severity: Optional[str]
    needsPopulation: bool
    state: str
    substate: str
    source: str
    notes: Optional[str]
    actions: List[dict]
    structuredData: dict
    isKev: bool
    kevResults: dict
    domain: Domain


class MostCommonVulnerability(BaseModel):
    title: str
    description: str
    severity: Optional[str]
    count: int


class ByOrgStat(BaseModel):
    id: str
    orgId: str
    value: int
    label: str


# Main StatsResponse model
class StatsResponse(BaseModel):
    result: Dict[str, Any] = {
        "domains": {
            "services": List[ServiceStat],
            "ports": List[PortStat],
            "numVulnerabilities": List[VulnerabilityStat],
            "total": int,
        },
        "vulnerabilities": {
            "severity": List[SeverityCountStat],
            "latestVulnerabilities": List[LatestVulnerability],
            "mostCommonVulnerabilities": List[MostCommonVulnerability],
            "byOrg": List[ByOrgStat],
        },
    }
