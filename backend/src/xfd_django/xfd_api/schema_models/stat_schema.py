"""Stats schema."""
# Standard Python Libraries
from datetime import datetime
from typing import Any, Dict, List, Optional

# Third-Party Libraries
from pydantic import BaseModel


# Reusing the previously defined models
class ServiceStat(BaseModel):
    """Service stat."""

    id: str
    value: int
    label: str


class PortStat(BaseModel):
    """Port stat."""

    id: int
    value: int
    label: str


class VulnerabilityStat(BaseModel):
    """Vulnerability stat."""

    id: str
    value: int
    label: str


class SeverityCountStat(BaseModel):
    """Severity count stat."""

    id: str
    value: int
    label: str


class Domain(BaseModel):
    """Domain schema."""

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
    """Latest vulnerability."""

    createdAt: datetime
    title: str
    description: Optional[str]
    severity: Optional[str]


class MostCommonVulnerability(BaseModel):
    """Most common vulnerability."""

    title: str
    description: str
    severity: Optional[str]
    count: int


class ByOrgStat(BaseModel):
    """By org stat."""

    id: str
    orgId: str
    value: int
    label: str


# Main StatsResponse model
class StatsResponse(BaseModel):
    """Stats response."""

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
