"""Domain schema."""
# Third-Party Libraries
# from pydantic.types import UUID1, UUID
# Standard Python Libraries
from datetime import datetime
from typing import Any, List, Optional
from uuid import UUID

# Third-Party Libraries
from pydantic import BaseModel, Field


class Domain(BaseModel):
    """Domain schema."""

    id: UUID
    createdAt: datetime
    updatedAt: datetime
    syncedAt: Optional[datetime] = None
    ip: str
    fromRootDomain: Optional[str]
    subdomainSource: Optional[str]
    ipOnly: bool
    reverseName: Optional[str]
    name: Optional[str]
    screenshot: Optional[str]
    country: Optional[str]
    asn: Optional[str]
    cloudHosted: bool
    ssl: Optional[Any]
    censysCertificatesResults: Optional[dict]
    trustymailResults: Optional[dict]
    discoveredBy_id: Optional[UUID]
    organization_id: Optional[UUID]
    isFceb: Optional[bool]
    fromCidr: Optional[bool]

    class Config:
        """Domain base schema config."""

        from_attributes = True
        validate_assignment = True


class DomainFilters(BaseModel):
    """DomainFilters schema."""

    port: Optional[int] = None
    service: Optional[str] = None
    reverseName: Optional[str] = None
    ip: Optional[str] = None
    organization: Optional[str] = None
    organizationName: Optional[str] = None
    vulnerabilities: Optional[str] = None
    tag: Optional[str] = None

    class Config:
        from_attributes = True


class DomainSearch(BaseModel):
    """DomainSearch schema."""

    page: int = 1
    sort: Optional[str] = "ASC"
    order: Optional[str] = "id"
    filters: Optional[DomainFilters] = None
    pageSize: Optional[int] = 25

    class Config:
        from_attributes = True


class DomainSearchResponse(BaseModel):
    """List of Domain objects"""

    results: List[Domain]


class TotalDomainsResponse(BaseModel):
    value: int

    class Config:
        from_attributes = True


class OrganizationResponse(BaseModel):
    id: UUID
    name: str

    class Config:
        orm_mode = True
        from_attributes = True


class ProductResponse(BaseModel):
    name: str
    version: Optional[str] = None


class ServiceResponse(BaseModel):
    id: UUID
    port: int
    lastSeen: Optional[str] = None
    products: List[ProductResponse]

    class Config:
        orm_mode = True
        from_attributes = True


class VulnerabilityResponse(BaseModel):
    id: UUID
    title: str
    severity: str
    state: str
    createdAt: Optional[datetime] = None

    class Config:
        orm_mode = True
        from_attributes = True


class WebpageResponse(BaseModel):
    url: str
    status: str
    responseSize: Optional[int] = None

    class Config:
        orm_mode = True
        from_attributes = True


class GetDomainResponse(BaseModel):
    id: UUID
    name: str
    ip: Optional[str] = None
    createdAt: datetime
    updatedAt: datetime
    country: Optional[str] = None
    cloudHosted: Optional[bool] = False
    organization: Optional[OrganizationResponse]
    vulnerabilities: Optional[List[VulnerabilityResponse]] = []
    services: Optional[List[ServiceResponse]] = []
    webpages: Optional[List[WebpageResponse]] = []

    class Config:
        orm_mode = True
        from_attributes = True
