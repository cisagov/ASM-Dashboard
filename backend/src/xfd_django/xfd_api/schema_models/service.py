"""Service schema."""
# Standard Python Libraries
from datetime import datetime
from typing import Any, Optional
from uuid import UUID

# Third-Party Libraries
from pydantic import BaseModel, Json
from pydantic.types import UUID1


class Service(BaseModel):
    """Service schema."""

    id: UUID
    createdAt: datetime
    updatedAt: datetime
    serviceSource: Optional[str]
    port: int
    service: Optional[str]
    lastSeen: Optional[datetime]
    banner: Optional[str]
    products: Json[Any]
    censysMetadata: Json[Any]
    censysIpv4Results: Json[Any]
    shodanResults: Json[Any]
    wappalyzerResults: Json[Any]
    domain: Optional[Any]
    discoveredBy: Optional[Any]

    class Config:
        from_attributes = True


class ServicesStat(BaseModel):
    id: UUID
    value: int

    class Config:
        from_attributes = True
