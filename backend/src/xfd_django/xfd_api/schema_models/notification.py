"""Notification schema."""
# Third-Party Libraries
# from pydantic.types import UUID1, UUID
# Standard Python Libraries
from datetime import datetime
from typing import Optional
from uuid import UUID

# Third-Party Libraries
from pydantic import BaseModel


class Notification(BaseModel):
    """Notification schema."""

    id: UUID
    createdAt: datetime
    updatedAt: datetime
    startDatetime: Optional[datetime]
    endDatetime: Optional[datetime]
    maintenanceType: Optional[str]
    updatedBy: Optional[str]
    status: Optional[str]
    message: Optional[str]

    class Config:
        """Config."""

        from_attributes = True


class CreateNotificationSchema(BaseModel):
    """Create notification schema."""

    maintenanceType: str
    status: str
    updatedBy: str
    message: str
    startDatetime: datetime
    endDatetime: datetime
