"""User schemas."""

# Standard Python Libraries
from datetime import datetime
from enum import Enum
from typing import List, Literal, Optional
from uuid import UUID

# Third-Party Libraries
from pydantic import BaseModel, Field

from .api_key import ApiKey
from .role import Role


class UserType(Enum):
    GLOBAL_ADMIN = "globalAdmin"
    GLOBAL_VIEW = "globalView"
    REGIONAL_ADMIN = "regionalAdmin"
    READY_SET_CYBER = "readySetCyber"
    STANDARD = "standard"


class User(BaseModel):
    """User schema."""

    id: UUID
    cognitoId: Optional[str]
    loginGovId: Optional[str]
    createdAt: datetime
    updatedAt: datetime
    firstName: str
    lastName: str
    fullName: str
    email: str
    invitePending: bool
    loginBlockedByMaintenance: bool
    dateAcceptedTerms: Optional[datetime]
    acceptedTermsVersion: Optional[str]
    lastLoggedIn: Optional[datetime]
    userType: UserType
    regionId: Optional[str]
    state: Optional[str]
    oktaId: Optional[str]
    roles: Optional[List[Role]] = []
    apiKeys: Optional[List[ApiKey]] = []


class UserResponse(BaseModel):
    """User response schema."""

    cognitoId: Optional[str]
    loginGovId: Optional[str]
    firstName: str
    lastName: str
    fullName: str
    email: str
    invitePending: bool
    loginBlockedByMaintenance: bool
    dateAcceptedTerms: Optional[datetime]
    acceptedTermsVersion: Optional[str]
    lastLoggedIn: Optional[datetime]
    userType: UserType
    regionId: Optional[str]
    state: Optional[str]
    oktaId: Optional[str]
    roles: Optional[List[Role]] = []
    apiKeys: Optional[List[ApiKey]] = []

    @classmethod
    def model_validate(cls, obj):
        # Convert fields before passing to Pydantic Schema
        user_dict = obj.__dict__.copy()
        user_dict["roles"] = [
            Role.model_validate(role).model_dump() for role in obj.roles.all()
        ]
        user_dict["apiKeys"] = [
            ApiKey.model_validate(api_key).model_dump() for api_key in obj.apiKeys.all()
        ]
        [ApiKey.from_orm(api_key) for api_key in obj]
        return cls(**user_dict)

    def model_dump(self, **kwargs):
        """Override model_dump to handle UUID serialization."""
        data = super().model_dump(**kwargs)
        if isinstance(data.get("id"), UUID):
            data["id"] = str(data["id"])  # Convert UUID to string
        return data

    class Config:
        from_attributes = True


# TODO: Confirm that userType is set during user creation
class NewUser(BaseModel):
    email: str
    firstName: str
    lastName: str
    organization: Optional[str]
    organizationAdmin: Optional[bool]
    regionId: Optional[str]
    state: Optional[str]
    userType: UserType


class UpdateUser(BaseModel):
    firstName: Optional[str]
    fullName: Optional[str]
    invitePending: Optional[bool]
    lastName: Optional[str]
    loginBlockedByMaintenance: Optional[bool]
    organization: Optional[str]
    regionId: Optional[str]
    role: Optional[str]
    state: Optional[str]
    userType: Optional[UserType]
