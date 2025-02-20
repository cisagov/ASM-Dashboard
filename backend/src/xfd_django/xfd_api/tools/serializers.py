"""Serializers to support user event logging."""
import json
from datetime import datetime, timezone
from xfd_api.models import User, Organization  # Adjust the import path as needed

def format_datetime(dt: datetime) -> str:
    """Format a datetime as an ISO 8601 UTC string with a trailing 'Z'."""
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def serialize_user(user: User) -> dict:
    """
    Serialize a User instance to a dictionary with camelCase keys.
    """
    return {
        "id": str(user.id),
        "cognitoId": user.cognitoId,
        "oktaId": user.oktaId,
        "loginGovId": user.loginGovId,
        "createdAt": format_datetime(user.createdAt),
        "updatedAt": format_datetime(user.updatedAt),
        "firstName": user.firstName,
        "lastName": user.lastName,
        "fullName": user.fullName,
        "email": user.email,
        "invitePending": user.invitePending,
        "loginBlockedByMaintenance": user.loginBlockedByMaintenance,
        "dateAcceptedTerms": format_datetime(user.dateAcceptedTerms) if user.dateAcceptedTerms else None,
        "acceptedTermsVersion": user.acceptedTermsVersion,
        "lastLoggedIn": format_datetime(user.lastLoggedIn) if user.lastLoggedIn else None,
        "userType": user.userType,
        "regionId": user.regionId,
        "state": user.state,
    }

def serialize_organization(org: Organization) -> dict:
    """
    Serialize an Organization instance to a dictionary with camelCase keys.
    Note: The pendingDomains field is stored as TEXT but represents a JSON array.
    """
    try:
        pending = json.loads(org.pendingDomains) if org.pendingDomains else []
    except (json.JSONDecodeError, TypeError):
        pending = []
    return {
        "id": str(org.id),
        "createdAt": format_datetime(org.createdAt),
        "updatedAt": format_datetime(org.updatedAt),
        "acronym": org.acronym,
        "name": org.name,
        "rootDomains": org.rootDomains,
        "ipBlocks": org.ipBlocks,
        "isPassive": org.isPassive,
        "pendingDomains": pending,
        "country": org.country,
        "state": org.state,
        "regionId": org.regionId,
        "stateFips": org.stateFips,
        "stateName": org.stateName,
        "county": org.county,
        "countyFips": org.countyFips,
        "type": org.type,
    }

def serialize_role(role) -> dict:
    """
    Serialize a Role instance to a dictionary.
    Adjust fields as needed.
    """
    return {
        "id": str(role.id),
        "role": role.role,
        "approved": role.approved,
        "user": serialize_user(role.user) if role.user else None,
        "createdAt": format_datetime(role.createdAt),
        "updatedAt": format_datetime(role.updatedAt),
    }
