"""
Organizations API.

"""
# Standard Python Libraries
from typing import List, Optional

# Third-Party Libraries
from fastapi import HTTPException, Query

from ..models import Organization
from ..schemas import Organization as OrganizationSchema


def read_orgs():
    """
    Call API endpoint to get all organizations.
    Returns:
        list: A list of all organizations.
    """
    try:
        organizations = Organization.objects.all()
        return [
            {
                "id": organization.id,
                "name": organization.name,
                "acronym": organization.acronym,
                "rootDomains": organization.rootDomains,
                "ipBlocks": organization.ipBlocks,
                "isPassive": organization.isPassive,
                "country": organization.country,
                "state": organization.state,
                "regionId": organization.regionId,
                "stateFips": organization.stateFips,
                "stateName": organization.stateName,
                "county": organization.county,
                "countyFips": organization.countyFips,
                "type": organization.type,
                "parentId": organization.parentId.id if organization.parentId else None,
                "createdById": organization.createdById.id
                if organization.createdById
                else None,
                "createdAt": organization.createdAt,
                "updatedAt": organization.updatedAt,
            }
            for organization in organizations
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def get_organizations(regionId):
    """
    List all organizations with query parameters.
    Args:
        regionId : region IDs to filter organizations by.
    Raises:
        HTTPException: If the user is not authorized or no organizations are found.

    Returns:
        List[Organizations]: A list of organizations matching the filter criteria.
    """

    try:
        organizations = Organization.objects.filter(regionId=regionId)
        return organizations
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
