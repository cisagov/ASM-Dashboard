"""API methods to support Organization endpoints."""

# Standard Python Libraries
import json
from typing import Any, Dict, List
import uuid

# Third-Party Libraries
from django.db.models import Q
from fastapi import HTTPException

from ..auth import (
    get_org_memberships,
    is_global_view_admin,
    is_global_write_admin,
    is_org_admin,
    is_regional_admin,
    is_regional_admin_for_organization,
    matches_user_region,
)
from ..helpers.regionStateMap import REGION_STATE_MAP
from ..models import Organization, OrganizationTag, Role, Scan, ScanTask, User
from ..schema_models import organization_schema
from ..tasks.es_client import ESClient


def is_valid_uuid(val: str) -> bool:
    """Check if the given string is a valid UUID."""
    try:
        uuid_obj = uuid.UUID(val, version=4)
    except ValueError:
        return False
    return str(uuid_obj) == val


# GET: /organizations
def list_organizations(current_user):
    """List organizations that the user is a member of or has access to."""
    try:
        # Check if user is GlobalViewAdmin or has memberships
        if not is_global_view_admin(current_user) and not get_org_memberships(
            current_user
        ):
            return []

        # Define filter for organizations based on admin status
        org_filter = {}
        if not is_global_view_admin(current_user):
            org_filter["id__in"] = get_org_memberships(current_user)
        org_filter["parent"] = None

        # Fetch organizations with related userRoles and tags
        organizations = (
            Organization.objects.prefetch_related("tags", "userRoles")
            .filter(**org_filter)
            .order_by("name")
        )

        # Serialize organizations using list comprehension
        organization_list = [
            {
                "id": str(org.id),
                "createdAt": org.createdAt.isoformat(),
                "updatedAt": org.updatedAt.isoformat(),
                "acronym": org.acronym,
                "name": org.name,
                "rootDomains": org.rootDomains,
                "ipBlocks": org.ipBlocks,
                "isPassive": org.isPassive,
                "pendingDomains": org.pendingDomains,
                "country": org.country,
                "state": org.state,
                "regionId": org.regionId,
                "stateFips": org.stateFips,
                "stateName": org.stateName,
                "county": org.county,
                "countyFips": org.countyFips,
                "type": org.type,
                "userRoles": [
                    {"id": str(role.id), "role": role.role, "approved": role.approved}
                    for role in org.userRoles.all()
                ],
                "tags": [
                    {
                        "id": str(tag.id),
                        "createdAt": tag.createdAt.isoformat(),
                        "updatedAt": tag.updatedAt.isoformat(),
                        "name": tag.name,
                    }
                    for tag in org.tags.all()
                ],
            }
            for org in organizations
        ]

        return organization_list

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=str(e))


# GET: /organizations/tags
def get_tags(current_user):
    """Fetch all possible organization tags."""
    try:
        # Check if user is a global admin
        if not is_global_view_admin(current_user):
            return []

        # Fetch organization tags
        tags = OrganizationTag.objects.all().values("id", "name")

        # Return the list of tags
        return list(tags)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# GET: /organizations/{organization_id}
def get_organization(organization_id, current_user):
    """Get information about a particular organization."""
    try:
        # Authorization checks
        if not (
            is_org_admin(current_user, organization_id)
            or is_global_write_admin(current_user)
            or is_regional_admin_for_organization(current_user, organization_id)
        ):
            raise HTTPException(status_code=403, detail="Unauthorized")

        # Fetch organization with relations
        organization = (
            Organization.objects.select_related("parent")
            .prefetch_related("userRoles__user", "granularScans", "tags", "children")
            .filter(id=organization_id)
            .first()
        )

        if not organization:
            raise HTTPException(status_code=404, detail="Organization not found")

        # Fetch scan tasks related to the organization, limited to 10 most recent
        scan_tasks = (
            ScanTask.objects.filter(organizations__id=organization_id)
            .select_related("scan")
            .order_by("-createdAt")[:10]
        )

        if isinstance(organization.pendingDomains, str):
            pending_domains = json.loads(organization.pendingDomains)
        elif isinstance(organization.pendingDomains, list):
            pending_domains = organization.pendingDomains
        else:
            pending_domains = []

        # Serialize organization details along with scan tasks
        org_data = {
            "id": str(organization.id),
            "createdAt": organization.createdAt.isoformat(),
            "updatedAt": organization.updatedAt.isoformat(),
            "acronym": organization.acronym,
            "name": organization.name,
            "rootDomains": organization.rootDomains,
            "ipBlocks": organization.ipBlocks,
            "isPassive": organization.isPassive,
            "pendingDomains": pending_domains,
            "country": organization.country,
            "state": organization.state,
            "regionId": organization.regionId,
            "stateFips": organization.stateFips,
            "stateName": organization.stateName,
            "county": organization.county,
            "countyFips": organization.countyFips,
            "type": organization.type,
            "createdBy": {
                "id": str(organization.createdBy.id),
                "firstName": organization.createdBy.firstName,
                "lastName": organization.createdBy.lastName,
                "email": organization.createdBy.email,
            }
            if organization.createdBy
            else None,
            "userRoles": [
                {
                    "id": str(role.id),
                    "role": role.role,
                    "approved": role.approved,
                    "user": {
                        "id": str(role.user.id),
                        "email": role.user.email,
                        "firstName": role.user.firstName,
                        "lastName": role.user.lastName,
                        "fullName": role.user.fullName,
                    },
                }
                for role in organization.userRoles.all()
            ],
            "granularScans": [
                {
                    "id": str(scan.id),
                    "createdAt": scan.createdAt.isoformat(),
                    "updatedAt": scan.updatedAt.isoformat(),
                    "name": scan.name,
                    "arguments": scan.arguments,
                    "frequency": scan.frequency,
                    "lastRun": scan.lastRun.isoformat() if scan.lastRun else None,
                    "isGranular": scan.isGranular,
                    "isUserModifiable": scan.isUserModifiable,
                    "isSingleScan": scan.isSingleScan,
                    "manualRunPending": scan.manualRunPending,
                }
                for scan in organization.granularScans.all()
            ],
            "tags": [
                {
                    "id": str(tag.id),
                    "createdAt": tag.createdAt.isoformat(),
                    "updatedAt": tag.updatedAt.isoformat(),
                    "name": tag.name,
                }
                for tag in organization.tags.all()
            ],
            "parent": {
                "id": str(organization.parent.id),
                "name": organization.parent.name,
            }
            if organization.parent
            else None,
            "children": [
                {"id": str(child.id), "name": child.name}
                for child in organization.children.all()
            ],
            "scanTasks": [
                {
                    "id": str(task.id),
                    "createdAt": task.createdAt.isoformat(),
                    "scan": {"id": str(task.scan.id), "name": task.scan.name}
                    if task.scan
                    else None,
                }
                for task in scan_tasks
            ],
        }

        return org_data

    except HTTPException as http_exc:
        raise http_exc

    except Exception as e:
        print(f"An error occurred: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# GET: /organizations/state/{state}
def get_by_state(state, current_user):
    """List organizations with specific state."""
    # Check if the current user is a regional admin
    if not is_regional_admin(current_user):
        raise HTTPException(status_code=403, detail="Unauthorized")

    # Fetch organizations based on the provided state
    organizations = Organization.objects.filter(state=state).values(
        "id",
        "createdAt",
        "updatedAt",
        "acronym",
        "name",
        "rootDomains",
        "ipBlocks",
        "isPassive",
        "pendingDomains",
        "country",
        "state",
        "regionId",
        "stateFips",
        "stateName",
        "county",
        "countyFips",
        "type",
    )

    if not organizations:
        raise HTTPException(
            status_code=404, detail="No organizations found for the given state"
        )

    # Return the serialized list of organizations
    return list(organizations)


# GET: /organizations/regionId/{region_id}
def get_by_region(regionId, current_user):
    """List organizations with specific regionId."""
    # Check if the current user is a regional admin
    if not is_regional_admin(current_user):
        raise HTTPException(status_code=403, detail="Unauthorized")

    # Fetch organizations based on the provided state
    organizations = Organization.objects.filter(regionId=regionId).values(
        "id",
        "createdAt",
        "updatedAt",
        "acronym",
        "name",
        "rootDomains",
        "ipBlocks",
        "isPassive",
        "pendingDomains",
        "country",
        "state",
        "regionId",
        "stateFips",
        "stateName",
        "county",
        "countyFips",
        "type",
    )

    if not organizations:
        raise HTTPException(
            status_code=404, detail="No organizations found for the given region"
        )

    # Return the serialized list of organizations
    return list(organizations)


# GET: /regions
def get_all_regions(current_user):
    """Get all regions."""
    try:
        # Check if user is GlobalViewAdmin or has memberships
        if not is_global_view_admin(current_user):
            raise HTTPException(status_code=403, detail="Unauthorized")

        # Fetch distinct regionId values
        regions = (
            Organization.objects.exclude(regionId__isnull=True)
            .values("regionId")
            .distinct()
        )

        # Convert to a list and return the regions
        return list(regions)

    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def find_or_create_tags(
    tags: List[organization_schema.TagSchema],
) -> List[OrganizationTag]:
    """Find or create organization tags."""
    final_tags = []

    for tag_data in tags:
        tag_name = tag_data.name

        # Check if a tag with the given name exists
        existing_tag = OrganizationTag.objects.filter(name=tag_name).first()
        if existing_tag:
            final_tags.append(existing_tag)
        else:
            # If not found, create a new tag
            created_tag = OrganizationTag.objects.create(name=tag_name)
            final_tags.append(created_tag)

    return final_tags


# POST: /organizations
def create_organization(organization_data, current_user):
    """Create a new organization."""
    try:
        # Check if the user is a GlobalWriteAdmin
        if not is_global_write_admin(current_user):
            raise HTTPException(status_code=403, detail="Unauthorized access.")

        # Prepare the organization data for creation
        organization_data_dict = organization_data.dict(
            exclude_unset=True, exclude={"tags", "parent"}
        )
        organization_data_dict["createdBy"] = current_user

        # Set regionId based on stateName if available
        organization_data_dict["regionId"] = REGION_STATE_MAP.get(
            organization_data.stateName, None
        )

        # Create the organization object
        organization = Organization.objects.create(**organization_data_dict)

        # Link parent organization if provided
        if organization_data.parent:
            organization.parent_id = organization_data.parent
            organization.save()

        # Link tags (using the find_or_create_tags function)
        if organization_data.tags:
            tags = find_or_create_tags(organization_data.tags)
            organization.tags.add(*tags)

        if isinstance(organization.pendingDomains, str):
            pending_domains = json.loads(organization.pendingDomains)
        elif isinstance(organization.pendingDomains, list):
            pending_domains = organization.pendingDomains
        else:
            pending_domains = []

        # Return the organization details in response
        return {
            "id": str(organization.id),
            "createdAt": organization.createdAt.isoformat(),
            "updatedAt": organization.updatedAt.isoformat(),
            "acronym": organization.acronym,
            "name": organization.name,
            "rootDomains": organization.rootDomains,
            "ipBlocks": organization.ipBlocks,
            "isPassive": organization.isPassive,
            "pendingDomains": pending_domains,
            "country": organization.country,
            "state": organization.state,
            "regionId": organization.regionId,
            "stateFips": organization.stateFips,
            "stateName": organization.stateName,
            "county": organization.county,
            "countyFips": organization.countyFips,
            "type": organization.type,
            "createdBy": {
                "id": str(current_user.id),  # Simplify to just the user ID
            },
            "tags": [
                {
                    "id": str(tag.id),
                    "createdAt": tag.createdAt.isoformat(),
                    "updatedAt": tag.updatedAt.isoformat(),
                    "name": tag.name,
                }
                for tag in organization.tags.all()
            ],
            "parent": {
                "id": str(organization.parent.id),
                "name": organization.parent.name,
            }
            if organization.parent
            else {},
        }

    except HTTPException as http_exc:
        raise http_exc
    except Organization.DoesNotExist:
        raise HTTPException(status_code=404, detail="Parent organization not found")
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=str(e))


# POST: /organizations_upsert
def upsert_organization(organization_data, current_user):
    """Create a new organization or update it if it already exists."""
    try:
        # Check if the user is a GlobalWriteAdmin
        if not is_global_write_admin(current_user):
            raise HTTPException(
                status_code=403, detail="Unauthorized access. View logs for details."
            )

        # Prepare the organization data for creation
        organization_data_dict = organization_data.dict(
            exclude_unset=True, exclude={"tags", "parent"}
        )
        organization_data_dict["createdBy"] = current_user

        # Set regionId based on stateName if available
        organization_data_dict["regionId"] = REGION_STATE_MAP.get(
            organization_data.stateName, None
        )

        # Try to update or create a new organization
        organization, created = Organization.objects.update_or_create(
            acronym=organization_data.acronym,  # Conflict target is the acronym
            defaults=organization_data_dict,  # Fields to update if organization exists
        )

        # Link parent organization if provided
        if organization_data.parent:
            organization.parent_id = organization_data.parent
            organization.save()

        # Link tags (using the find_or_create_tags function)
        if organization_data.tags:
            tags = find_or_create_tags(organization_data.tags)
            organization.tags.add(*tags)

        if isinstance(organization.pendingDomains, str):
            pending_domains = json.loads(organization.pendingDomains)
        elif isinstance(organization.pendingDomains, list):
            pending_domains = organization.pendingDomains
        else:
            pending_domains = []

        # Return the organization details in response
        return {
            "id": str(organization.id),
            "createdAt": organization.createdAt.isoformat(),
            "updatedAt": organization.updatedAt.isoformat(),
            "acronym": organization.acronym,
            "name": organization.name,
            "rootDomains": organization.rootDomains,
            "ipBlocks": organization.ipBlocks,
            "isPassive": organization.isPassive,
            "pendingDomains": pending_domains,
            "country": organization.country,
            "state": organization.state,
            "regionId": organization.regionId,
            "stateFips": organization.stateFips,
            "stateName": organization.stateName,
            "county": organization.county,
            "countyFips": organization.countyFips,
            "type": organization.type,
            "createdBy": {
                "id": str(organization.createdBy.id),
                "firstName": organization.createdBy.firstName,
                "lastName": organization.createdBy.lastName,
                "email": organization.createdBy.email,
            }
            if organization.createdBy
            else None,
            "tags": [
                {
                    "id": str(tag.id),
                    "createdAt": tag.createdAt.isoformat(),
                    "updatedAt": tag.updatedAt.isoformat(),
                    "name": tag.name,
                }
                for tag in organization.tags.all()
            ],
            "parent": {
                "id": str(organization.parent.id),
                "name": organization.parent.name,
            }
            if organization.parent
            else {},
        }

    except HTTPException as http_exc:
        raise http_exc
    except Organization.DoesNotExist:
        raise HTTPException(status_code=404, detail="Parent organization not found")
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=str(e))


# PUT: /organizations/{organization_id}
def update_organization(organization_id: str, organization_data, current_user):
    """Update an organization by its ID."""
    try:
        # Validate the organization ID and ensure it's a valid UUID
        if not organization_id or not is_valid_uuid(organization_id):
            raise HTTPException(status_code=404, detail="Organization not found")

        # Ensure the current user has permission to update the organization
        if not is_org_admin(current_user, organization_id):
            raise HTTPException(status_code=403, detail="Unauthorized access.")

        # Fetch the existing organization with userRoles and granularScans relations
        try:
            organization = Organization.objects.prefetch_related(
                "userRoles", "granularScans"
            ).get(id=organization_id)
        except Organization.DoesNotExist:
            raise HTTPException(status_code=404, detail="Organization not found")

        # Update only the fields that are provided
        if organization_data.name is not None:
            organization.name = organization_data.name
        if organization_data.acronym is not None:
            organization.acronym = organization_data.acronym
        if organization_data.rootDomains is not None:
            organization.rootDomains = organization_data.rootDomains
        if organization_data.ipBlocks is not None:
            organization.ipBlocks = organization_data.ipBlocks
        if organization_data.stateName is not None:
            organization.stateName = organization_data.stateName
        if organization_data.state is not None:
            organization.state = organization_data.state
        if organization_data.isPassive is not None:
            organization.isPassive = organization_data.isPassive

        # Handle parent organization if provided
        if organization_data.parent:
            organization.parent_id = organization_data.parent

        # Handle tags (using the find_or_create_tags function)
        if organization_data.tags:
            tags = find_or_create_tags(organization_data.tags)
            organization.tags.set(tags)

        # Save the updated organization object
        organization.save()

        if isinstance(organization.pendingDomains, str):
            pending_domains = json.loads(organization.pendingDomains)
        elif isinstance(organization.pendingDomains, list):
            pending_domains = organization.pendingDomains
        else:
            pending_domains = []

        # Return the updated organization details in response
        return {
            "id": str(organization.id),
            "createdAt": organization.createdAt.isoformat(),
            "updatedAt": organization.updatedAt.isoformat(),
            "acronym": organization.acronym,
            "name": organization.name,
            "rootDomains": organization.rootDomains,
            "ipBlocks": organization.ipBlocks,
            "isPassive": organization.isPassive,
            "pendingDomains": pending_domains,
            "country": organization.country,
            "state": organization.state,
            "regionId": organization.regionId,
            "stateFips": organization.stateFips,
            "stateName": organization.stateName,
            "county": organization.county,
            "countyFips": organization.countyFips,
            "type": organization.type,
            "createdBy": {
                "id": str(organization.createdBy.id),
                "firstName": organization.createdBy.firstName,
                "lastName": organization.createdBy.lastName,
                "email": organization.createdBy.email,
            }
            if organization.createdBy
            else None,
            "tags": [
                {
                    "id": str(tag.id),
                    "createdAt": tag.createdAt.isoformat(),
                    "updatedAt": tag.updatedAt.isoformat(),
                    "name": tag.name,
                }
                for tag in organization.tags.all()
            ],
            "userRoles": [
                {
                    "id": str(role.id),
                    "role": role.role,
                    "approved": role.approved,
                    "user": {
                        "id": str(role.user.id),
                        "email": role.user.email,
                        "firstName": role.user.firstName,
                        "lastName": role.user.lastName,
                        "fullName": role.user.fullName,
                    },
                }
                for role in organization.userRoles.all()
            ],
            "granularScans": [
                {
                    "id": str(scan.id),
                    "createdAt": scan.createdAt.isoformat(),
                    "updatedAt": scan.updatedAt.isoformat(),
                    "name": scan.name,
                    "arguments": scan.arguments,
                    "frequency": scan.frequency,
                    "lastRun": scan.lastRun.isoformat() if scan.lastRun else None,
                    "isGranular": scan.isGranular,
                    "isUserModifiable": scan.isUserModifiable,
                    "isSingleScan": scan.isSingleScan,
                    "manualRunPending": scan.manualRunPending,
                }
                for scan in organization.granularScans.all()
            ],
        }

    except HTTPException as http_exc:
        raise http_exc

    except Organization.DoesNotExist:
        raise HTTPException(status_code=404, detail="Organization not found")
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=str(e))


# DELETE: /organizations/{organization_id}
def delete_organization(org_id: str, current_user):
    """Delete a particular organization."""
    try:
        # Validate the organization ID format (UUID)
        if not is_valid_uuid(org_id):
            raise HTTPException(status_code=404, detail="Invalid organization ID.")

        # Check if the current user is a GlobalWriteAdmin
        if not is_global_write_admin(current_user):
            raise HTTPException(status_code=403, detail="Unauthorized access.")

        # Fetch the organization by ID to ensure it exists
        try:
            organization = Organization.objects.get(id=org_id)
        except Organization.DoesNotExist:
            raise HTTPException(status_code=404, detail="Organization not found.")

        # Delete the organization
        organization.delete()

        # Return success response
        return {
            "status": "success",
            "message": f"Organization {org_id} has been deleted successfully.",
        }

    except HTTPException as http_exc:
        raise http_exc

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# POST: /v2/organizations/{organization_id}/users
def add_user_to_org_v2(organization_id: str, user_data, current_user):
    """Add a user to a particular organization."""
    try:
        # Check if the current user has regional admin permissions
        if not is_regional_admin(current_user):
            raise HTTPException(status_code=403, detail="Unauthorized access.")

        # Validate the organization ID format (UUID)
        if not is_valid_uuid(organization_id):
            raise HTTPException(status_code=404, detail="Invalid organization ID.")

        # Fetch the organization by ID
        try:
            organization = Organization.objects.get(id=organization_id)
        except Organization.DoesNotExist:
            raise HTTPException(status_code=404, detail="Organization not found.")

        # Validate the user ID in the body
        user_id = user_data.userId
        if not is_valid_uuid(user_id):
            raise HTTPException(status_code=404, detail="Invalid user ID.")

        # Fetch the user by ID
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise HTTPException(status_code=404, detail="User not found.")

        # Check if the current user's region matches the user's region
        if not matches_user_region(current_user, user.regionId):
            raise HTTPException(
                status_code=403, detail="Unauthorized access due to region mismatch."
            )

        # Prepare the new role data
        new_role_data = {
            "user": user,
            "organization": organization,
            "approved": True,
            "role": user_data.role,
            "approvedBy": current_user,
            "createdBy": current_user,
        }

        # Create the new role object
        new_role = Role.objects.create(**new_role_data)

        # Return the created role in the response
        return {
            "id": str(new_role.id),
            "user": {
                "id": str(new_role.user.id),
                "email": new_role.user.email,
                "firstName": new_role.user.firstName,
                "lastName": new_role.user.lastName,
            },
            "organization": {
                "id": str(new_role.organization.id),
                "name": new_role.organization.name,
            },
            "role": new_role.role,
            "approved": new_role.approved,
            "approvedBy": {
                "id": str(new_role.approvedBy.id),
                "email": new_role.approvedBy.email,
            },
            "createdBy": {
                "id": str(new_role.createdBy.id),
                "email": new_role.createdBy.email,
            },
        }

    except HTTPException as http_exc:
        raise http_exc

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=str(e))


# POST: /organizations/{organization_id}/roles/{role_id}/approve
def approve_role(organization_id: str, role_id, current_user):
    """Approve a role within an organization."""
    # Check if the current user is an org admin for the organization
    if not is_org_admin(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Unauthorized access.")

    # Validate that the role_id is a valid UUID
    if not is_valid_uuid(role_id):
        raise HTTPException(status_code=404, detail="Role not found")

    # Validate that the organization_id is a valid UUID
    if not is_valid_uuid(organization_id):
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        # Fetch the role within the organization
        role = Role.objects.filter(organization_id=organization_id, id=role_id).first()

        if role:
            # Approve the role and set the approvedBy field to the current user
            role.approved = True
            role.approvedBy = current_user
            role.save()

            return {"status": "success", "message": "Role approved successfully"}

        raise HTTPException(status_code=404, detail="Role not found")

    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# POST: /organizations/{organization_id}/roles/{role_id}/remove
def remove_role(organization_id: str, role_id, current_user):
    """Remove a role within an organization."""
    # Check if the current user is an org admin for the organization
    if not is_org_admin(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Unauthorized access.")

    # Validate that the role_id is a valid UUID
    if not is_valid_uuid(role_id):
        raise HTTPException(status_code=404, detail="Role not found")

    # Validate that the organization_id is a valid UUID
    if not is_valid_uuid(organization_id):
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        # Attempt to delete the role within the organization
        result = Role.objects.filter(
            organization_id=organization_id, id=role_id
        ).delete()

        # If no role was deleted, raise a 404
        if result[0] == 0:
            raise HTTPException(status_code=404, detail="Role not found")

        return {"status": "success", "message": "Role removed successfully"}

    except HTTPException as http_exc:
        raise http_exc

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# POST: /organizations/{organization_id}/granularScans/{scan_id}/update
def update_org_scan(organization_id: str, scan_id, scan_data, current_user):
    """Enable or disable a scan for a particular organization."""
    # Validate organization_id is a valid UUID
    if not is_valid_uuid(organization_id):
        raise HTTPException(status_code=404, detail="Organization not found")

    # Check if the current user is either an org admin or a global write admin
    if not (
        is_org_admin(current_user, organization_id)
        or is_global_write_admin(current_user)
    ):
        raise HTTPException(status_code=403, detail="Unauthorized access.")

    # Validate scan_id is a valid UUID
    if not is_valid_uuid(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        # Fetch the scan that is granular and user-modifiable
        scan = Scan.objects.filter(
            id=scan_id, isGranular=True, isUserModifiable=True
        ).first()
        if not scan:
            raise HTTPException(
                status_code=404, detail="Scan not found or not modifiable"
            )

        # Fetch the organization and its related granular scans
        organization = (
            Organization.objects.prefetch_related("granularScans")
            .filter(id=organization_id)
            .first()
        )
        if not organization:
            raise HTTPException(status_code=404, detail="Organization not found")

        # Check the "enabled" field in the request body
        if not scan_data.enabled:
            enabled = False
        else:
            enabled = scan_data.enabled

        # Add the scan to the organization's granular scans if enabled and not already present
        if enabled:
            if not organization.granularScans.filter(id=scan_id).exists():
                organization.granularScans.add(scan)
        # Remove the scan from the organization's granular scans if disabled and present
        else:
            if organization.granularScans.filter(id=scan_id).exists():
                organization.granularScans.remove(scan)

        # Save the updated organization
        organization.save()

        if isinstance(organization.pendingDomains, str):
            pending_domains = json.loads(organization.pendingDomains)
        elif isinstance(organization.pendingDomains, list):
            pending_domains = organization.pendingDomains
        else:
            pending_domains = []

        # Return a success response
        return {
            "id": str(organization.id),
            "createdAt": organization.createdAt.isoformat(),
            "updatedAt": organization.updatedAt.isoformat(),
            "acronym": organization.acronym,
            "name": organization.name,
            "rootDomains": organization.rootDomains,
            "ipBlocks": organization.ipBlocks,
            "isPassive": organization.isPassive,
            "pendingDomains": pending_domains,
            "country": organization.country,
            "state": organization.state,
            "regionId": organization.regionId,
            "stateFips": organization.stateFips,
            "stateName": organization.stateName,
            "county": organization.county,
            "countyFips": organization.countyFips,
            "type": organization.type,
            "granularScans": [
                {
                    "id": str(scan.id),
                    "createdAt": scan.createdAt.isoformat(),
                    "updatedAt": scan.updatedAt.isoformat(),
                    "name": scan.name,
                    "arguments": scan.arguments,
                    "frequency": scan.frequency,
                    "lastRun": scan.lastRun.isoformat() if scan.lastRun else None,
                    "isGranular": scan.isGranular,
                    "isUserModifiable": scan.isUserModifiable,
                    "isSingleScan": scan.isSingleScan,
                    "manualRunPending": scan.manualRunPending,
                }
                for scan in organization.granularScans.all()
            ],
        }

    except HTTPException as http_exc:
        raise http_exc

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# GET: /v2/organizations
def list_organizations_v2(state, regionId, current_user):
    """List organizations that the user is a member of or has access to."""
    try:
        # Check if user is GlobalViewAdmin or has memberships
        if not is_global_view_admin(current_user) and not get_org_memberships(
            current_user
        ):
            return []

        # Prepare the filter criteria
        filter_criteria = Q()

        if not is_global_view_admin(current_user):
            filter_criteria &= Q(id__in=get_org_memberships(current_user))

        if state:
            filter_criteria &= Q(state__in=state)

        if regionId:
            filter_criteria &= Q(regionId__in=regionId)

        # Fetch organizations with related userRoles and tags
        organizations = (
            Organization.objects.filter(filter_criteria)
            if filter_criteria
            else Organization.objects.all()
        )

        # Serialize organizations using list comprehension
        organization_list = [
            {
                "id": str(org.id),
                "createdAt": org.createdAt.isoformat(),
                "updatedAt": org.updatedAt.isoformat(),
                "acronym": org.acronym,
                "name": org.name,
                "rootDomains": org.rootDomains,
                "ipBlocks": org.ipBlocks,
                "isPassive": org.isPassive,
                "pendingDomains": org.pendingDomains,
                "country": org.country,
                "state": org.state,
                "regionId": org.regionId,
                "stateFips": org.stateFips,
                "stateName": org.stateName,
                "county": org.county,
                "countyFips": org.countyFips,
                "type": org.type,
            }
            for org in organizations
        ]

        return organization_list

    except HTTPException as http_exc:
        raise http_exc

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=str(e))


# POST: /search/organizations
def search_organizations_task(search_body, current_user: User):
    """Handle the logic for searching organizations in Elasticsearch."""
    try:
        # Check if user is GlobalViewAdmin or has memberships
        if not is_global_view_admin(current_user) and not get_org_memberships(
            current_user
        ):
            return []

        # Initialize Elasticsearch client
        client = ESClient()

        # Construct the Elasticsearch query

        query_body: Dict[str, Any] = {"query": {"bool": {"must": [], "filter": []}}}

        # Use match_all if searchTerm is empty
        if search_body.searchTerm.strip():
            query_body["query"]["bool"]["must"].append(
                {"wildcard": {"name": f"*{search_body.searchTerm}*"}}
            )
        else:
            query_body["query"]["bool"]["must"].append({"match_all": {}})

        # Add region filters if provided
        if search_body.regions:
            query_body["query"]["bool"]["filter"].append(
                {"terms": {"regionId": search_body.regions}}
            )

        # Log the query for debugging
        print(f"Query body: {query_body}")

        # Execute the search
        search_results = client.search_organizations(query_body)

        return {"body": search_results}

    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=500, detail="An error occurred while searching organizations."
        )
