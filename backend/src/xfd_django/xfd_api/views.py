"""
This module defines the API endpoints for the FastAPI application.

It includes endpoints for:
- Healthcheck
- Retrieving all API keys
- Retrieving all organizations

Endpoints:
    - healthcheck: Returns the health status of the application.
    - get_api_keys: Retrieves all API keys.
    - read_orgs: Retrieves all organizations.

Dependencies:
    - fastapi
    - .auth
    - .models
"""

# Standard Python Libraries
import json
from typing import List, Optional

# Third-Party Libraries
from asgiref.sync import sync_to_async
from django.shortcuts import render
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from redis import asyncio as aioredis

# from .schemas import Cpe
from . import schema_models
from .api_methods import api_key as api_key_methods
from .api_methods import auth as auth_methods
from .api_methods import notification as notification_methods
from .api_methods import scan
from .api_methods.api_keys import get_api_keys
from .api_methods.cpe import get_cpes_by_id
from .api_methods.cve import get_cves_by_id, get_cves_by_name
from .api_methods.domain import export_domains, get_domain_by_id, search_domains
from .api_methods.organization import get_organizations, read_orgs
from .api_methods.user import get_users
from .api_methods.vulnerability import get_vulnerability_by_id, update_vulnerability
from .auth import (
    get_current_active_user,
    get_tag_organization_ids,
    get_user_domains,
    get_user_organization_ids,
    get_user_ports,
    get_user_service_ids,
    is_global_view_admin,
)
from .login_gov import callback, login
from .models import Assessment, Domain, Organization, User, Vulnerability
from .schema_models import scan as scanSchema
from .schema_models.api_key import ApiKey as ApiKeySchema
from .schema_models.assessment import Assessment as AssessmentSchema
from .schema_models.by_org_item import ByOrgItem
from .schema_models.cpe import Cpe as CpeSchema
from .schema_models.cve import Cve as CveSchema
from .schema_models.domain import Domain as DomainSchema
from .schema_models.domain import DomainFilters, DomainSearch, TotalDomainsResponse
from .schema_models.latest_vuln import LatestVulnerabilitySchema
from .schema_models.most_common_vuln import MostCommonVulnerabilitySchema
from .schema_models.notification import Notification as NotificationSchema
from .schema_models.organization import Organization as OrganizationSchema
from .schema_models.ports_stats import PortsStats
from .schema_models.role import Role as RoleSchema
from .schema_models.service import ServicesStat
from .schema_models.severity_count import SeverityCountSchema
from .schema_models.user import User as UserSchema
from .schema_models.vulnerability import Vulnerability as VulnerabilitySchema
from .schema_models.vulnerability import VulnerabilityStat

# Define API router
api_router = APIRouter()


async def default_identifier(request):
    """Return default identifier."""
    return request.headers.get("X-Real-IP", request.client.host)


async def get_redis_client(request: Request):
    """Get the Redis client from the application state."""
    return request.app.state.redis


# Healthcheck endpoint
@api_router.get("/healthcheck", tags=["Testing"])
async def healthcheck():
    """
    Healthcheck endpoint.

    Returns:
        dict: A dictionary containing the health status of the application.
    """
    return {"status": "ok2"}


@api_router.get("/test-apikeys", tags=["Testing"])
async def call_get_api_keys():
    """
    Get all API keys.

    Returns:
        list: A list of all API keys.
    """
    return get_api_keys()


@api_router.post(
    "/test-orgs",
    # dependencies=[Depends(get_current_active_user)],
    response_model=List[OrganizationSchema],
    tags=["Organizations", "Testing"],
)
async def call_read_orgs():
    """
    List all organizations with query parameters.
    Args:
        state (Optional[List[str]]): List of states to filter organizations by.
        regionId (Optional[List[str]]): List of region IDs to filter organizations by.

    Raises:
        HTTPException: If the user is not authorized or no organizations are found.

    Returns:
        List[Organizations]: A list of organizations matching the filter criteria.
    """
    return read_orgs()


# TODO: Uncomment checks for current_user once authentication is implemented
@api_router.get(
    "/assessments",
    #  current_user: User = Depends(get_current_active_user),
    tags=["ReadySetCyber"],
)
async def list_assessments():
    """
    Lists all assessments for the logged-in user.

    Args:
        current_user (User): The current authenticated user.

    Raises:
        HTTPException: If the user is not authorized or assessments are not found.

    Returns:
        List[Assessment]: A list of assessments for the logged-in user.
    """
    # Ensure the user is authenticated
    # if not current_user:
    #     raise HTTPException(status_code=401, detail="Unauthorized")

    # Query the database for assessments belonging to the current user
    # assessments = Assessment.objects.filter(user=current_user)
    assessments = (
        Assessment.objects.all()
    )  # TODO: Remove this line once filtering by user is implemented

    # Return assessments if found, or raise a 404 error if none exist
    if not assessments.exists():
        raise HTTPException(status_code=404, detail="No assessments found")

    return list(assessments)


@api_router.post("/search")
async def search():
    pass


@api_router.post("/search/export")
async def export_search():
    pass


@api_router.get(
    "/cpes/{cpe_id}",
    # dependencies=[Depends(get_current_active_user)],
    response_model=CpeSchema,
    tags=["Cpe"],
)
async def call_get_cpes_by_id(cpe_id):
    """
    Get Cpe by id.
    Returns:
        object: a single Cpe object.
    """
    return get_cpes_by_id(cpe_id)


@api_router.get(
    "/cves/{cve_id}",
    # dependencies=[Depends(get_current_active_user)],
    response_model=CveSchema,
    tags=["Cve"],
)
async def call_get_cves_by_id(cve_id):
    """
    Get Cve by id.
    Returns:
        object: a single Cve object.
    """
    return get_cves_by_id(cve_id)


@api_router.get(
    "/cves/name/{cve_name}",
    # dependencies=[Depends(get_current_active_user)],
    response_model=CveSchema,
    tags=["Get cve by name"],
)
async def call_get_cves_by_name(cve_name):
    """
    Get Cve by name.
    Returns:
        object: a single Cpe object.
    """
    return get_cves_by_name(cve_name)


@api_router.post(
    "/domain/search",
    # dependencies=[Depends(get_current_active_user)],
    response_model=List[DomainSchema],
    tags=["Domains"],
)
async def call_search_domains(domain_search: DomainSearch):
    try:
        return search_domains(domain_search)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@api_router.post(
    "/domain/export",
    # dependencies=[Depends(get_current_active_user)],
    tags=["Domains"],
)
async def call_export_domains(domain_search: DomainSearch):
    try:
        return export_domains(domain_search)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get(
    "/domain/{domain_id}",
    # dependencies=[Depends(get_current_active_user)],
    response_model=DomainSchema,
    tags=["Get domain by id"],
)
async def call_get_domain_by_id(domain_id: str):
    """
    Get domain by id.
    Returns:
        object: a single Domain object.
    """
    return get_domain_by_id(domain_id)


@api_router.post("/vulnerabilities/search")
async def search_vulnerabilities():
    try:
        pass
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@api_router.post("/vulnerabilities/export")
async def export_vulnerabilities():
    try:
        pass
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get(
    "/vulnerabilities/{vulnerabilityId}",
    # dependencies=[Depends(get_current_active_user)],
    response_model=VulnerabilitySchema,
    tags="Get vulnerability by id",
)
async def call_get_vulnerability_by_id(vuln_id):
    """
    Get vulnerability by id.
    Returns:
        object: a single Vulnerability object.
    """
    return get_vulnerability_by_id(vuln_id)


@api_router.put(
    "/vulnerabilities/{vulnerabilityId}",
    # dependencies=[Depends(get_current_active_user)],
    response_model=VulnerabilitySchema,
    tags="Update vulnerability",
)
async def call_update_vulnerability(vuln_id, data: VulnerabilitySchema):
    """
    Update vulnerability by id.

    Returns:
        object: a single vulnerability object that has been modified.
    """
    return update_vulnerability(vuln_id, data)


######################
# Auth
######################


# Okta Callback
@api_router.post("/auth/okta-callback", tags=["auth"])
async def okta_callback(request: Request):
    """Handle Okta Callback."""
    return await auth_methods.handle_okta_callback(request)


# Login
@api_router.get("/login", tags=["auth"])
async def login_route():
    """Handle V1 Login."""
    return login()


# V1 Callback
@api_router.post("/auth/callback", tags=["auth"])
async def callback_route(request: Request):
    """Handle V1 Callback."""
    body = await request.json()
    try:
        user_info = callback(body)
        return user_info
    except Exception as error:
        raise HTTPException(status_code=400, detail=str(error))


######################
# Users
######################


# GET Current User
@api_router.get("/users/me", tags=["users"])
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@api_router.get(
    "/users/{regionId}",
    response_model=List[UserSchema],
    # dependencies=[Depends(get_current_active_user)],
    tags=["User"],
)
async def call_get_users(regionId):
    """
    Call get_users()

    Args:
        regionId: Region IDs to filter users by.

    Raises:
        HTTPException: If the user is not authorized or no users are found.

    Returns:
        List[User]: A list of users matching the filter criteria.
    """
    return get_users(regionId)


######################
# API-Keys
######################


# POST
@api_router.post("/api-keys", response_model=ApiKeySchema, tags=["api-keys"])
async def create_api_key(current_user: User = Depends(get_current_active_user)):
    """Create api key."""
    return api_key_methods.post(current_user)


# DELETE
@api_router.delete("/api-keys/{id}", tags=["api-keys"])
async def delete_api_key(
    id: str, current_user: User = Depends(get_current_active_user)
):
    """Delete api key by id."""
    return api_key_methods.delete(id, current_user)


@api_router.get(
    "/organizations/{regionId}",
    response_model=List[OrganizationSchema],
    # dependencies=[Depends(get_current_active_user)],
    tags=["Organization"],
)
async def call_get_organizations(regionId):
    """
    List all organizations with query parameters.
    Args:
        regionId : Region IDs to filter organizations by.

    Raises:
        HTTPException: If the user is not authorized or no organizations are found.

    Returns:
        List[Organizations]: A list of organizations matching the filter criteria.
    """
    return get_organizations(regionId)


# GET ALL
@api_router.get("/api-keys", response_model=List[ApiKeySchema], tags=["api-keys"])
async def get_all_api_keys(current_user: User = Depends(get_current_active_user)):
    """Get all api keys."""
    return api_key_methods.get_all(current_user)


# GET BY ID
@api_router.get("/api-keys/{id}", response_model=ApiKeySchema, tags=["api-keys"])
async def get_api_key(id: str, current_user: User = Depends(get_current_active_user)):
    """Get api key by id."""
    return api_key_methods.get_by_id(id, current_user)


#########################
#     Notifications
#########################


# POST
@api_router.post(
    "/notifications", response_model=NotificationSchema, tags=["notifications"]
)
async def create_notification(current_user: User = Depends(get_current_active_user)):
    """Create notification key."""
    # return notification_handler.post(current_user)
    return []


# DELETE
@api_router.delete(
    "/notifications/{id}", response_model=NotificationSchema, tags=["notifications"]
)
async def delete_notification(
    id: str, current_user: User = Depends(get_current_active_user)
):
    """Delete notification by id."""
    return notification_methods.delete(id, current_user)


# GET ALL
@api_router.get(
    "/notifications", response_model=List[NotificationSchema], tags=["notifications"]
)
async def get_all_notifications(current_user: User = Depends(get_current_active_user)):
    """Get all notifications."""
    return notification_methods.get_all(current_user)


# GET BY ID
@api_router.get(
    "/notifications/{id}", response_model=NotificationSchema, tags=["notifications"]
)
async def get_notification(
    id: str, current_user: User = Depends(get_current_active_user)
):
    """Get notification by id."""
    return notification_methods.get_by_id(id, current_user)


# UPDATE BY ID
@api_router.put("/notifications/{id}", tags=["notifications"])
async def update_notification(
    id: str, current_user: User = Depends(get_current_active_user)
):
    """Update notification key by id."""
    return notification_methods.delete(id, current_user)


# GET 508 Banner
@api_router.get("/notifications/508-banner", tags=["notifications"])
async def get_508_banner(current_user: User = Depends(get_current_active_user)):
    """Get notification by id."""
    return notification_methods.get_508_banner(current_user)


# ========================================
#   Scan Endpoints
# ========================================


@api_router.get(
    "/scans",
    dependencies=[Depends(get_current_active_user)],
    response_model=scanSchema.GetScansResponseModel,
    tags=["Scans"],
)
async def list_scans(current_user: User = Depends(get_current_active_user)):
    """Retrieve a list of all scans."""
    return scan.list_scans(current_user)


@api_router.get(
    "/granularScans",
    dependencies=[Depends(get_current_active_user)],
    response_model=scanSchema.GetGranularScansResponseModel,
    tags=["Scans"],
)
async def list_granular_scans(current_user: User = Depends(get_current_active_user)):
    """Retrieve a list of granular scans. User must be authenticated."""
    return scan.list_granular_scans(current_user)


@api_router.post(
    "/scans",
    dependencies=[Depends(get_current_active_user)],
    response_model=scanSchema.CreateScanResponseModel,
    tags=["Scans"],
)
async def create_scan(
    scan_data: scanSchema.NewScan, current_user: User = Depends(get_current_active_user)
):
    """Create a new scan."""
    return scan.create_scan(scan_data, current_user)


@api_router.get(
    "/scans/{scan_id}",
    dependencies=[Depends(get_current_active_user)],
    response_model=scanSchema.GetScanResponseModel,
    tags=["Scans"],
)
async def get_scan(scan_id: str, current_user: User = Depends(get_current_active_user)):
    """Get a scan by its ID. User must be authenticated."""
    return scan.get_scan(scan_id, current_user)


@api_router.put(
    "/scans/{scan_id}",
    dependencies=[Depends(get_current_active_user)],
    response_model=scanSchema.CreateScanResponseModel,
    tags=["Scans"],
)
async def update_scan(
    scan_id: str,
    scan_data: scanSchema.NewScan,
    current_user: User = Depends(get_current_active_user),
):
    """Update a scan by its ID."""
    return scan.update_scan(scan_id, scan_data, current_user)


@api_router.delete(
    "/scans/{scan_id}",
    dependencies=[Depends(get_current_active_user)],
    response_model=scanSchema.GenericMessageResponseModel,
    tags=["Scans"],
)
async def delete_scan(
    scan_id: str, current_user: User = Depends(get_current_active_user)
):
    """Delete a scan by its ID."""
    return scan.delete_scan(scan_id, current_user)


@api_router.post(
    "/scans/{scan_id}/run",
    dependencies=[Depends(get_current_active_user)],
    response_model=scanSchema.GenericMessageResponseModel,
    tags=["Scans"],
)
async def run_scan(scan_id: str, current_user: User = Depends(get_current_active_user)):
    """Manually run a scan by its ID"""
    return scan.run_scan(scan_id, current_user)


@api_router.post(
    "/scheduler/invoke", dependencies=[Depends(get_current_active_user)], tags=["Scans"]
)
async def invoke_scheduler(current_user: User = Depends(get_current_active_user)):
    """Manually invoke the scan scheduler."""
    response = await scan.invoke_scheduler(current_user)
    return response


@api_router.get(
    "/services/",
    tags=["Retrieve Stats"],
)
async def get_services(
    current_user: User = Depends(get_current_active_user),
    redis_client=Depends(get_redis_client),
):
    """Retrieve services from Elasticache filtered by user."""
    try:
        # Get service IDs associated with the user's organizations
        user_service_ids = get_user_service_ids(current_user)

        if not user_service_ids:
            raise HTTPException(
                status_code=404, detail="No services found for the user."
            )

        services_data = []

        # Fetch data from Redis for each service ID
        for service_id in user_service_ids:
            service_data = await redis_client.get(service_id)
            if service_data:
                try:
                    # Attempt to parse the service_data as JSON
                    parsed_data = json.loads(service_data)
                    services_data.append({"id": service_id, "value": parsed_data})
                except json.JSONDecodeError:
                    # If not JSON, assume it's an integer-like string and convert
                    services_data.append({"id": service_id, "value": int(service_data)})

        if not services_data:
            raise HTTPException(
                status_code=404, detail="No service data found in cache."
            )

        return services_data

    except aioredis.RedisError as redis_error:
        raise HTTPException(status_code=500, detail=f"Redis error: {redis_error}")

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"An unexpected error occurred: {e}"
        )


@api_router.get(
    "/ports/",
    response_model=List[PortsStats],  # Expecting a list of Stats objects
    tags=["Retrieve Stats"],
)
async def get_Ports(
    current_user: User = Depends(get_current_active_user),
    redis_client=Depends(get_redis_client),
):
    """Retrieve Stats from Elasticache."""
    try:
        # Get ports associated with the user's organizations
        user_ports = get_user_ports(current_user)

        if not user_ports:
            raise HTTPException(status_code=404, detail="No ports found for the user.")

        # Retrieve the ports stats JSON data from Redis
        ports_json = await redis_client.get("ports_stats")

        if not ports_json:
            raise HTTPException(status_code=404, detail="No ports data found in cache.")

        # Deserialize JSON data
        all_ports_data = json.loads(ports_json)

        # Filter the ports data to include only the user's ports
        ports_data = [
            port_stat for port_stat in all_ports_data if port_stat["port"] in user_ports
        ]

        if not ports_data:
            raise HTTPException(
                status_code=404, detail="No port data found for the user in cache."
            )

        return ports_data

    except aioredis.RedisError as redis_error:
        raise HTTPException(status_code=500, detail=f"Redis error: {redis_error}")

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"An unexpected error occurred: {e}"
        )


@api_router.get(
    "/num-vulnerabilities/",
    response_model=List[VulnerabilityStat],  # Expecting a list of Stats objects
    tags=["Retrieve Stats"],
)
async def get_NumVulnerabilities(
    current_user: User = Depends(get_current_active_user),
    redis_client: aioredis.Redis = Depends(get_redis_client),
):
    """
    Retrieve number of vulnerabilities stats from ElastiCache (Redis) filtered by user.
    """
    try:
        # Step 1: Retrieve the list of domain names associated with the user
        user_domains = await get_user_domains(current_user)
        # print(user_domains)

        if not user_domains:
            raise HTTPException(
                status_code=404, detail="No domains found for the user."
            )

        # Step 2: Retrieve all vulnerability stats data from Redis
        vulnerabilities_stats = await redis_client.get("num_vulnerabilities_stats")

        if not vulnerabilities_stats:
            raise HTTPException(
                status_code=404, detail="No vulnerabilities stats data found in cache."
            )

        # Step 3: Filter the vulnerabilities stats based on user's domains
        filtered_data = []
        for composite_id, value in vulnerabilities_stats.items():
            try:
                domain, severity = composite_id.split("|", 1)
            except ValueError:
                # If the composite_id doesn't contain '|', skip this entry
                continue

            if domain in user_domains:
                filtered_data.append({"id": composite_id, "value": int(value)})

        if not filtered_data:
            raise HTTPException(
                status_code=404,
                detail="No vulnerability data found for the user in cache.",
            )

        return filtered_data

    except aioredis.RedisError as redis_error:
        raise HTTPException(status_code=500, detail=f"Redis error: {redis_error}")

    except HTTPException as http_exc:
        raise http_exc  # Already handled, re-raise

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"An unexpected error occurred: {e}"
        )


@api_router.get(
    "/latest-vulnerabilities/",
    response_model=List[LatestVulnerabilitySchema],
    tags=["Retrieve Stats"],
)
async def get_latest_vulnerabilities(
    organization: str = Query(None, description="Filter by organization ID"),
    tag: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    redis_client: aioredis.Redis = Depends(get_redis_client),
):
    try:
        # Step 1: Retrieve data from Redis
        vulnerabilities_json = await redis_client.get("latest_vulnerabilities")

        if vulnerabilities_json is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Data not found in cache."
            )

        # Deserialize JSON data
        if isinstance(vulnerabilities_json, bytes):
            vulnerabilities_json = vulnerabilities_json.decode("utf-8")
        vulnerabilities_data = json.loads(vulnerabilities_json)

        # Validate data format
        if not isinstance(vulnerabilities_data, list):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unexpected data format.",
            )

        # Get user's organization IDs
        user_org_ids = await get_user_organization_ids(current_user)
        if not user_org_ids:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User does not belong to any organizations.",
            )

        # Check if user is a global admin
        is_admin = is_global_view_admin(current_user)

        # Determine accessible organizations
        if is_admin:
            accessible_org_ids = None  # None implies access to all organizations
        else:
            accessible_org_ids = set(user_org_ids)

        # Apply filters
        if organization:
            if (
                accessible_org_ids is not None
                and organization not in accessible_org_ids
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User does not have access to the specified organization.",
                )
            accessible_org_ids = {organization}
        elif tag:
            tag_org_ids = get_tag_organization_ids(tag)
            if accessible_org_ids is not None:
                accessible_org_ids = accessible_org_ids.intersection(tag_org_ids)
            else:
                accessible_org_ids = set(tag_org_ids)
            if not accessible_org_ids:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No accessible organizations found for the specified tag.",
                )

        # Filter vulnerabilities based on accessible organizations
        if accessible_org_ids is not None:
            filtered_vulnerabilities = [
                vuln
                for vuln in vulnerabilities_data
                if vuln.get("organizationId") in accessible_org_ids
            ]
        else:
            filtered_vulnerabilities = vulnerabilities_data

        return filtered_vulnerabilities

    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to parse JSON data from cache.",
        )
    except aioredis.RedisError as redis_err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Redis error: {redis_err}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@api_router.get(
    "/most-common-vulnerabilities/",
    response_model=List[MostCommonVulnerabilitySchema],
    tags=["Retrieve Stats"],
)
async def get_most_common_vulnerabilities(
    organization: str = Query(None, description="Filter by organization ID"),
    tag: str = Query(None, description="Filter by tag"),
    current_user: User = Depends(get_current_active_user),
    redis_client: aioredis.Redis = Depends(get_redis_client),
):
    try:
        # Retrieve data from Redis
        vulnerabilities_json = await redis_client.get("most_common_vulnerabilities")

        if vulnerabilities_json is None:
            raise HTTPException(status_code=404, detail="Data not found in cache.")

        # Deserialize JSON data
        if isinstance(vulnerabilities_json, bytes):
            vulnerabilities_json = vulnerabilities_json.decode("utf-8")
        vulnerabilities_data = json.loads(vulnerabilities_json)

        # Validate data format
        if not isinstance(vulnerabilities_data, list):
            raise HTTPException(status_code=500, detail="Unexpected data format.")

        # Get user's organization IDs
        user_org_ids = await get_user_organization_ids(current_user)
        print(user_org_ids)
        if not user_org_ids:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User does not belong to any organizations.",
            )

        # Check if user is a global admin
        is_admin = is_global_view_admin(current_user)

        # Determine accessible organizations
        if is_admin:
            accessible_org_ids = None  # None implies access to all organizations
        else:
            accessible_org_ids = set(user_org_ids)

        # Apply filters
        if organization:
            if (
                accessible_org_ids is not None
                and organization not in accessible_org_ids
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User does not have access to the specified organization.",
                )
            accessible_org_ids = {organization}
        elif tag:
            tag_org_ids = get_tag_organization_ids(tag)
            if accessible_org_ids is not None:
                accessible_org_ids = accessible_org_ids.intersection(tag_org_ids)
            else:
                accessible_org_ids = set(tag_org_ids)
            if not accessible_org_ids:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No accessible organizations found for the specified tag.",
                )

        # Filter vulnerabilities based on accessible organizations
        if accessible_org_ids is not None:
            filtered_vulnerabilities = [
                vuln
                for vuln in vulnerabilities_data
                if vuln.get("organizationId") in accessible_org_ids
            ]
        else:
            filtered_vulnerabilities = vulnerabilities_data

        return filtered_vulnerabilities

    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500, detail="Failed to parse JSON data from cache."
        )
    except aioredis.RedisError as redis_err:
        raise HTTPException(status_code=500, detail=f"Redis error: {redis_err}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get(
    "/severity-counts/",
    response_model=List[SeverityCountSchema],
    tags=["Retrieve Stats"],
)
async def get_severity_counts(
    organization: str = Query(None, description="Filter by organization ID"),
    tag: str = Query(None, description="Filter by tag"),
    current_user: User = Depends(get_current_active_user),
    redis_client: aioredis.Redis = Depends(get_redis_client),
):
    """
    Retrieves the count of open vulnerabilities grouped by severity from Redis.
    """
    try:
        # Retrieve data from Redis
        vulnerabilities_json = await redis_client.get("vulnerabilities_data")

        if vulnerabilities_json is None:
            raise HTTPException(status_code=404, detail="Data not found in cache.")

        # Deserialize JSON data
        vulnerabilities_data = json.loads(vulnerabilities_json)

        # Get user's organization IDs
        user_org_ids = await get_user_organization_ids(current_user)
        if not user_org_ids:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User does not belong to any organizations.",
            )

        # Check if user is a global admin
        is_admin = is_global_view_admin(current_user)

        # Determine accessible organizations
        if is_admin:
            accessible_org_ids = None  # None implies access to all organizations
        else:
            accessible_org_ids = set(user_org_ids)

        # Apply filters
        if organization:
            if (
                accessible_org_ids is not None
                and organization not in accessible_org_ids
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User does not have access to the specified organization.",
                )
            accessible_org_ids = {organization}
        elif tag:
            tag_org_ids = get_tag_organization_ids(tag)
            if accessible_org_ids is not None:
                accessible_org_ids = accessible_org_ids.intersection(tag_org_ids)
            else:
                accessible_org_ids = set(tag_org_ids)
            if not accessible_org_ids:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No accessible organizations found for the specified tag.",
                )

        # Filter vulnerabilities based on accessible organizations
        if accessible_org_ids is not None:
            filtered_vulnerabilities = [
                vuln
                for vuln in vulnerabilities_data
                if vuln.get("organizationId") in accessible_org_ids
            ]
        else:
            filtered_vulnerabilities = vulnerabilities_data

        # Aggregate counts by severity
        severity_counts = {}
        for vuln in filtered_vulnerabilities:
            severity = vuln.get("severity")
            if severity not in severity_counts:
                severity_counts[severity] = 0
            severity_counts[severity] += 1

        # Transform to list of dictionaries
        severity_data = [
            {"id": severity, "value": count, "label": severity}
            for severity, count in severity_counts.items()
        ]

        return severity_data

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get(
    "/domains/total/",
    response_model=TotalDomainsResponse,
    tags=["Retrieve Stats"],
)
async def get_total_domains(
    organization: str = Query(None, description="Filter by organization ID"),
    tag: str = Query(None, description="Filter by tag"),
    current_user: User = Depends(get_current_active_user),
):
    try:
        # Base QuerySet
        queryset = Domain.objects.all()

        # Apply filtering logic at the endpoint
        # Check if the user is a global admin
        is_admin = is_global_view_admin(current_user)

        # Get user's accessible organizations
        if not is_admin:
            user_org_ids = await get_user_organization_ids(current_user)
            if not user_org_ids:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User does not belong to any organizations.",
                )
            queryset = queryset.filter(organizationId__id__in=user_org_ids)
        else:
            user_org_ids = None  # Admin has access to all organizations

        # Apply organization filter
        if organization:
            if user_org_ids is not None and organization not in user_org_ids:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User does not have access to the specified organization.",
                )
            queryset = queryset.filter(organizationId__id=organization)

        # Apply tag filter
        if tag:
            tag_org_ids = get_tag_organization_ids(tag)
            if user_org_ids is not None:
                accessible_org_ids = set(user_org_ids).intersection(tag_org_ids)
                if not accessible_org_ids:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="No accessible organizations found for the specified tag.",
                    )
                queryset = queryset.filter(organizationId__id__in=accessible_org_ids)
            else:
                queryset = queryset.filter(organizationId__id__in=tag_org_ids)

        # Get total count
        total_domains = await sync_to_async(queryset.count)()

        # Return the count in the expected schema
        return {"value": total_domains}

    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@api_router.get(
    "/by-org/",
    response_model=List[ByOrgItem],
    tags=["Retrieve Stats"],
)
async def get_by_org(
    organization: str = Query(None, description="Filter by organization ID"),
    tag: str = Query(None, description="Filter by tag"),
    current_user: User = Depends(get_current_active_user),
    redis_client: aioredis.Redis = Depends(get_redis_client),
):
    """
    Retrieves the count of open vulnerabilities grouped by organization from Redis.
    """
    try:
        # Retrieve data from Redis
        json_data = await redis_client.get("vulnerabilities_by_org")

        if json_data is None:
            raise HTTPException(status_code=404, detail="Data not found in cache.")

        vulnerabilities_data = json.loads(json_data)

        # Get user's organization IDs
        user_org_ids = await get_user_organization_ids(current_user)
        if not user_org_ids:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User does not belong to any organizations.",
            )

        # Check if user is a global admin
        is_admin = is_global_view_admin(current_user)

        # Determine accessible organizations
        if is_admin:
            accessible_org_ids = None
        else:
            accessible_org_ids = set(user_org_ids)

        # Apply filters
        if organization:
            if (
                accessible_org_ids is not None
                and organization not in accessible_org_ids
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User does not have access to the specified organization.",
                )
            accessible_org_ids = {organization}
        elif tag:
            tag_org_ids = get_tag_organization_ids(tag)
            if accessible_org_ids is not None:
                accessible_org_ids = accessible_org_ids.intersection(tag_org_ids)
            else:
                accessible_org_ids = set(tag_org_ids)
            if not accessible_org_ids:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No accessible organizations found for the specified tag.",
                )

        # Filter vulnerabilities
        if accessible_org_ids is not None:
            filtered_vulnerabilities = [
                vuln
                for vuln in vulnerabilities_data
                if vuln["orgId"] in accessible_org_ids
            ]
        else:
            filtered_vulnerabilities = vulnerabilities_data

        # Aggregate counts by organization
        org_counts = {}
        for vuln in filtered_vulnerabilities:
            org_id = vuln["orgId"]
            org_name = vuln["orgName"]
            if org_id not in org_counts:
                org_counts[org_id] = {
                    "id": org_name,
                    "orgId": org_id,
                    "value": 0,
                    "label": org_name,
                }
            org_counts[org_id]["value"] += 1

        # Convert to list and sort
        results = sorted(org_counts.values(), key=lambda x: x["value"], reverse=True)

        return results

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
