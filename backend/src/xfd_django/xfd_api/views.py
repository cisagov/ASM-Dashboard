"""This module defines the API endpoints for the FastAPI application."""
# Standard Python Libraries
import os
from typing import List, Optional
from uuid import UUID

# Third-Party Libraries
from django.shortcuts import render
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse

# from .schemas import Cpe
from .api_methods import api_key as api_key_methods
from .api_methods import auth as auth_methods
from .api_methods import notification as notification_methods
from .api_methods import organization, proxy, scan, scan_tasks
from .api_methods.cpe import get_cpes_by_id
from .api_methods.cve import get_cves_by_id, get_cves_by_name
from .api_methods.domain import export_domains, get_domain_by_id, search_domains
from .api_methods.saved_search import (
    create_saved_search,
    delete_saved_search,
    get_saved_search,
    list_saved_searches,
    update_saved_search,
)
from .api_methods.search import export, search_post
from .api_methods.user import get_users
from .api_methods.vulnerability import (
    get_vulnerability_by_id,
    search_vulnerabilities,
    update_vulnerability,
)
from .auth import get_current_active_user
from .login_gov import callback, login
from .models import Assessment, Domain, User, Vulnerability
from .schema_models import organization as OrganizationSchema
from .schema_models import scan as scanSchema
from .schema_models import scan_tasks as scanTaskSchema
from .schema_models.api_key import ApiKey as ApiKeySchema
from .schema_models.cpe import Cpe as CpeSchema
from .schema_models.cve import Cve as CveSchema
from .schema_models.domain import Domain as DomainSchema
from .schema_models.domain import DomainFilters, DomainSearch
from .schema_models.notification import Notification as NotificationSchema
from .schema_models.role import Role as RoleSchema
from .schema_models.saved_search import SavedSearch as SavedSearchSchema
from .schema_models.search import SearchBody, SearchRequest, SearchResponse
from .schema_models.user import User as UserSchema
from .schema_models.vulnerability import Vulnerability as VulnerabilitySchema
from .schema_models.vulnerability import VulnerabilitySearch

# Define API router
api_router = APIRouter()


# Healthcheck endpoint
@api_router.get("/healthcheck", tags=["Testing"])
async def healthcheck():
    """
    Healthcheck endpoint.

    Returns:
        dict: A dictionary containing the health status of the application.
    """
    return {"status": "ok"}


# ========================================
#   Proxy Endpoints
# ========================================


# Matomo Proxy
@api_router.api_route(
    "/matomo/{path:path}",
    dependencies=[Depends(get_current_active_user)],
    tags=["Analytics"],
)
async def matomo_proxy(
    path: str, request: Request, current_user: User = Depends(get_current_active_user)
):
    """Proxy requests to the Matomo analytics instance."""
    # Public paths -- directly allowed
    allowed_paths = ["/matomo.php", "/matomo.js"]
    if any(
        [request.url.path.startswith(allowed_path) for allowed_path in allowed_paths]
    ):
        return await proxy.proxy_request(path, request, os.getenv("MATOMO_URL"))

    # Redirects for specific font files
    if request.url.path in [
        "/plugins/Morpheus/fonts/matomo.woff2",
        "/plugins/Morpheus/fonts/matomo.woff",
        "/plugins/Morpheus/fonts/matomo.ttf",
    ]:
        return RedirectResponse(
            url=f"https://cdn.jsdelivr.net/gh/matomo-org/matomo@3.14.1{request.url.path}"
        )

    # Ensure only global admin can access other paths
    if current_user.userType != "globalAdmin":
        raise HTTPException(status_code=403, detail="Unauthorized")

    # Handle the proxy request to Matomo
    return await proxy.proxy_request(
        request, os.getenv("MATOMO_URL", ""), path, cookie_name="MATOMO_SESSID"
    )


# P&E Proxy
@api_router.api_route(
    "/pe/{path:path}",
    dependencies=[Depends(get_current_active_user)],
    tags=["P&E Proxy"],
)
async def pe_proxy(
    path: str, request: Request, current_user: User = Depends(get_current_active_user)
):
    """Proxy requests to the P&E Django application."""
    # Ensure only Global Admin and Global View users can access
    if current_user.userType not in ["globalView", "globalAdmin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")

    # Handle the proxy request to the P&E Django application
    return await proxy.proxy_request(request, os.getenv("PE_API_URL", ""), path)


# ========================================
#   Assessment Endpoints
# ========================================


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
    dependencies=[Depends(get_current_active_user)],
    response_model=List[DomainSchema],
    tags=["Domains"],
)
async def call_search_domains(
    domain_search: DomainSearch, current_user: User = Depends(get_current_active_user)
):
    return search_domains(domain_search, current_user)


@api_router.post(
    "/domain/export",
    dependencies=[Depends(get_current_active_user)],
    tags=["Domains"],
)
async def call_export_domains(domain_search: DomainSearch):
    return export_domains(domain_search)


@api_router.get(
    "/domain/{domain_id}",
    dependencies=[Depends(get_current_active_user)],
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


@api_router.post(
    "/vulnerabilities/search",
    dependencies=[Depends(get_current_active_user)],
    response_model=List[VulnerabilitySchema],
    tags=["Vulnerabilities"],
)
async def call_search_vulnerabilities(
    vulnerability_search: VulnerabilitySearch,
    current_user: User = Depends(get_current_active_user),
):
    return search_vulnerabilities(vulnerability_search, current_user)


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


# ========================================
#   Auth Endpoints
# ========================================


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


# ========================================
#   Users Endpoints
# ========================================


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


# ========================================
#   Api-Key Endpoints
# ========================================


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


# ========================================
#   Saved Search  Endpoints
# ========================================


# Create a new saved search
@api_router.post(
    "/saved-searches",
    dependencies=[Depends(get_current_active_user)],
    response_model=SavedSearchSchema,
    tags=["Saved Search"],
)
async def call_create_saved_search(
    name: str,
    search_term: str,
    region_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Create a new saved search."""

    request = {
        "name": name,
        "searchTerm": search_term,
        "regionId": region_id,
        "createdById": current_user,
    }

    return create_saved_search(request)


# Get all existing saved searches
@api_router.get(
    "/saved-searches",
    dependencies=[Depends(get_current_active_user)],
    response_model=List[SavedSearchSchema],
    tags=["Saved Search"],
)
async def call_list_saved_searches():
    """Retrieve a list of all saved searches."""
    return list_saved_searches()


# Get individual saved search by ID
@api_router.get(
    "/saved-searches/{saved_search_id}",
    dependencies=[Depends(get_current_active_user)],
    response_model=SavedSearchSchema,
    tags=["Saved Search"],
)
async def call_get_saved_search(saved_search_id: str):
    """Retrieve a saved search by its ID."""
    return get_saved_search(saved_search_id)


# Update saved search by ID
@api_router.put(
    "/saved-searches/{saved_search_id}",
    dependencies=[Depends(get_current_active_user)],
    response_model=SavedSearchSchema,
    tags=["Saved Search"],
)
async def call_update_saved_search(
    saved_search_id: str,
    name: str,
    search_term: str,
    current_user: User = Depends(get_current_active_user),
):
    """Update a saved search by its ID."""

    request = {
        "name": name,
        "saved_search_id": saved_search_id,
        "searchTerm": search_term,
    }

    return update_saved_search(request)


# Delete saved search by ID
@api_router.delete(
    "/saved-searches/{saved_search_id}",
    dependencies=[Depends(get_current_active_user)],
    tags=["Saved Search"],
)
async def call_delete_saved_search(saved_search_id: str):
    """Delete a saved search by its ID."""
    return delete_saved_search(saved_search_id)


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


# ========================================
#   Notification Endpoints
# ========================================


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


# ========================================
#   Scan Task Endpoints
# ========================================


@api_router.post(
    "/scan-tasks/search",
    dependencies=[Depends(get_current_active_user)],
    response_model=scanTaskSchema.ScanTaskListResponse,
    tags=["Scan Tasks"],
)
async def list_scan_tasks(
    search_data: Optional[scanTaskSchema.ScanTaskSearch] = Body(None),
    current_user: User = Depends(get_current_active_user),
):
    """List scan tasks based on filters."""
    return scan_tasks.list_scan_tasks(search_data, current_user)


@api_router.post(
    "/scan-tasks/{scan_task_id}/kill",
    dependencies=[Depends(get_current_active_user)],
    tags=["Scan Tasks"],
)
async def kill_scan_tasks(
    scan_task_id: UUID, current_user: User = Depends(get_current_active_user)
):
    """Kill a scan task."""
    return scan_tasks.kill_scan_task(scan_task_id, current_user)


@api_router.get(
    "/scan-tasks/{scan_task_id}/logs",
    dependencies=[Depends(get_current_active_user)],
    # response_model=scanTaskSchema.GenericResponse,
    tags=["Scan Tasks"],
)
async def get_scan_task_logs(
    scan_task_id: UUID, current_user: User = Depends(get_current_active_user)
):
    """Get logs from a particular scan task."""
    return scan_tasks.get_scan_task_logs(scan_task_id, current_user)


# ========================================
#   Organization Endpoints
# ========================================


@api_router.get(
    "/organizations",
    dependencies=[Depends(get_current_active_user)],
    response_model=List[OrganizationSchema.GetOrganizationSchema],
    tags=["Organizations"],
)
async def list_organizations(current_user: User = Depends(get_current_active_user)):
    """Retrieve a list of all organizations."""
    return organization.list_organizations(current_user)


@api_router.get(
    "/organizations/tags",
    dependencies=[Depends(get_current_active_user)],
    response_model=List[OrganizationSchema.GetTagSchema],
    tags=["Organizations"],
)
async def get_organization_tags(current_user: User = Depends(get_current_active_user)):
    """Retrieve a list of organization tags."""
    return organization.get_tags(current_user)


@api_router.get(
    "/organizations/{organization_id}",
    dependencies=[Depends(get_current_active_user)],
    response_model=OrganizationSchema.GetSingleOrganizationSchema,
    tags=["Organizations"],
)
async def get_organization(
    organization_id: str, current_user: User = Depends(get_current_active_user)
):
    """Retrieve an organization by its ID."""
    return organization.get_organization(organization_id, current_user)


@api_router.get(
    "/organizations/state/{state}",
    dependencies=[Depends(get_current_active_user)],
    response_model=List[OrganizationSchema.GetOrganizationSchema],
    tags=["Organizations"],
)
async def get_organizations_by_state(
    state: str, current_user: User = Depends(get_current_active_user)
):
    """Retrieve organizations by state."""
    return organization.get_by_state(state, current_user)


@api_router.get(
    "/organizations/regionId/{region_id}",
    dependencies=[Depends(get_current_active_user)],
    response_model=List[OrganizationSchema.GetOrganizationSchema],
    tags=["Organizations"],
)
async def get_organizations_by_region(
    region_id: str, current_user: User = Depends(get_current_active_user)
):
    """Retrieve organizations by region ID."""
    return organization.get_by_region(region_id, current_user)


@api_router.get(
    "/regions",
    dependencies=[Depends(get_current_active_user)],
    response_model=List[OrganizationSchema.RegionSchema],
    tags=["Regions"],
)
async def list_regions(current_user: User = Depends(get_current_active_user)):
    """Retrieve a list of all regions."""
    return organization.get_all_regions(current_user)


@api_router.post(
    "/organizations",
    dependencies=[Depends(get_current_active_user)],
    response_model=OrganizationSchema.GetSingleOrganizationSchema,
    tags=["Organizations"],
)
async def create_organization(
    organization_data: OrganizationSchema.NewOrganization,
    current_user: User = Depends(get_current_active_user),
):
    """Create a new organization."""
    return organization.create_organization(organization_data, current_user)


@api_router.post(
    "/organizations_upsert",
    dependencies=[Depends(get_current_active_user)],
    response_model=OrganizationSchema.GetSingleOrganizationSchema,
    tags=["Organizations"],
)
async def upsert_organization(
    organization_data: OrganizationSchema.NewOrganization,
    current_user: User = Depends(get_current_active_user),
):
    """Upsert an organization."""
    return organization.upsert_organization(organization_data, current_user)


@api_router.put(
    "/organizations/{organization_id}",
    dependencies=[Depends(get_current_active_user)],
    response_model=OrganizationSchema.GetSingleOrganizationSchema,
    tags=["Organizations"],
)
async def update_organization(
    organization_id: str,
    org_data: OrganizationSchema.NewOrganization,
    current_user: User = Depends(get_current_active_user),
):
    """Update an organization by its ID."""
    return organization.update_organization(organization_id, org_data, current_user)


@api_router.delete(
    "/organizations/{organization_id}",
    dependencies=[Depends(get_current_active_user)],
    response_model=OrganizationSchema.GenericMessageResponseModel,
    tags=["Organizations"],
)
async def delete_organization(
    organization_id: str, current_user: User = Depends(get_current_active_user)
):
    """Delete an organization by its ID."""
    return organization.delete_organization(organization_id, current_user)


@api_router.post(
    "/v2/organizations/{organization_id}/users",
    dependencies=[Depends(get_current_active_user)],
    response_model=OrganizationSchema.GenericPostResponseModel,
    tags=["Organizations"],
)
async def add_user_to_organization_v2(
    organization_id: str,
    user_data: OrganizationSchema.NewOrgUser,
    current_user: User = Depends(get_current_active_user),
):
    """Add a user to an organization."""
    return organization.add_user_to_org_v2(organization_id, user_data, current_user)


@api_router.post(
    "/organizations/{organization_id}/roles/{role_id}/approve",
    dependencies=[Depends(get_current_active_user)],
    response_model=OrganizationSchema.GenericMessageResponseModel,
    tags=["Organizations"],
)
async def approve_role(
    organization_id: str,
    role_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Approve a role within an organization."""
    return organization.approve_role(organization_id, role_id, current_user)


@api_router.post(
    "/organizations/{organization_id}/roles/{role_id}/remove",
    dependencies=[Depends(get_current_active_user)],
    response_model=OrganizationSchema.GenericMessageResponseModel,
    tags=["Organizations"],
)
async def remove_role(
    organization_id: str,
    role_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Remove a role from an organization."""
    return organization.remove_role(organization_id, role_id, current_user)


@api_router.post(
    "/organizations/{organization_id}/granularScans/{scan_id}/update",
    dependencies=[Depends(get_current_active_user)],
    response_model=OrganizationSchema.GetSingleOrganizationSchema,
    tags=["Organizations"],
)
async def update_granular_scan(
    organization_id: str,
    scan_id: str,
    scan_data: OrganizationSchema.NewOrgScan,
    current_user: User = Depends(get_current_active_user),
):
    """Update a granular scan for an organization."""
    return organization.update_org_scan(
        organization_id, scan_id, scan_data, current_user
    )


@api_router.get(
    "/v2/organizations",
    dependencies=[Depends(get_current_active_user)],
    response_model=List[OrganizationSchema.GetOrganizationSchema],
    tags=["Organizations"],
)
async def list_organizations_v2(
    state: Optional[List[str]] = Query(None),
    regionId: Optional[List[str]] = Query(None),
    current_user: User = Depends(get_current_active_user),
):
    """Retrieve a list of all organizations (version 2)."""
    return organization.list_organizations_v2(state, regionId, current_user)


# ========================================
#   Search Endpoints
# ========================================


@api_router.post(
    "/search",
    dependencies=[Depends(get_current_active_user)],
    response_model=SearchResponse,
    tags=["Search"],
)
async def search(request: SearchRequest):
    try:
        search_post(request)

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@api_router.post(
    "/search/export", dependencies=[Depends(get_current_active_user)], tags=["Search"]
)
async def export_endpoint(request: Request):
    try:
        body = await request.json()
        search_body = SearchBody(**body)  # Parse request body into SearchBody
        result = export(search_body, request)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
