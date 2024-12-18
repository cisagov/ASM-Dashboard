"""This module defines the API endpoints for the FastAPI application."""
# Standard Python Libraries
import json
import os
from typing import List, Optional
from uuid import UUID

# Third-Party Libraries
from asgiref.sync import sync_to_async
from django.shortcuts import render
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from redis import asyncio as aioredis

# from .schemas import Cpe
from .api_methods import api_key as api_key_methods
from .api_methods import auth as auth_methods
from .api_methods import notification as notification_methods
from .api_methods import organization, proxy, scan, scan_tasks, user
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
from .api_methods.search import search_export, search_post
from .api_methods.stats import (
    get_by_org_stats,
    get_num_vulns,
    get_severity_stats,
    get_stats,
    get_user_ports_count,
    get_user_services_count,
    stats_latest_vulns,
    stats_most_common_vulns,
)
from .api_methods.user import (
    accept_terms,
    delete_user,
    get_me,
    get_users,
    get_users_by_region_id,
    get_users_by_state,
    get_users_v2,
    update_user,
    update_user_v2,
)
from .api_methods.vulnerability import (
    get_vulnerability_by_id,
    search_vulnerabilities,
    update_vulnerability,
)
from .auth import get_current_active_user
from .login_gov import callback, login
from .models import Domain, Organization, User, Vulnerability
from .schema_models import organization_schema as OrganizationSchema
from .schema_models import scan as scanSchema
from .schema_models import scan_tasks as scanTaskSchema
from .schema_models import stat_schema
from .schema_models.api_key import ApiKey as ApiKeySchema
from .schema_models.cpe import Cpe as CpeSchema
from .schema_models.cve import Cve as CveSchema
from .schema_models.domain import Domain as DomainSchema
from .schema_models.domain import DomainFilters, DomainSearch, TotalDomainsResponse
from .schema_models.notification import Notification as NotificationSchema
from .schema_models.role import Role as RoleSchema
from .schema_models.saved_search import (
    SavedSearchCreate,
    SavedSearchList,
    SavedSearchUpdate,
)
from .schema_models.saved_search import SavedSearch as SavedSearchSchema
from .schema_models.search import DomainSearchBody, SearchResponse
from .schema_models.user import (
    NewUser,
    NewUserResponseModel,
    RegisterUserResponse,
    UpdateUserV2,
)
from .schema_models.user import User as UserSchema
from .schema_models.user import UserResponse, UserResponseV2, VersionModel
from .schema_models.vulnerability import Vulnerability as VulnerabilitySchema
from .schema_models.vulnerability import VulnerabilitySearch

# Define API router
api_router = APIRouter()


async def default_identifier(request):
    """Return default identifier."""
    return request.headers.get("X-Real-IP", request.client.host)


async def get_redis_client(request: Request):
    """Get the Redis client from the application state."""
    return request.app.state.redis


# ========================================
#   Analytics
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
    tags=["Analytics"],
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
#   API Key Endpoints
# ========================================


# POST
@api_router.post("/api-keys", response_model=ApiKeySchema, tags=["API Keys"])
async def create_api_key(current_user: User = Depends(get_current_active_user)):
    """Create api key."""
    return api_key_methods.post(current_user)


# DELETE
@api_router.delete("/api-keys/{id}", tags=["API Keys"])
async def delete_api_key(
    id: str, current_user: User = Depends(get_current_active_user)
):
    """Delete api key by id."""
    return api_key_methods.delete(id, current_user)


# ========================================
#   Auth Endpoints
# ========================================


# Okta Callback
@api_router.post("/auth/okta-callback", tags=["Auth"])
async def okta_callback(request: Request):
    """Handle Okta Callback."""
    return await auth_methods.handle_okta_callback(request)


# Login
@api_router.get("/login", tags=["Auth"])
async def login_route():
    """Handle V1 Login."""
    return login()


# V1 Callback
@api_router.post("/auth/callback", tags=["Auth"])
async def callback_route(request: Request):
    """Handle V1 Callback."""
    body = await request.json()
    try:
        user_info = callback(body)
        return user_info
    except Exception as error:
        raise HTTPException(status_code=400, detail=str(error))


# ========================================
#   CPE Endpoints
# ========================================


@api_router.get(
    "/cpes/{cpe_id}",
    # dependencies=[Depends(get_current_active_user)],
    response_model=CpeSchema,
    tags=["CPEs"],
)
async def call_get_cpes_by_id(cpe_id):
    """
    Get Cpe by id.
    Returns:
        object: a single Cpe object.
    """
    return get_cpes_by_id(cpe_id)


# ========================================
#   CVE Endpoints
# ========================================


@api_router.get(
    "/cves/{cve_id}",
    # dependencies=[Depends(get_current_active_user)],
    response_model=CveSchema,
    tags=["CVEs"],
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
    tags=["CVEs"],
)
async def call_get_cves_by_name(cve_name):
    """
    Get Cve by name.
    Returns:
        object: a single Cpe object.
    """
    return get_cves_by_name(cve_name)


# ========================================
#   Domain Endpoints
# ========================================


@api_router.post(
    "/domain/search",
    dependencies=[Depends(get_current_active_user)],
    response_model=List[DomainSchema],
    tags=["Domains"],
)
async def call_search_domains(
    domain_search: DomainSearch, current_user: User = Depends(get_current_active_user)
):
    try:
        return search_domains(domain_search, current_user)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@api_router.post(
    "/domain/export",
    dependencies=[Depends(get_current_active_user)],
    tags=["Domains"],
)
async def call_export_domains(domain_search: DomainSearch):
    try:
        return export_domains(domain_search)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get(
    "/domain/{domain_id}",
    dependencies=[Depends(get_current_active_user)],
    # response_model=GetDomainResponse,
    tags=["Domains"],
)
async def call_get_domain_by_id(domain_id: str):
    """
    Get domain by id.
    Returns:
        object: a single Domain object.
    """
    return get_domain_by_id(domain_id)


# ========================================
#   Notification Endpoints
# ========================================


# POST
@api_router.post(
    "/notifications", response_model=NotificationSchema, tags=["Notifications"]
)
async def create_notification(current_user: User = Depends(get_current_active_user)):
    """Create notification key."""
    # return notification_handler.post(current_user)
    return []


# DELETE
@api_router.delete(
    "/notifications/{id}", response_model=NotificationSchema, tags=["Notifications"]
)
async def delete_notification(
    id: str, current_user: User = Depends(get_current_active_user)
):
    """Delete notification by id."""
    return notification_methods.delete(id, current_user)


# GET ALL: Doesn't require authentication
@api_router.get(
    "/notifications", response_model=List[NotificationSchema], tags=["Notifications"]
)
async def get_all_notifications():
    """Get all notifications."""
    return notification_methods.get_all()


# GET BY ID
@api_router.get(
    "/notifications/{id}", response_model=NotificationSchema, tags=["Notifications"]
)
async def get_notification(
    id: str, current_user: User = Depends(get_current_active_user)
):
    """Get notification by id."""
    return notification_methods.get_by_id(id, current_user)


# UPDATE BY ID
@api_router.put("/notifications/{id}", tags=["Notifications"])
async def update_notification(
    id: str, current_user: User = Depends(get_current_active_user)
):
    """Update notification key by id."""
    return notification_methods.delete(id, current_user)


# GET 508 Banner: Doesn't require authentication
@api_router.get("/notifications/508-banner", tags=["Notifications"])
async def get_508_banner():
    """Get notification by id."""
    return notification_methods.get_508_banner()


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


@api_router.post(
    "/search/organizations",
    dependencies=[Depends(get_current_active_user)],
    tags=["Organizations"],
)
async def search_organizations(
    search_body: OrganizationSchema.OrganizationSearchBody,
    current_user: User = Depends(get_current_active_user),
):
    """Search for organizations in Elasticsearch."""
    return organization.search_organizations_task(search_body, current_user)


# ========================================
#   Region Endpoints
# ========================================


@api_router.get(
    "/regions",
    dependencies=[Depends(get_current_active_user)],
    response_model=List[OrganizationSchema.RegionSchema],
    tags=["Regions"],
)
async def list_regions(current_user: User = Depends(get_current_active_user)):
    """Retrieve a list of all regions."""
    return organization.get_all_regions(current_user)


# ========================================
#   Saved Search  Endpoints
# ========================================


# Create a new saved search
@api_router.post(
    "/saved-searches",
    dependencies=[Depends(get_current_active_user)],
    response_model=SavedSearchSchema,
    tags=["Saved Searches"],
)
async def call_create_saved_search(
    saved_search: SavedSearchCreate,
    current_user: User = Depends(get_current_active_user),
):
    """Create a new saved search."""

    request = {
        "name": saved_search.name,
        "count": saved_search.count,
        "sortDirection": saved_search.sortDirection,
        "sortField": saved_search.sortField,
        "searchTerm": saved_search.searchTerm,
        "searchPath": saved_search.searchPath,
        "filters": saved_search.filters,
        "createdById": current_user,
    }

    return create_saved_search(request)


# Get all existing saved searches
@api_router.get(
    "/saved-searches",
    dependencies=[Depends(get_current_active_user)],
    response_model=SavedSearchList,
    tags=["Saved Searches"],
)
async def call_list_saved_searches(user: User = Depends(get_current_active_user)):
    """Retrieve a list of all saved searches."""
    return list_saved_searches(user)


# Get individual saved search by ID
@api_router.get(
    "/saved-searches/{saved_search_id}",
    dependencies=[Depends(get_current_active_user)],
    response_model=SavedSearchSchema,
    tags=["Saved Searches"],
)
async def call_get_saved_search(
    saved_search_id: str, current_user: User = Depends(get_current_active_user)
):
    """Retrieve a saved search by its ID."""
    return get_saved_search(saved_search_id, current_user)


# Update saved search by ID
@api_router.put(
    "/saved-searches/{saved_search_id}",
    dependencies=[Depends(get_current_active_user)],
    response_model=SavedSearchUpdate,
    tags=["Saved Searches"],
)
async def call_update_saved_search(
    saved_search: SavedSearchUpdate,
    saved_search_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Update a saved search by its ID."""

    request = {
        "saved_search_id": saved_search_id,
        "name": saved_search.name,
        "count": saved_search.count,
        "searchTerm": saved_search.searchTerm,
        "sortDirection": saved_search.sortDirection,
        "sortField": saved_search.sortField,
        "searchPath": saved_search.searchPath,
        "filters": saved_search.filters,
    }

    return update_saved_search(request, current_user)


# Delete saved search by ID
@api_router.delete(
    "/saved-searches/{saved_search_id}",
    dependencies=[Depends(get_current_active_user)],
    tags=["Saved Searches"],
)
async def call_delete_saved_search(
    saved_search_id: str, current_user: User = Depends(get_current_active_user)
):
    """Delete a saved search by its ID."""
    return delete_saved_search(saved_search_id, current_user)


# GET ALL
@api_router.get("/api-keys", response_model=List[ApiKeySchema], tags=["API Keys"])
async def get_all_api_keys(current_user: User = Depends(get_current_active_user)):
    """Get all api keys."""
    return api_key_methods.get_all(current_user)


# GET BY ID
@api_router.get("/api-keys/{id}", response_model=ApiKeySchema, tags=["API Keys"])
async def get_api_key(id: str, current_user: User = Depends(get_current_active_user)):
    """Get api key by id."""
    return api_key_methods.get_by_id(id, current_user)


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
#   Search Endpoints
# ========================================


@api_router.post(
    "/search",
    dependencies=[Depends(get_current_active_user)],
    response_model=SearchResponse,
    tags=["Search"],
)
async def search(
    search_body: DomainSearchBody, current_user: User = Depends(get_current_active_user)
):
    """ElasticSearch get domains index."""
    try:
        return await search_post(search_body, current_user)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@api_router.post(
    "/search/export", dependencies=[Depends(get_current_active_user)], tags=["Search"]
)
async def export_endpoint(
    search_body: DomainSearchBody, current_user: User = Depends(get_current_active_user)
):
    try:
        result = await search_export(search_body, current_user)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ========================================
#   Stat Endpoints
# ========================================


@api_router.post(
    "/stats",
    dependencies=[Depends(get_current_active_user)],
    response_model=stat_schema.StatsResponse,
    tags=["Stats"],
)
async def get_services(
    filter_data: OrganizationSchema.StatsPayloadSchema,
    current_user: User = Depends(get_current_active_user),
    redis_client=Depends(get_redis_client),
):
    """Retrieve all stats from Elasticache filtered by user."""
    return await get_stats(filter_data, current_user, redis_client)


@api_router.post(
    "/services",
    response_model=List[stat_schema.ServiceStat],
    dependencies=[Depends(get_current_active_user)],
    tags=["Stats"],
)
async def post(
    filter_data: OrganizationSchema.StatsPayloadSchema,
    current_user: User = Depends(get_current_active_user),
    redis_client=Depends(get_redis_client),
):
    """Retrieve services from Elasticache filtered by user."""
    return await get_user_services_count(filter_data, current_user, redis_client)


@api_router.post(
    "/ports",
    dependencies=[Depends(get_current_active_user)],
    response_model=List[stat_schema.PortStat],
    tags=["Stats"],
)
async def get_ports_stats(
    filter_data: OrganizationSchema.StatsPayloadSchema,
    current_user: User = Depends(get_current_active_user),
    redis_client=Depends(get_redis_client),
):
    """Retrieve Port Stats from Elasticache."""
    return await get_user_ports_count(filter_data, current_user, redis_client)


@api_router.post(
    "/num-vulns",
    dependencies=[Depends(get_current_active_user)],
    response_model=List[stat_schema.VulnerabilityStat],
    tags=["Stats"],
)
async def get_num_vulns_stats(
    filter_data: OrganizationSchema.StatsPayloadSchema,
    current_user: User = Depends(get_current_active_user),
    redis_client: aioredis.Redis = Depends(get_redis_client),
):
    """
    Retrieve number of vulnerabilities stats from ElastiCache (Redis) filtered by user.
    """
    return await get_num_vulns(filter_data, current_user, redis_client)


@api_router.post(
    "/latest-vulns",
    dependencies=[Depends(get_current_active_user)],
    response_model=List[stat_schema.LatestVulnerability],
    tags=["Stats"],
)
async def get_latest_vulnerabilities(
    filter_data: OrganizationSchema.StatsPayloadSchema,
    current_user: User = Depends(get_current_active_user),
    redis_client: aioredis.Redis = Depends(get_redis_client),
):
    return await stats_latest_vulns(filter_data, current_user, redis_client)


@api_router.post(
    "/most-common-vulns",
    dependencies=[Depends(get_current_active_user)],
    response_model=List[stat_schema.MostCommonVulnerability],
    tags=["Stats"],
)
async def get_most_common_vulns(
    filter_data: OrganizationSchema.StatsPayloadSchema,
    current_user: User = Depends(get_current_active_user),
    redis_client: aioredis.Redis = Depends(get_redis_client),
):
    return await stats_most_common_vulns(filter_data, current_user, redis_client)


@api_router.post(
    "/severity-counts",
    dependencies=[Depends(get_current_active_user)],
    response_model=List[stat_schema.SeverityCountStat],
    tags=["Stats"],
)
async def get_severity_counts(
    filter_data: OrganizationSchema.StatsPayloadSchema,
    current_user: User = Depends(get_current_active_user),
    redis_client: aioredis.Redis = Depends(get_redis_client),
):
    """
    Retrieves the count of open vulnerabilities grouped by severity from Redis.
    """
    return await get_severity_stats(filter_data, current_user, redis_client)


@api_router.post(
    "/by-org",
    dependencies=[Depends(get_current_active_user)],
    response_model=List[stat_schema.ByOrgStat],
    tags=["Stats"],
)
async def get_by_org(
    filter_data: OrganizationSchema.StatsPayloadSchema,
    current_user: User = Depends(get_current_active_user),
    redis_client: aioredis.Redis = Depends(get_redis_client),
):
    """
    Retrieves the count of open vulnerabilities grouped by severity from Redis.
    """
    return await get_by_org_stats(filter_data, current_user, redis_client)


# ========================================
#   Testing Endpoints
# ========================================


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
#   User Endpoints
# ========================================


@api_router.post(
    "/users/me/acceptTerms",
    response_model=UserSchema,
    dependencies=[Depends(get_current_active_user)],
    tags=["Users"],
)
async def call_accept_terms(
    version_data: VersionModel, current_user: User = Depends(get_current_active_user)
):
    """Accept the latest terms of service."""

    return accept_terms(version_data, current_user)


@api_router.get("/users/me", tags=["Users"])
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return get_me(current_user)


@api_router.delete(
    "/users/{userId}",
    response_model=OrganizationSchema.GenericMessageResponseModel,
    dependencies=[Depends(get_current_active_user)],
    tags=["Users"],
)
async def call_delete_user(
    userId: str, current_user: User = Depends(get_current_active_user)
):
    """Delete user."""
    return delete_user(userId, current_user)


@api_router.get(
    "/users",
    response_model=List[UserResponseV2],
    dependencies=[Depends(get_current_active_user)],
    tags=["Users"],
)
async def call_get_users(current_user: User = Depends(get_current_active_user)):
    """Get all users."""
    return get_users(current_user)


@api_router.get(
    "/users/regionId/{regionId}",
    response_model=List[UserSchema],
    dependencies=[Depends(get_current_active_user)],
    tags=["Users"],
)
async def call_get_users_by_region_id(
    regionId, current_user: User = Depends(get_current_active_user)
):
    """
    Call get_users_by_region_id()
    Args:
        request : The HTTP request containing query parameters.

    Raises:
        HTTPException: If the user is not authorized or no users are found.

    Returns:
        List[User]: A list of users matching the filter criteria.
    """
    return get_users_by_region_id(regionId, current_user)


@api_router.get(
    "/users/state/{state}",
    response_model=List[UserSchema],
    dependencies=[Depends(get_current_active_user)],
    tags=["Users"],
)
async def call_get_users_by_state(
    state, current_user: User = Depends(get_current_active_user)
):
    """
    Call get_users_by_state()
    Args:
        request : The HTTP request containing query parameters.

    Raises:
        HTTPException: If the user is not authorized or no users are found.

    Returns:
        List[User]: A list of users matching the filter criteria.
    """
    return get_users_by_state(state, current_user)


@api_router.get(
    "/v2/users",
    response_model=List[UserResponseV2],
    dependencies=[Depends(get_current_active_user)],
    tags=["Users"],
)
async def call_get_users_v2(
    state: Optional[str] = Query(None),
    regionId: Optional[str] = Query(None),
    invitePending: Optional[bool] = Query(None),
    current_user: User = Depends(get_current_active_user),
):
    """Get users with filter."""
    return get_users_v2(state, regionId, invitePending, current_user)


@api_router.put(
    "/v2/users/{user_id}",
    dependencies=[Depends(get_current_active_user)],
    response_model=UserResponseV2,
    tags=["Users"],
)
async def update_user_v2_view(
    user_id: str,
    user_data: UpdateUserV2,
    current_user: User = Depends(get_current_active_user),
):
    """Update a particular user."""
    return update_user_v2(user_id, user_data, current_user)


@api_router.post("/users/{userId}", tags=["Users"])
async def call_update_user(
    userId, body, current_user: User = Depends(get_current_active_user)
):
    """
    Update a user by ID.
    Args:
        userId : The ID of the user to update.
        request : The HTTP request containing authorization and target for update.

    Raises:
        HTTPException: If the user is not authorized or the user is not found.

    Returns:
        JSONResponse: The result of the update.
    """
    return update_user(userId, body, current_user)


@api_router.put(
    "/users/{user_id}/register/approve",
    dependencies=[Depends(get_current_active_user)],
    response_model=RegisterUserResponse,
    tags=["Users"],
)
async def register_approve(
    user_id: str, current_user: User = Depends(get_current_active_user)
):
    """Approve a registered user."""
    return user.approve_user_registration(user_id, current_user)


@api_router.put(
    "/users/{user_id}/register/deny",
    dependencies=[Depends(get_current_active_user)],
    response_model=RegisterUserResponse,
    tags=["Users"],
)
async def register_deny(
    user_id: str, current_user: User = Depends(get_current_active_user)
):
    """Deny a registered user."""
    return user.deny_user_registration(user_id, current_user)


@api_router.post(
    "/users",
    dependencies=[Depends(get_current_active_user)],
    response_model=NewUserResponseModel,
    tags=["Users"],
)
async def invite_user(
    new_user: NewUser, current_user: User = Depends(get_current_active_user)
):
    """Invite a user."""
    return user.invite(new_user, current_user)


# ========================================
#   Vulnerability Endpoints
# ========================================


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
    try:
        return search_vulnerabilities(vulnerability_search, current_user)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@api_router.post("/vulnerabilities/export", tags=["Vulnerabilities"])
async def export_vulnerabilities():
    try:
        pass
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get(
    "/vulnerabilities/{vulnerabilityId}",
    dependencies=[Depends(get_current_active_user)],
    response_model=VulnerabilitySchema,
    tags=["Vulnerabilities"],
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
    dependencies=[Depends(get_current_active_user)],
    response_model=VulnerabilitySchema,
    tags=["Vulnerabilities"],
)
async def call_update_vulnerability(
    vuln_id,
    data: VulnerabilitySchema,
    current_user: User = Depends(get_current_active_user),
):
    """
    Update vulnerability by id.

    Returns:
        object: a single vulnerability object that has been modified.
    """
    return update_vulnerability(vuln_id, data, current_user)
