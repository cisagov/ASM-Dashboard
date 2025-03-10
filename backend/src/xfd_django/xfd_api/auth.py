"""Authentication utilities for the FastAPI application."""

# Standard Python Libraries
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import os
import re
from typing import Optional
from urllib.parse import urlencode
import uuid

# Third-Party Libraries
from django.conf import settings
from django.forms.models import model_to_dict
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
import jwt
import requests

# from .helpers import user_to_dict
from .models import ApiKey, Organization, OrganizationTag, Role, User

# JWT_ALGORITHM = "RS256"
JWT_SECRET = settings.JWT_SECRET
SECRET_KEY = settings.SECRET_KEY
JWT_ALGORITHM = settings.JWT_ALGORITHM
JWT_TIMEOUT_HOURS = settings.JWT_TIMEOUT_HOURS

api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)


def user_to_dict(user):
    """Take a user model object from django and sanitize fields for output."""
    user_dict = model_to_dict(user)  # Convert model to dict
    # Convert any UUID fields to strings
    if isinstance(user_dict.get("id"), uuid.UUID):
        user_dict["id"] = str(user_dict["id"])
    for key, val in user_dict.items():
        if isinstance(val, datetime):
            user_dict[key] = str(val)
    return user_dict


def create_jwt_token(user):
    """Create a JWT token for a given user."""
    payload = {
        "id": str(user.id),
        "email": user.email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=int(JWT_TIMEOUT_HOURS)),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_token_from_header(request: Request) -> Optional[str]:
    """Extract token from the Authorization header, allowing 'Bearer' or raw tokens."""
    auth_header = request.headers.get("Authorization")
    if auth_header:
        if auth_header.startswith("Bearer "):
            return auth_header[7:]  # Remove 'Bearer ' prefix
        return auth_header  # Return the token directly if no 'Bearer ' prefix
    return None


def get_user_by_api_key(api_key: str):
    """Get a user by their API key."""
    hashed_key = sha256(api_key.encode()).hexdigest()
    try:
        api_key_instance = ApiKey.objects.get(hashedKey=hashed_key)
        api_key_instance.lastUsed = datetime.now(timezone.utc)
        api_key_instance.save(update_fields=["lastUsed"])
        return api_key_instance.user
    except ApiKey.DoesNotExist:
        print("API Key not found")
        return None


# Endpoint Authorization Function
def get_current_active_user(
    request: Request,
    api_key: Optional[str] = Security(api_key_header),
    token: Optional[str] = Depends(get_token_from_header),
):
    """Ensure the current user is authenticated and active, supporting either API key or token."""
    user = None
    if api_key:
        user = get_user_by_api_key(api_key)
    elif token:
        # Check if token is an API key
        if re.match(r"^[A-Fa-f0-9]{32}$", token):
            user = get_user_by_api_key(token)
        else:
            try:
                # Decode token in Authorization header to get user
                payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                user_id = payload.get("id")

                if user_id is None:
                    print("No user ID found in token")
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid token",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                # Fetch the user by ID from the database
                user = User.objects.get(id=user_id)
            except jwt.ExpiredSignatureError:
                print("Token has expired")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has expired",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            except jwt.InvalidTokenError:
                print("Invalid token")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No valid authentication credentials provided",
        )

    if user is None:
        print("User not authenticated")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

    # Attach email to request state for logging
    request.state.user_email = user.email
    return user


# POST: /auth/okta-callback
async def handle_okta_callback(request):
    """POST API LOGIC."""
    body = await request.json()
    code = body.get("code", None)
    if code is None:
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Code not found in request body",
        )
    jwt_data = await get_jwt_from_code(code)
    print("JWT Data: {}".format(jwt_data))
    if jwt_data is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid authorization code or failed to retrieve tokens",
        )

    decoded_token = jwt_data.get("decoded_token")

    resp = await process_user(decoded_token)
    token = resp.get("token")

    # Create a JSONResponse object to return the response and set the cookie
    response = JSONResponse(
        content={"message": "User authenticated", "data": resp, "token": token}
    )
    response.set_cookie(key="token", value=token)

    # Set the 'crossfeed-token' cookie
    response.set_cookie(
        key="crossfeed-token",
        value=token,
        # httponly=True,  # This makes the cookie inaccessible to JavaScript
        # secure=True,    # Ensures the cookie is only sent over HTTPS
        # samesite="Lax"  # Restricts when cookies are sent
    )
    return response


async def process_user(decoded_token):
    """Process a user based on decoded token information."""
    user = User.objects.filter(email=decoded_token["email"]).first()
    if not user:
        # Create a new user if they don't exist from Okta fields in SAML Response
        user = User(
            email=decoded_token["email"],
            oktaId=decoded_token["sub"],
            firstName=decoded_token.get("given_name"),
            lastName=decoded_token.get("family_name"),
            userType="standard",
            invitePending=True,
        )
        user.save()
    else:
        # Update user oktaId (legacy users) and login time
        user.oktaId = decoded_token["sub"]
        user.lastLoggedIn = datetime.now()
        user.save()

    if user:
        if not JWT_SECRET:
            raise HTTPException(status_code=500, detail="JWT_SECRET is not defined")
        # Generate JWT token
        signed_token = jwt.encode(
            {
                "id": str(user.id),
                "email": user.email,
                "exp": datetime.utcnow() + timedelta(hours=int(JWT_TIMEOUT_HOURS)),
            },
            JWT_SECRET,
            algorithm=JWT_ALGORITHM,
        )

        process_resp = {"token": signed_token, "user": user_to_dict(user)}
        return process_resp
    else:
        raise HTTPException(status_code=400, detail="User not found")


async def get_jwt_from_code(auth_code: str):
    """Exchange authorization code for JWT tokens and decode."""
    try:
        callback_url = os.getenv("REACT_APP_COGNITO_CALLBACK_URL")
        client_id = os.getenv("REACT_APP_COGNITO_CLIENT_ID")
        domain = os.getenv("REACT_APP_COGNITO_DOMAIN")
        proxy_url = os.getenv("LZ_PROXY_URL")

        scope = "openid"
        authorize_token_url = "https://{}/oauth2/token".format(domain)
        authorize_token_body = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": auth_code,
            "redirect_uri": callback_url,
            "scope": scope,
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        # Set up proxies if PROXY_URL is defined
        proxies = None
        if proxy_url:
            proxies = {"http": proxy_url, "https": proxy_url}

        response = requests.post(
            authorize_token_url,
            headers=headers,
            data=urlencode(authorize_token_body),
            proxies=proxies,
            timeout=20,  # Timeout in seconds
        )
        token_response = response.json()
        # Convert the id_token to bytes
        id_token = token_response["id_token"].encode("utf-8")
        access_token = token_response.get("access_token")
        refresh_token = token_response.get("refresh_token")

        # Decode the token without verifying the signature (if needed)
        decoded_token = jwt.decode(id_token, options={"verify_signature": False})
        print("decoded token: {}".format(decoded_token))
        return {
            "refresh_token": refresh_token,
            "id_token": id_token,
            "access_token": access_token,
            "decoded_token": decoded_token,
        }

    except Exception as error:
        print("get_jwt_from_code post error: {}".format(error))


def is_global_write_admin(current_user) -> bool:
    """Check if the user has global write admin permissions."""
    return current_user and current_user.userType == "globalAdmin"


def is_global_view_admin(current_user) -> bool:
    """Check if the user has global view permissions."""
    return current_user and current_user.userType in ["globalView", "globalAdmin"]


def is_regional_admin(current_user) -> bool:
    """Check if the user has regional admin permissions."""
    return current_user and current_user.userType in ["regionalAdmin", "globalAdmin"]


def is_org_admin(current_user, organization_id) -> bool:
    """Check if the user is an admin of the given organization."""
    if not organization_id:
        return False

    # Check if the user has an admin role in the given organization
    for role in current_user.roles.all():
        if str(role.organization.id) == str(organization_id) and role.role == "admin":
            return True

    # If the user is a global write admin, they are considered an org admin
    return is_global_write_admin(current_user)


def is_regional_admin_for_organization(current_user, organization_id) -> bool:
    """Check if user is a regional admin and if a selected organization belongs to their region."""
    if not organization_id:
        return False

    # Check if the user is a regional admin
    if is_regional_admin(current_user):
        # Check if the organization belongs to the user's region
        user_region_id = (
            current_user.regionId
        )  # Assuming this is available in the user object
        organization_region_id = get_organization_region(
            organization_id
        )  # Function to fetch the organization's region
        return user_region_id == organization_region_id

    return False


def can_access_user(current_user, target_user_id) -> bool:
    """Check if current user is allowed to modify.the target user."""
    if not target_user_id:
        return False

    # Check if the current user is the target user or a global write admin
    if str(current_user.id) == str(target_user_id) or is_global_write_admin(
        current_user
    ):
        return True

    # Check if the user is a regional admin and the target user is in the same region
    if is_regional_admin(current_user):
        target_user = User.objects.get(id=target_user_id)
        return current_user.regionId == target_user.regionId

    return False


def get_org_memberships(current_user) -> list[str]:
    """Return the organization IDs that a user is a member of."""
    # Check if the user has a 'roles' attribute and it's not None

    roles = Role.objects.filter(user=current_user)
    return [role.organization.id for role in roles if role.organization]


def get_organization_region(organization_id: str) -> str:
    """Fetch the region ID for the given organization."""
    organization = Organization.objects.get(id=organization_id)
    return organization.regionId


def get_tag_organizations(current_user, tag_id) -> list[str]:
    """Return the organizations belonging to a tag, if the user can access the tag."""
    # Check if the user is a global view admin
    if not is_global_view_admin(current_user):
        return []

    # Fetch the OrganizationTag and its related organizations
    tag = (
        OrganizationTag.objects.prefetch_related("organizations")
        .filter(id=tag_id)
        .first()
    )
    if tag:
        # Return a list of organization IDs
        return [org.id for org in tag.organizations.all()]

    # Return an empty list if tag is not found
    return []


def matches_user_region(current_user, user_region_id: str) -> bool:
    """Check if the current user's region matches the user's region being modified."""
    # Check if the current user is a global admin (can match any region)
    if is_global_write_admin(current_user):
        return True

    # Ensure the user has a region associated with them
    if not current_user.regionId or not user_region_id:
        return False

    # Compare the region IDs
    return user_region_id == current_user.regionId


def get_stats_org_ids(current_user, filters):
    """Get organization ids that a user has access to for the stats."""
    # Extract filters from the Pydantic model
    regions_filter = filters.filters.regions if filters and filters.filters else []
    organizations_filter = (
        filters.filters.organizations if filters and filters.filters else []
    )
    if organizations_filter == [""]:
        organizations_filter = []
    tags_filter = filters.filters.tags if filters and filters.filters else []

    # Final list of organization IDs
    organization_ids = set()

    # Case 1: Explicit organization IDs in filters
    if organizations_filter:
        # Check user type restrictions for provided organization IDs
        for org_id in organizations_filter:
            if (
                is_global_view_admin(current_user)
                or (is_regional_admin_for_organization(current_user, org_id))
                or (is_org_admin(current_user, org_id))
                or (get_org_memberships(current_user))
            ):
                organization_ids.add(org_id)

        if not organization_ids:
            raise HTTPException(
                status_code=403,
                detail="User does not have access to the specified organizations.",
            )

    # Case 2: Global view admin (if no explicit organization filter)
    elif is_global_view_admin(current_user):
        # Get organizations by region
        if regions_filter:
            organizations_by_region = Organization.objects.filter(
                regionId__in=regions_filter
            ).values_list("id", flat=True)
            organization_ids.update(organizations_by_region)

        # Get organizations by tag
        for tag_id in tags_filter:
            organizations_by_tag = get_tag_organizations(current_user, tag_id)
            organization_ids.update(organizations_by_tag)

    # Case 3: Regional admin
    elif current_user.userType in ["regionalAdmin"]:
        user_region_id = current_user.regionId

        # Allow only organizations in the user's region
        organizations_in_region = Organization.objects.filter(
            regionId=user_region_id
        ).values_list("id", flat=True)
        organization_ids.update(organizations_in_region)

        # Apply filters within the user's region
        if regions_filter and user_region_id in regions_filter:
            organization_ids.update(organizations_in_region)

        # Include organizations by tag within the same region
        for tag_id in tags_filter:
            tag_organizations = get_tag_organizations(current_user, tag_id)
            regional_tag_organizations = [
                org_id
                for org_id in tag_organizations
                if get_organization_region(org_id) == user_region_id
            ]
            organization_ids.update(regional_tag_organizations)

    # Case 4: Standard user
    else:
        # Allow only organizations where the user is a member
        user_organization_ids = current_user.roles.values_list(
            "organization_id", flat=True
        )
        organization_ids.update(user_organization_ids)

    return organization_ids
