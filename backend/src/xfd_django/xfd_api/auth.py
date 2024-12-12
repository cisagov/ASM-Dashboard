"""Authentication utilities for the FastAPI application."""

# Standard Python Libraries
from datetime import datetime, timedelta, timezone
import hashlib
from hashlib import sha256
import os
from typing import List, Optional
from urllib.parse import urlencode
import uuid

# Third-Party Libraries
from asgiref.sync import sync_to_async
from django.conf import settings
from django.forms.models import model_to_dict
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
import requests

# from .helpers import user_to_dict
from .models import ApiKey, Domain, Organization, OrganizationTag, Role, Service, User

# JWT_ALGORITHM = "RS256"
JWT_SECRET = settings.JWT_SECRET
SECRET_KEY = settings.SECRET_KEY
JWT_ALGORITHM = settings.JWT_ALGORITHM
JWT_TIMEOUT_HOURS = settings.JWT_TIMEOUT_HOURS

api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)


def user_to_dict(user):
    """Takes a user model object from django and
    sanitizes fields for output.

    Args:
        user (django model): Django User model object

    Returns:
        dict: Returns sanitized and formated dict
    """
    user_dict = model_to_dict(user)  # Convert model to dict
    # Convert any UUID fields to strings
    if isinstance(user_dict.get("id"), uuid.UUID):
        user_dict["id"] = str(user_dict["id"])
    for key, val in user_dict.items():
        if isinstance(val, datetime):
            user_dict[key] = str(val)
    return user_dict


def create_jwt_token(user):
    """
    Create a JWT token for a given user.

    Args:
        user (User): The user object for whom the token is created.

    Returns:
        str: The encoded JWT token.
    """
    payload = {
        "id": str(user.id),
        "email": user.email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=int(JWT_TIMEOUT_HOURS)),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token):
    """
    Decode a JWT token to retrieve the user.

    Args:
        token (str): The JWT token to decode.

    Returns:
        User: The user object decoded from the token, or None if invalid or expired.
    """

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithm=JWT_ALGORITHM)
        user = User.objects.get(id=payload["id"])
        return user
    except (ExpiredSignatureError, InvalidTokenError, User.DoesNotExist):
        return None


def get_org_memberships(current_user) -> list[str]:
    """Returns the organization IDs that a user is a member of."""
    # Check if the user has a 'roles' attribute and it's not None

    roles = Role.objects.filter(user=current_user)
    return [role.organization.id for role in roles if role.organization]


async def get_user_domains(user_id: str) -> List[str]:
    """
    Retrieves a list of domain names associated with the user's organizations.
    """
    try:
        # Check if the user exists
        user_exists = await sync_to_async(User.objects.filter(id=user_id).exists)()
        if not user_exists:
            return []

        # Fetch organization IDs associated with the user
        organization_ids_qs = Role.objects.filter(user__id=user_id).values_list(
            "organization", flat=True
        )
        organization_ids = await sync_to_async(lambda qs: list(qs))(organization_ids_qs)

        if not organization_ids:
            return []

        # Fetch domain names associated with these organizations
        domain_names_qs = Domain.objects.filter(
            organization__in=organization_ids
        ).values_list("name", flat=True)
        domain_list = await sync_to_async(lambda qs: list(qs))(domain_names_qs)

        return domain_list
    except Exception as e:
        # Optionally, handle exceptions or return an empty list
        return []


def get_user_service_ids(user_id):
    """
    Retrieves service IDs associated with the organizations the user belongs to.
    """
    # Get organization IDs the user is a member of
    organization_ids = Role.objects.filter(user=user_id).values_list(
        "organization", flat=True
    )

    # Get domain IDs associated with these organizations
    domain_ids = Domain.objects.filter(organization__in=organization_ids).values_list(
        "id", flat=True
    )

    # Get service IDs associated with these domains
    service_ids = Service.objects.filter(domainId__in=domain_ids).values_list(
        "id", flat=True
    )

    return list(map(str, service_ids))  # Convert UUIDs to strings if necessary


async def get_user_organization_ids(user_id: str) -> List[str]:
    try:
        # Fetch organization IDs associated with the user
        organization_ids_qs = Role.objects.filter(user__id=user_id).values_list(
            "organization__id", flat=True
        )
        organization_ids = await sync_to_async(list)(organization_ids_qs)
        return [str(org_id) for org_id in organization_ids]
    except Exception:
        return []


def get_user_ports(user_id):
    """
    Retrieves port numbers associated with the organizations the user belongs to.
    """
    # Get organization IDs the user is a member of
    organization_ids = Role.objects.filter(user=user_id).values_list(
        "organization", flat=True
    )

    # Get domain IDs associated with these organizations
    domain_ids = Domain.objects.filter(organization__in=organization_ids).values_list(
        "id", flat=True
    )

    # Get ports associated with services of these domains
    ports = (
        Service.objects.filter(domainId__in=domain_ids)
        .values_list("port", flat=True)
        .distinct()
    )

    return list(ports)


def get_tag_organization_ids(current_user, tag_id: Optional[str] = None) -> list[str]:
    """Returns the organizations belonging to a tag, if the user can access the tag."""
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


def hash_key(key: str) -> str:
    """
    Helper to hash API key.

    Returns:
        str: hashed API key value
    """

    return hashlib.sha256(key.encode()).hexdigest()


# TODO: Confirm still needed
async def get_user_info_from_cognito(token):
    """Get user info from cognito."""
    jwks_url = f"https://cognito-idp.us-east-1.amazonaws.com/{os.getenv('REACT_APP_USER_POOL_ID')}/.well-known/jwks.json"
    response = requests.get(jwks_url)
    jwks = response.json()
    unverified_header = jwt.get_unverified_header(token)
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"],
            }
    user_info = decode_jwt_token(token)
    return user_info


async def get_token_from_header(request: Request) -> Optional[str]:
    """
    Extract token from the Authorization header, allowing 'Bearer' or raw tokens.

    Args:
        request (Request): The incoming request object.

    Returns:
        Optional[str]: The token extracted from the Authorization header, or None if missing.
    """
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


async def process_user(decoded_token, access_token, refresh_token):
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
        scope = "openid"
        authorize_token_url = f"https://{domain}/oauth2/token"
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

        response = requests.post(
            authorize_token_url, headers=headers, data=urlencode(authorize_token_body)
        )
        token_response = response.json()
        # Convert the id_token to bytes
        id_token = token_response["id_token"].encode("utf-8")
        access_token = token_response.get("access_token")
        refresh_token = token_response.get("refresh_token")

        # Decode the token without verifying the signature (if needed)
        decoded_token = jwt.decode(id_token, options={"verify_signature": False})
        print(f"decoded token: {decoded_token}")
        return {
            "refresh_token": refresh_token,
            "id_token": id_token,
            "access_token": access_token,
            "decoded_token": decoded_token,
        }

    except Exception as error:
        print(f"get_jwt_from_code post error: {error}")
        pass


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


def get_organization_region(organization_id: str) -> str:
    """Fetch the region ID for the given organization."""
    organization = Organization.objects.get(id=organization_id)
    return organization.regionId


def get_tag_organizations(current_user, tag_id) -> list[str]:
    """Returns the organizations belonging to a tag, if the user can access the tag."""
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
    """Checks if the current user's region matches the user's region being modified."""

    # Check if the current user is a global admin (can match any region)
    if is_global_write_admin(current_user):
        return True

    # Ensure the user has a region associated with them
    if not current_user.regionId or not user_region_id:
        return False

    # Compare the region IDs
    return user_region_id == current_user.regionId
