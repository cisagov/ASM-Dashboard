"""Authentication utilities for the FastAPI application."""

# Standard Python Libraries
from datetime import datetime, timedelta, timezone
import hashlib
from hashlib import sha256
import os
from typing import Optional
from urllib.parse import urlencode
import uuid

# Third-Party Libraries
from django.conf import settings
from django.forms.models import model_to_dict
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
import requests

from .models import ApiKey, Organization, OrganizationTag, Role, User

JWT_SECRET = os.getenv("JWT_SECRET")
SECRET_KEY = settings.SECRET_KEY
JWT_ALGORITHM = "HS256"
JWT_TIMEOUT_HOURS = 4

api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)


def user_to_dict(user):
    """Takes a user model object from django and
    sanitizes fields for output.

    Args:
        user (django model): Django User model object

    Returns:
        dict: Returns sanitized and formated dict
    """
    user_dict = model_to_dict(user)
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
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_TIMEOUT_HOURS),
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
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = User.objects.get(id=payload["id"])
        return user
    except (ExpiredSignatureError, InvalidTokenError, User.DoesNotExist):
        return None


def hash_key(key: str) -> str:
    """
    Helper to hash API key.

    Returns:
        str: hashed API key value
    """

    return hashlib.sha256(key.encode()).hexdigest()


async def get_token_from_header(request: Request) -> str:
    """
    Extract token from the Authorization header, allowing 'Bearer' or raw tokens.

    Args:
        request (Request): The incoming request object.

    Returns:
        str: The token extracted from the Authorization header.

    Raises:
        HTTPException: If the Authorization header is missing or improperly formatted.
    """
    auth_header = request.headers.get("Authorization")
    if auth_header:
        if auth_header.startswith("Bearer "):
            return auth_header[7:]  # Remove 'Bearer ' prefix
        return auth_header  # Return the token directly if no 'Bearer ' prefix
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authorization header is missing",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_user_by_api_key(api_key: str):
    """Get a user by their API key."""
    hashed_key = sha256(api_key.encode()).hexdigest()
    try:
        api_key_instance = ApiKey.objects.get(hashedKey=hashed_key)
        api_key_instance.lastUsed = datetime.now(timezone.utc)
        api_key_instance.save(update_fields=["lastUsed"])
        return api_key_instance.userId
    except ApiKey.DoesNotExist:
        print("API Key not found")
        return None


# def get_current_active_user(
#     api_key: Optional[str] = Security(api_key_header),
#     token: Optional[str] = Depends(get_token_from_header),
# ):
#     """
#     Ensure the current user is authenticated and active, supporting API key or token.

#     Args:
#         api_key (Optional[str]): The API key provided in headers.
#         token (Optional[str]): The JWT token from the Authorization header.

#     Returns:
#         User: The authenticated user object.

#     Raises:
#         HTTPException: If authentication fails or credentials are invalid.
#     """
#     user = None
#     if api_key:
#         user = get_user_by_api_key(api_key)
#     else:
#         try:
#             payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
#             user_id = payload.get("id")

#             if user_id is None:
#                 raise HTTPException(
#                     status_code=status.HTTP_401_UNAUTHORIZED,
#                     detail="Invalid token",
#                     headers={"WWW-Authenticate": "Bearer"},
#                 )
#             user = User.objects.get(id=user_id)
#         except jwt.ExpiredSignatureError:
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="Token has expired",
#                 headers={"WWW-Authenticate": "Bearer"},
#             )
#         except jwt.InvalidTokenError:
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="Invalid token",
#                 headers={"WWW-Authenticate": "Bearer"},
#             )
#     if user is None:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid authentication credentials",
#         )
#     return user


def get_current_active_user(
    api_key: Optional[str] = Security(api_key_header),
    token: Optional[str] = Depends(get_token_from_header),
):
    """
    Ensure the current user is authenticated and active, supporting either API key or token.

    Args:
        api_key (Optional[str]): The API key provided in headers.
        token (Optional[str]): The JWT token from the Authorization header.

    Returns:
        User: The authenticated user object.

    Raises:
        HTTPException: If authentication fails or credentials are invalid.
    """
    user = None
    if api_key:
        user = get_user_by_api_key(api_key)
    elif token:
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = payload.get("id")

            if user_id is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            user = User.objects.get(id=user_id)
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidTokenError:
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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )
    return user


async def process_user(decoded_token, access_token, refresh_token):
    """Process a user based on decoded token information."""
    user = User.objects.filter(email=decoded_token["email"]).first()
    if not user:
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
        user.oktaId = decoded_token["sub"]
        user.lastLoggedIn = datetime.now()
        user.save()

    if user:
        if not JWT_SECRET:
            raise HTTPException(status_code=500, detail="JWT_SECRET is not defined")

        signed_token = jwt.encode(
            {
                "id": str(user.id),
                "email": user.email,
                "exp": datetime.utcnow() + timedelta(hours=JWT_TIMEOUT_HOURS),
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
        id_token = token_response["id_token"].encode("utf-8")
        access_token = token_response.get("access_token")
        refresh_token = token_response.get("refresh_token")

        decoded_token = jwt.decode(id_token, options={"verify_signature": False})
        return {
            "refresh_token": refresh_token,
            "id_token": id_token,
            "access_token": access_token,
            "decoded_token": decoded_token,
        }

    except Exception as error:
        print(f"get_jwt_from_code post error: {error}")
        pass


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
    for role in current_user.roles.all():
        if str(role.organization.id) == str(organization_id) and role.role == "admin":
            return True
    return is_global_write_admin(current_user)


def is_regional_admin_for_organization(current_user, organization_id) -> bool:
    """Check if user is a regional admin and if a selected organization belongs to their region."""
    if not organization_id:
        return False
    if is_regional_admin(current_user):
        user_region_id = current_user.regionId
        organization_region_id = get_organization_region(organization_id)
        return user_region_id == organization_region_id
    return False


def get_organization_region(organization_id: str) -> str:
    """Fetch the region ID for the given organization."""
    organization = Organization.objects.get(id=organization_id)
    return organization.regionId


def get_tag_organizations(current_user, tag_id) -> list[str]:
    """Returns the organizations belonging to a tag, if the user can access the tag."""
    if not is_global_view_admin(current_user):
        return []
    tag = (
        OrganizationTag.objects.prefetch_related("organizations")
        .filter(id=tag_id)
        .first()
    )
    if tag:
        return [org.id for org in tag.organizations.all()]
    return []


def get_org_memberships(current_user) -> list[str]:
    """Returns the organization IDs that a user is a member of."""
    roles = Role.objects.filter(user=current_user)
    if not roles:
        return []
    return [role.organization.id for role in roles if role.organization]


def matches_user_region(current_user, user_region_id: str) -> bool:
    """Checks if the current user's region matches the user's region being modified."""
    if is_global_write_admin(current_user):
        return True
    if not current_user.region_id or not user_region_id:
        return False
    return user_region_id == current_user.region_id
