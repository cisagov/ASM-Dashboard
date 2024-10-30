"""
User API.

"""
# Standard Python Libraries
from datetime import datetime
import inspect
from typing import List, Optional, Tuple

# Third-Party Libraries
from django.core.paginator import Paginator
from django.db.models import Q
from django.forms import model_to_dict
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from ..auth import (
    can_access_user,
    get_org_memberships,
    is_global_view_admin,
    is_global_write_admin,
    is_regional_admin,
)
from ..helpers.filter_helpers import sort_direction
from ..models import User
from ..schema_models.user import NewUser as NewUserSchema
from ..schema_models.user import UpdateUser as UpdateUserSchema
from ..schema_models.user import User as UserSchema


async def accept_terms(request: Request):
    """
    Accept the latest terms of service.
    Args:
        request : The HTTP request containing the user and the terms version.

    Returns:
        User: The updated user.
    """
    try:
        current_user = request.state.user
        if not current_user:
            raise HTTPException(status_code=401, detail="User not authenticated.")

        body = await request.json()
        version = body.get("version")
        if not version:
            raise HTTPException(
                status_code=400, detail="Missing version in request body."
            )

        current_user.dateAcceptedTerms = datetime.now()
        current_user.acceptedTermsVersion = version
        current_user.save()

        return UserSchema.model_validate(current_user)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


#  TODO: Add user context and permissions
def delete_user(current_user, target_user_id):
    """
    Delete a user by ID.
    Args:
        request : The HTTP request containing authorization and target for deletion..

    Raises:
        HTTPException: If the user is not authorized or the user is not found.

    Returns:
        JSONResponse: The result of the deletion.
    """

    try:
        # current_user = request.state.user
        target_user = User.objects.get(id=target_user_id)
        result = target_user.delete()
        return JSONResponse(status_code=200, content={"result": result})

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def get_users(current_user):
    """
    Retrieve a list of all users.
    Args:
        request : The HTTP request containing authorization information.

    Raises:
        HTTPException: If the user is not authorized.

    Returns:
        List[User]: A list of all users.
    """
    try:
        if not (is_global_view_admin(current_user)):
            raise HTTPException(status_code=401, detail="Unauthorized")

        users = User.objects.all().prefetch_related("roles", "roles.organization")
        return [UserSchema.model_validate(user) for user in users]

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def get_users_by_region_id(current_user, region_id):
    """
    List users with specific regionId.
    Args:
        request : The HTTP request containing the regionId.

    Returns:
        JSONResponse: The list of users with the specified regionId.
    """
    try:
        if not is_regional_admin(current_user):
            raise HTTPException(status_code=401, detail="Unauthorized")

        if not region_id:
            raise HTTPException(
                status_code=400, detail="Missing regionId in path parameters"
            )

        users = User.objects.filter(regionId=region_id).prefetch_related(
            "roles", "roles.organization"
        )
        if users:
            return JSONResponse(
                status_code=200,
                content=[UserSchema.model_validate(user) for user in users],
            )
        else:
            raise HTTPException(
                status_code=404, detail="No users found for the specified regionId"
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def get_users_by_state(state, current_user):
    """
    List users with specific state.
    Args:
        request : The HTTP request containing the state.

    Returns:
        JSONResponse: The list of users with the specified state.
    """
    try:
        if not is_regional_admin(current_user):
            raise HTTPException(status_code=401, detail="Unauthorized")

        if not state:
            raise HTTPException(
                status_code=400, detail="Missing state in path parameters"
            )

        users = User.objects.filter(state=state).prefetch_related(
            "roles", "roles.organization"
        )
        if users:
            return JSONResponse(
                status_code=200,
                content=[UserSchema.model_validate(user) for user in users],
            )
        else:
            raise HTTPException(
                status_code=404, detail="No users found for the specified state"
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def get_users_v2(state, regionId, invitePending, current_user):
    """
    Retrieve a list of users based on optional filter parameters.
    Args:
        request : The HTTP request containing query parameters.

    Raises:
        HTTPException: If the user is not authorized or no users are found.

    Returns:
        List[User]: A list of users matching the filter criteria.
    """
    try:
        filters = {}

        if state:
            filters["state"] = state
        if regionId:
            filters["regionId"] = regionId
        if invitePending:
            filters["invitePending"] = invitePending

        users = User.objects.filter(**filters).prefetch_related("roles")
        return [model_to_dict(user) for user in users]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def update_user(target_user_id, body, current_user):
    """
    Update a particular user.
    Args:
        request: The HTTP request containing the update data.

    Raises:
        HTTPException: If the user is not authorized or the user is not found.

    Returns:
        User: The updated user.
    """
    try:
        if not can_access_user(current_user, target_user_id):
            raise HTTPException(status_code=401, detail="Unauthorized")

        if not target_user_id or not User.objects.filter(id=target_user_id).exists():
            raise HTTPException(status_code=404, detail="User not found")

        update_data = NewUserSchema(**body)

        if not is_global_write_admin(current_user) and update_data.userType:
            raise HTTPException(status_code=401, detail="Unauthorized to set userType")

        user = User.objects.get(id=target_user_id)
        user.firstName = update_data.firstName or user.firstName
        user.lastName = update_data.lastName or user.lastName
        user.fullName = f"{user.firstName} {user.lastName}"
        user.userType = update_data.userType or user.userType
        user.state = update_data.state or user.state
        user.regionId = update_data.regionId or user.regionId
        user.email = update_data.email or user.email
        user.organization = update_data.organization or user.organization
        user.organizationAdmin = (
            update_data.organizationAdmin
            if update_data.organizationAdmin is not None
            else user.organizationAdmin
        )

        user.save()

        return UserSchema.model_validate(user)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def update_user_v2(request: Request):
    """
    Update a particular user.
    Args:
        request: The HTTP request containing the update data.

    Raises:
        HTTPException: If the user is not authorized or the user is not found.

    Returns:
        User: The updated user.
    """
    try:
        current_user = request.state.user
        target_user_id = request.path_params["user_id"]
        if not can_access_user(current_user, target_user_id):
            raise HTTPException(status_code=401, detail="Unauthorized")

        if not target_user_id or not User.objects.filter(id=target_user_id).exists():
            raise HTTPException(status_code=404, detail="User not found")

        body = await request.json()
        update_data = UpdateUserSchema(**body)

        if not is_global_write_admin(current_user) and update_data.userType:
            raise HTTPException(status_code=401, detail="Unauthorized to set userType")

        user = User.objects.get(id=target_user_id)
        user.firstName = update_data.firstName or user.firstName
        user.lastName = update_data.lastName or user.lastName
        user.fullName = f"{user.firstName} {user.lastName}"
        user.userType = update_data.userType or user.userType
        user.state = update_data.state or user.state
        user.regionId = update_data.regionId or user.regionId
        user.invitePending = (
            update_data.invitePending
            if update_data.invitePending is not None
            else user.invitePending
        )
        user.loginBlockedByMaintenance = (
            update_data.loginBlockedByMaintenance
            if update_data.loginBlockedByMaintenance is not None
            else user.loginBlockedByMaintenance
        )
        user.organization = update_data.organization or user.organization

        user.save()

        return UserSchema.model_validate(user)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
