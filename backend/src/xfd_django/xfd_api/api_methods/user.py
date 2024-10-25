"""
User API.

"""
# Standard Python Libraries
from datetime import datetime
from typing import List, Optional

# Third-Party Libraries
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from ..auth import (
    can_access_user,
    is_global_view_admin,
    is_global_write_admin,
    is_regional_admin,
)
from ..models import User
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
def delete_user(request: Request):
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
        target_user_id = request.path_params["user_id"]
        target_user = User.objects.get(id=target_user_id)
        result = target_user.delete()
        return JSONResponse(status_code=200, content={"result": result})

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def get_users(request: Request):
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
        current_user = request.state.user
        if not (is_global_view_admin(current_user) or is_regional_admin(current_user)):
            raise HTTPException(status_code=401, detail="Unauthorized")

        users = User.objects.all().prefetch_related("roles", "roles.organization")
        return [UserSchema.model_validate(user) for user in users]

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def get_users_v2(request: Request):
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
        query_params = request.query_params
        filters = {}

        if "state" in query_params:
            filters["state"] = query_params["state"]
        if "regionId" in query_params:
            filters["regionId"] = query_params["regionId"]
        if "invitePending" in query_params:
            filters["invitePending"] = query_params["invitePending"]

        users = User.objects.filter(**filters).prefetch_related("roles")
        return [UserSchema.model_validate(user) for user in users]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def update_user(request: Request):
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
        # Check if the current user can access the user to be updated
        current_user = request.state.user
        target_user_id = request.path_params["user_id"]
        if not can_access_user(current_user, target_user_id):
            raise HTTPException(status_code=401, detail="Unauthorized")

        # Validate the user ID
        if not target_user_id or not User.objects.filter(id=target_user_id).exists():
            raise HTTPException(status_code=404, detail="User not found")

        # Parse and validate the request body
        body = await request.json()
        update_data = UpdateUserSchema(**body)

        # Check if the current user can set the userType
        if not is_global_write_admin(current_user) and update_data.userType:
            raise HTTPException(status_code=401, detail="Unauthorized to set userType")

        # Retrieve the user to be updated
        user = User.objects.get(id=target_user_id)
        user.firstName = update_data.firstName or user.firstName
        user.lastName = update_data.lastName or user.lastName
        user.fullName = f"{user.firstName} {user.lastName}"
        user.userType = update_data.userType or user.userType

        # Save the updated user
        user.save()

        return user
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
