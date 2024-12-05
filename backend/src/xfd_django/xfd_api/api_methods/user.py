"""
User API.

"""
# Standard Python Libraries
from datetime import datetime
import os
from typing import List
import uuid

# Third-Party Libraries
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Prefetch
from django.forms import model_to_dict
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from ..auth import (
    can_access_user,
    is_global_view_admin,
    is_global_write_admin,
    is_org_admin,
    is_regional_admin,
    matches_user_region,
)
from ..helpers.email import (
    send_invite_email,
    send_registration_approved_email,
    send_registration_denied_email,
)
from ..helpers.regionStateMap import REGION_STATE_MAP
from ..models import Organization, Role, User
from ..schema_models.user import NewUser as NewUserSchema
from ..schema_models.user import UpdateUser as UpdateUserSchema
from ..schema_models.user import User as UserSchema


def is_valid_uuid(val: str) -> bool:
    """Check if the given string is a valid UUID."""
    try:
        uuid_obj = uuid.UUID(val, version=4)
    except ValueError:
        return False
    return str(uuid_obj) == val

# GET: /users/me
def get_me(current_user):
    """Get current user."""
    # Fetch the user and related objects from the database
    user = User.objects.prefetch_related(
        Prefetch('roles', queryset=Role.objects.select_related('organization')),
        Prefetch('apiKeys')
    ).get(id=str(current_user.id))

    # Convert the user object to a dictionary
    user_dict = model_to_dict(user)

    # Add id: model_to_dict does not automatically include
    user_dict['id'] = str(user.id)

    # Include roles with their related organization
    user_dict['roles'] = [
        {
            "id": role.id,
            "role": role.role,
            "approved": role.approved,
            "organization": model_to_dict(role.organization) if role.organization else None
        }
        for role in user.roles.all()
    ]

    # Include API keys
    user_dict['apiKeys'] = list(user.apiKeys.values('id', 'createdAt', 'updatedAt', 'lastUsed', 'hashedKey', 'lastFour'))

    return user_dict

# POST: /users/me/acceptTerms
def accept_terms(version_data, current_user):
    """Accept the latest terms of service."""
    try:
        version = version_data.version
        if not version:
            raise HTTPException(
                status_code=400, detail="Missing version in request body."
            )

        current_user.dateAcceptedTerms = datetime.now()
        current_user.acceptedTermsVersion = version
        current_user.save()

        return {
            "id": str(current_user.id),
            "cognitoId": current_user.cognitoId,
            "oktaId": current_user.oktaId,
            "loginGovId": current_user.loginGovId,
            "createdAt": current_user.createdAt.isoformat() if current_user.createdAt else None,
            "updatedAt": current_user.updatedAt.isoformat() if current_user.updatedAt else None,
            "firstName": current_user.firstName,
            "lastName": current_user.lastName,
            "fullName": current_user.fullName,
            "email": current_user.email,
            "invitePending": current_user.invitePending,
            "loginBlockedByMaintenance": current_user.loginBlockedByMaintenance,
            "dateAcceptedTerms": current_user.dateAcceptedTerms.isoformat() if current_user.dateAcceptedTerms else None,
            "acceptedTermsVersion": current_user.acceptedTermsVersion,
            "lastLoggedIn": current_user.lastLoggedIn.isoformat() if current_user.lastLoggedIn else None,
            "userType": current_user.userType,
            "regionId": current_user.regionId,
            "state": current_user.state,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# DELETE: /users/{userId}
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
    if not can_access_user(current_user, target_user_id):
        return HTTPException(status_code=401, detail="Unauthorized")

    try:
        target_user = User.objects.get(id=target_user_id)
        result = target_user.delete()
        return JSONResponse(status_code=200, content={"result": result})

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# GET: /users
def get_users(current_user):
    """
    Retrieve a list of all users.
    Args:
        current_user : The user making the request.

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

# GET: /users/regionId/{regionId}
def get_users_by_region_id(current_user, region_id):
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

# GET: /users/state/{state}
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

# GET: /v2/users
def get_users_v2(state, regionId, invitePending, current_user):
    """Retrieve a list of users based on optional filter parameters."""
    try:
        # Check if user is a regional admin or global admin
        if not is_regional_admin(current_user):
            raise HTTPException(status_code=401, detail="Unauthorized")
        
        filters = {}

        if state is not None:
            filters["state"] = state
        if regionId is not None:
            filters["regionId"] = regionId
        if invitePending is not None:
            filters["invitePending"] = invitePending

        users = User.objects.filter(**filters).prefetch_related("roles__organization")

        # Return the updated user details
        return [
            {
                "id": str(user.id),
                "createdAt": user.createdAt.isoformat(),
                "updatedAt": user.updatedAt.isoformat(),
                "firstName": user.firstName,
                "lastName": user.lastName,
                "fullName": user.fullName,
                "email": user.email,
                "regionId": user.regionId,
                "state": user.state,
                "userType": user.userType,
                "lastLoggedIn": user.lastLoggedIn,
                "roles": [
                    {
                        "id": str(role.id),
                        "organization": {
                            "id": str(role.organization.id),
                            "name": role.organization.name,
                        } if role.organization else None,
                    }
                    for role in user.roles.all()
                ],
            }
            for user in users
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# POST: /users/{userId}
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

# PUT: /v2/users/{user_id}
def update_user_v2(user_id, user_data, current_user):
    """Update a particular user."""
    try:
        # Validate that the user ID is a valid UUID
        if not user_id or not is_valid_uuid(user_id):
            raise HTTPException(status_code=404, detail="User not found")

        # Check if the current user has permission to access/update this user
        if not can_access_user(current_user, user_id):
            raise HTTPException(status_code=403, detail="Unauthorized access.")

        # Fetch the user to be updated
        try:
            user = User.objects.prefetch_related("roles").get(id=user_id)
        except User.DoesNotExist:
            raise HTTPException(status_code=404, detail="User not found")

        # Global admins only can update the userType
        if not is_global_write_admin(current_user) and user_data.userType:
            raise HTTPException(status_code=403, detail="Only global admins can update userType.")

        # Update fields
        if user_data.state:
            user.regionId = REGION_STATE_MAP.get(user_data.state)

        print(user_data.dict())
        # Check for invitePending explicitly
        if "invitePending" in user_data.dict():
            user.invitePending = user_data.invitePending
        for field, value in user_data.dict(exclude_defaults=True).items():
            setattr(user, field, value)

        # Save the updated user
        user.save()

        # Fetch updated user with roles and related data
        updated_user = User.objects.prefetch_related("roles__organization").get(id=user_id)

        # Return the updated user details
        return {
            "id": str(updated_user.id),
            "createdAt": updated_user.createdAt.isoformat(),
            "updatedAt": updated_user.updatedAt.isoformat(),
            "firstName": updated_user.firstName,
            "lastName": updated_user.lastName,
            "fullName": user.fullName,
            "email": updated_user.email,
            "regionId": updated_user.regionId,
            "state": updated_user.state,
            "userType": updated_user.userType,
            "lastLoggedIn": user.lastLoggedIn,
            "roles": [
                {
                    "id": str(role.id),
                    "organization": {
                        "id": str(role.organization.id),
                        "name": role.organization.name,
                    } if role.organization else None,
                }
                for role in updated_user.roles.all()
            ],
        }
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        print(f"Error updating user: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")

# PUT: /users/{user_id}/register/approve
def approve_user_registration(user_id, current_user):
    """Approve a registered user."""
    if not is_valid_uuid(user_id):
        raise HTTPException(status_code=404, detail="Invalid user ID.")

    try:
        # Retrieve the user by ID
        user = User.objects.get(id=user_id)
    except ObjectDoesNotExist:
        raise HTTPException(status_code=404, detail="User not found.")

    # Ensure authorizer's region matches the user's region
    if not matches_user_region(current_user, user.regionId):
        raise HTTPException(status_code=403, detail="Unauthorized region access.")

    # Send email notification
    try:
        send_registration_approved_email(
            user.email,
            subject="CyHy Dashboard Registration Approved",
            first_name=user.firstName,
            last_name=user.lastName,
            template="crossfeed_approval_notification.html",
        )

    except HTTPException as http_exc:
        raise http_exc

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")

    return {"statusCode": 200, "body": "User registration approved."}


# PUT: /users/{user_id}/register/deny
def deny_user_registration(user_id: str, current_user: User):
    """Deny a user's registration by user ID."""

    # Validate UUID format for the user_id
    if not is_valid_uuid(user_id):
        raise HTTPException(status_code=404, detail="User not found.")

    try:
        # Retrieve the user object
        user = User.objects.filter(id=user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        # Ensure authorizer's region matches the user's region
        if not matches_user_region(current_user, user.regionId):
            raise HTTPException(status_code=403, detail="Unauthorized region access.")

        # Send registration denial email to the user
        send_registration_denied_email(
            user.email,
            subject="CyHy Dashboard Registration Denied",
            first_name=user.firstName,
            last_name=user.lastName,
            template="crossfeed_denial_notification.html",
        )

        return {"statusCode": 200, "body": "User registration denied."}

    except HTTPException as http_exc:
        raise http_exc
    except ObjectDoesNotExist:
        raise HTTPException(status_code=404, detail="User not found.")
    except Exception as e:
        print(f"Error denying registration: {e}")
        raise HTTPException(
            status_code=500, detail="Error processing registration denial."
        )

# POST: /users
def invite(new_user_data, current_user):
    """Invite a user."""

    try:
        # Validate permissions
        if new_user_data.organization:
            if not is_org_admin(current_user, new_user_data.organization):
                raise HTTPException(status_code=403, detail="Unauthorized access.")
        else:
            if not is_global_write_admin(current_user):
                raise HTTPException(status_code=403, detail="Unauthorized access.")

        # Non-global admins cannot set userType
        if not is_global_write_admin(current_user) and new_user_data.userType:
            raise HTTPException(status_code=403, detail="Unauthorized access.")

        # Lowercase the email for consistency
        new_user_data.email = new_user_data.email.lower()

        # Map state to region ID if state is provided
        if new_user_data.state:
            new_user_data.regionId = REGION_STATE_MAP.get(new_user_data.state)

        # Check if the user already exists
        user = User.objects.filter(email=new_user_data.email).first()
        organization = (
            Organization.objects.filter(id=new_user_data.organization).first()
            if new_user_data.organization
            else None
        )

        if not user:
            # Create a new user if they do not exist
            user = User.objects.create(
                invitePending=True,
                **new_user_data.dict(
                    exclude_unset=True,
                    exclude={"organizationAdmin", "organization", "userType"},
                ),
            )
            if not os.getenv("IS_LOCAL"):
                send_invite_email(user.email, organization)
        elif not user.firstName and not user.lastName:
            # Update first and last name if the user exists but has no name set
            user.firstName = new_user_data.firstName
            user.lastName = new_user_data.lastName
            user.save()

        # Always update userType if specified
        if new_user_data.userType:
            user.userType = new_user_data.userType
            user.save()

        # Assign role if an organization is specified
        if organization:
            Role.objects.update_or_create(
                user=user,
                organization=organization,
                defaults={
                    "approved": True,
                    "createdBy": current_user,
                    "approvedBy": current_user,
                    "role": "admin" if new_user_data.organizationAdmin else "user",
                },
            )
        # Return the updated user with relevant details
        return {
            "id": str(user.id),
            "firstName": user.firstName,
            "lastName": user.lastName,
            "email": user.email,
            "userType": user.userType,
            "roles": [
                {
                    "id": str(role.id),
                    "role": role.role,
                    "approved": role.approved,
                    "organization": {
                        "id": str(role.organization.id),
                        "name": role.organization.name,
                    }
                    if role.organization
                    else {},
                }
                for role in user.roles.select_related("organization").all()
            ],
            "invitePending": user.invitePending,
        }

    except HTTPException as http_exc:
        raise http_exc

    except Exception as e:
        print(f"Error inviting user: {e}")
        raise HTTPException(status_code=500, detail="Error inviting user.")