"""
User API.

"""
# Standard Python Libraries
from typing import List, Optional

# Third-Party Libraries
from fastapi import HTTPException, Query
from django.db.models import Prefetch
from django.forms.models import model_to_dict

from ..models import User, Role
from ..schema_models.user import User as UserSchema


def get_me(current_user):
    """Get current user."""
    # Fetch the user and related objects from the database
    user = User.objects.prefetch_related(
        Prefetch('roles', queryset=Role.objects.select_related('organization')),
        Prefetch('apiKeys')
    ).get(id=str(current_user.id))

    # Convert the user object to a dictionary
    user_dict = model_to_dict(user, exclude=['password'])

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


def get_users(regionId):
    """
    Retrieve a list of users based on optional filter parameters.

    Args:
        regionId : Region ID to filter users by.
    Raises:
        HTTPException: If the user is not authorized or no users are found.

    Returns:
        List[User]: A list of users matching the filter criteria.
    """

    try:
        users = User.objects.filter(regionId=regionId).prefetch_related("roles")
        return [UserSchema.from_orm(user) for user in users]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
