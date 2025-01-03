"""/api-keys API logic"""

# Standard Python Libraries
import uuid

# Third-Party Libraries
from fastapi import HTTPException, status
from xfd_api.models import Notification
from xfd_api.schema_models.notification import Notification as NotificationSchema

from ..auth import get_org_memberships, is_global_view_admin


def post(data, current_user):
    """POST LOGIC"""
    # Check if user is GlobalViewAdmin or has memberships
    if not is_global_view_admin(current_user) and not get_org_memberships(current_user):
        raise HTTPException(status_code=403, detail="Unauthorized")
    data.extend(id=uuid.uuid4())
    # Create the record in the database
    result = Notification.objects.create(data)

    # Return Serialized data from Schema
    return NotificationSchema.from_orm(result).dict()


def delete(notification_id, current_user):
    """DELETE LOGIC"""
    try:
        # Check if user is GlobalViewAdmin or has memberships
        if not is_global_view_admin(current_user) and not get_org_memberships(
            current_user
        ):
            raise HTTPException(status_code=403, detail="Unauthorized")

        # Validate that key_id is a valid UUID
        uuid.UUID(notification_id)
        result = Notification.objects.get(id=notification_id, userId=current_user)

        # Delete the Item
        result.delete()
        return {"status": "success", "message": "Item deleted successfully"}
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Invalid id value"
        )
    except Notification.DoesNotExist:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Item not found"
        )


def get_all():
    """GET All LOGIC"""
    try:
        # Get all objects from the database
        result = Notification.objects.all()

        # Convert each object to Schema using from_orm
        return [NotificationSchema.from_orm(item) for item in result]

    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


def get_by_id(notification_id, current_user):
    """GET by id"""
    try:
        # Check if user is GlobalViewAdmin or has memberships
        if not is_global_view_admin(current_user) and not get_org_memberships(
            current_user
        ):
            raise HTTPException(status_code=403, detail="Unauthorized")

        # Find the item by its id
        result = Notification.objects.get(id=notification_id)

        # Convert the result to Schema using from_orm
        return NotificationSchema.from_orm(result)

    except Notification.DoesNotExist:
        raise HTTPException(status_code=404, detail="Item not found")
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


# TODO: Adding placeholder until we determine if we still need this.
# def get_508_banner(current_user):
#     """GET 508 banner."""

#     # Remove logic if no longer needed or update to actual return object.
#     try:
#         # Get the 508 banner from the DB
#         result = ""

#         # Format/Return Banner
#         return result

#     except Exception as error:
#         raise HTTPException(status_code=500, detail=str(error))
