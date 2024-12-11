"""/api-keys API logic"""

# Standard Python Libraries
from datetime import datetime, timezone
import hashlib
import secrets
import uuid

# Third-Party Libraries
from fastapi import HTTPException, status
from xfd_api.models import ApiKey
from xfd_api.schema_models.api_key import ApiKey as ApiKeySchema


def post(current_user):
    """POST API logic for creating a new API key."""
    # Generate a random 16-byte API key
    key = secrets.token_hex(16)

    # Hash the API key
    hashed_key = hashlib.sha256(key.encode()).hexdigest()

    # Create ApiKey instance in the database
    api_key_instance = ApiKey.objects.create(
        id=uuid.uuid4(),
        hashedKey=hashed_key,
        lastFour=key[-4:],
        user=current_user,
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )

    # Convert the Django model instance to the Pydantic model, excluding fields like hashedKey and user
    validated_data = ApiKeySchema.model_validate(api_key_instance).model_dump(
        exclude={"hashedKey", "user"}
    )

    # Add the actual API key to the response for initial display to the user
    validated_data["api_key"] = key

    return validated_data


def delete(id, current_user):
    """DELETE API LOGIC"""
    try:
        # Confirm id is a valid UUID
        uuid.UUID(id)

        # Delete by id
        api_key = ApiKey.objects.get(id=id)
        api_key.delete()

        # Delete Response TODO: confirm output
        return {"status": "success", "message": "API Key deleted successfully"}

    except ApiKey.DoesNotExist:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="API Key not found"
        )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Invalid API Key ID"
        )


def get_all(current_user):
    """GET All API LOGIC"""
    try:
        # Get all ApiKey objects from the database
        api_keys = ApiKey.objects.all()

        # Return schema validated response
        validated_response = [
            ApiKeySchema.model_validate(item).model_dump(
                exclude={"hashedKey", "userId"}
            )
            for item in api_keys
        ]

        return validated_response

    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


def get_by_id(id, current_user):
    """GET API KEY by id"""
    try:
        # Confirm id is a valid UUID
        uuid.UUID(id)

        # Find the ApiKey by its ID
        api_key = ApiKey.objects.get(id=id)

        # Return validated output
        return ApiKeySchema.model_validate(obj=api_key).model_dump(
            exclude={"hashedKey", "userId"}
        )

    except ApiKey.DoesNotExist:
        raise HTTPException(status_code=404, detail="API Key not found")

    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))
