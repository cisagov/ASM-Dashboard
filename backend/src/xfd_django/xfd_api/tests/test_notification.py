"""Test notifications."""
import secrets
import uuid
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from xfd_api.auth import create_jwt_token
from xfd_api.models import Notification, User, UserType
from xfd_django.asgi import app

client = TestClient(app)

# Test: Creating a notification as a GlobalViewAdmin user should succeed
@pytest.mark.django_db(transaction=True)
def test_create_notification_as_global_view_admin():
    """Test notification creation by GlobalViewAdmin."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.post(
        "/notifications",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
        json={"message": "Test notification"},
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert data["message"] == "Test notification"
    
    # Ensure the notification was stored in the database
    assert Notification.objects.filter(id=data["id"]).exists()

# Test: Deleting a notification as a GlobalViewAdmin user should succeed
@pytest.mark.django_db(transaction=True)
def test_delete_notification_as_global_view_admin():
    """Test notification deletion by GlobalViewAdmin."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    
    notification = Notification.objects.create(
        id=uuid.uuid4(),
        message="Test notification",
        user=user,
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )
    
    response = client.delete(
        f"/notifications/{notification.id}",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    
    assert response.status_code == 200
    assert response.json() == {"status": "success", "message": "Item deleted successfully"}
    
    # Ensure the notification was removed from the database
    assert not Notification.objects.filter(id=notification.id).exists()

# Test: Getting all notifications should succeed
@pytest.mark.django_db(transaction=True)
def test_get_all_notifications():
    """Test retrieving all notifications."""
    Notification.objects.create(
        id=uuid.uuid4(),
        message="Test notification 1",
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )
    Notification.objects.create(
        id=uuid.uuid4(),
        message="Test notification 2",
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )
    
    response = client.get("/notifications")
    
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 2

# Test: Getting a notification by ID as a GlobalViewAdmin user should succeed
@pytest.mark.django_db(transaction=True)
def test_get_notification_by_id_as_global_view_admin():
    """Test retrieving a specific notification by ID as GlobalViewAdmin."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    
    notification = Notification.objects.create(
        id=uuid.uuid4(),
        message="Test notification",
        user=user,
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )
    
    response = client.get(
        f"/notifications/{notification.id}",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    
    assert response.status_code == 200
    assert response.json()["message"] == "Test notification"
