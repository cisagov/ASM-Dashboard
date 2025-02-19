"""Test notifications."""
# Standard Python Libraries
from datetime import datetime
import secrets
import uuid

# Third-Party Libraries
from fastapi.testclient import TestClient
import pytest
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
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )

    response = client.post(
        "/notifications",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
        json={
            "id": str(uuid.uuid4()),
            "maintenanceType": "Routine",
            "status": "Active",
            "updatedBy": "AdminUser",
            "message": "Scheduled maintenance",
            "startDatetime": datetime.utcnow().isoformat(),
            "endDatetime": datetime.utcnow().isoformat(),
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert data["message"] == "Scheduled maintenance"

    # Ensure the notification was stored in the database
    assert Notification.objects.filter(id=data["id"]).exists()


# Test: Creating a notification as a regular user should fail
@pytest.mark.django_db(transaction=True)
def test_create_notification_as_regular_user_fails():
    """Test notification creation should fail for a standard user."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )

    response = client.post(
        "/notifications",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
        json={
            "id": str(uuid.uuid4()),
            "maintenanceType": "Routine",
            "status": "Active",
            "updatedBy": "AdminUser",
            "message": "Scheduled maintenance",
            "startDatetime": datetime.utcnow().isoformat(),
            "endDatetime": datetime.utcnow().isoformat(),
        },
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized"}


# Test: Deleting a notification as a GlobalViewAdmin user should succeed
@pytest.mark.django_db(transaction=True)
def test_delete_notification_as_global_view_admin():
    """Test notification deletion by GlobalViewAdmin."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )

    notification = Notification.objects.create(
        maintenanceType="Routine",
        status="Active",
        updatedBy="AdminUser",
        message="Scheduled maintenance",
        startDatetime=datetime.utcnow(),
        endDatetime=datetime.utcnow(),
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )

    response = client.delete(
        "/notifications/{}".format(notification.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "success",
        "message": "Item deleted successfully",
    }

    # Ensure the notification was removed from the database
    assert not Notification.objects.filter(id=notification.id).exists()


# Test: Deleting a notification as a regular user should fail
@pytest.mark.django_db(transaction=True)
def test_delete_notification_as_regular_user_fails():
    """Test notification deletion should fail for a standard user."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )

    notification = Notification.objects.create(
        maintenanceType="Routine",
        status="Active",
        updatedBy="AdminUser",
        message="Scheduled maintenance",
        startDatetime=datetime.utcnow(),
        endDatetime=datetime.utcnow(),
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )

    response = client.delete(
        "/notifications/{}".format(notification.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized"}

    # Ensure the notification was not removed from the database
    assert Notification.objects.filter(id=notification.id).exists()


# Test: Getting all notifications should succeed
@pytest.mark.django_db(transaction=True)
def test_get_all_notifications():
    """Test retrieving all notifications."""
    Notification.objects.create(
        maintenanceType="Routine",
        status="Active",
        updatedBy="AdminUser",
        message="Test notification 1",
        startDatetime=datetime.utcnow(),
        endDatetime=datetime.utcnow(),
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )
    Notification.objects.create(
        maintenanceType="Routine",
        status="Active",
        updatedBy="AdminUser",
        message="Test notification 2",
        startDatetime=datetime.utcnow(),
        endDatetime=datetime.utcnow(),
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
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )

    notification = Notification.objects.create(
        maintenanceType="Routine",
        status="Active",
        updatedBy="AdminUser",
        message="Test notification",
        startDatetime=datetime.utcnow(),
        endDatetime=datetime.utcnow(),
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )

    response = client.get(
        "/notifications/{}".format(notification.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    assert response.json()["message"] == "Test notification"


# Test: Getting a notification by ID as a regular user should fail
@pytest.mark.django_db(transaction=True)
def test_get_notification_by_id_as_regular_user_fails():
    """Test retrieving a specific notification by ID should fail for a standard user."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )

    notification = Notification.objects.create(
        maintenanceType="Routine",
        status="Active",
        updatedBy="AdminUser",
        message="Scheduled maintenance",
        startDatetime=datetime.utcnow(),
        endDatetime=datetime.utcnow(),
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )

    response = client.get(
        "/notifications/{}".format(notification.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized"}


@pytest.mark.django_db(transaction=True)
def test_update_notification_as_global_view_admin():
    """Test updating a notification by GlobalViewAdmin."""
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
        maintenanceType="Routine",
        status="Active",
        updatedBy="AdminUser",
        message="Initial message",
        startDatetime=datetime.utcnow(),
        endDatetime=datetime.utcnow(),
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )

    response = client.put(
        "/notifications/{}".format(notification.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
        json={
            "maintenanceType": "Routine",
            "status": "Updated",
            "updatedBy": "AdminUser",
            "message": "Updated message",
            "startDatetime": datetime.utcnow().isoformat(),
            "endDatetime": datetime.utcnow().isoformat(),
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Updated message"

    # Ensure the notification was updated in the database
    notification.refresh_from_db()
    assert notification.message == "Updated message"


@pytest.mark.django_db(transaction=True)
def test_update_notification_as_regular_user_fails():
    """Test updating a notification should fail for a standard user."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    notification = Notification.objects.create(
        id=uuid.uuid4(),
        maintenanceType="Routine",
        status="Active",
        updatedBy="AdminUser",
        message="Initial message",
        startDatetime=datetime.utcnow(),
        endDatetime=datetime.utcnow(),
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )

    response = client.put(
        "/notifications/{}".format(notification.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
        json={
            "maintenanceType": "Routine",
            "status": "Updated",
            "updatedBy": "AdminUser",
            "message": "Updated message",
            "startDatetime": datetime.utcnow().isoformat(),
            "endDatetime": datetime.utcnow().isoformat(),
        },
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized"}

    # Ensure the notification was NOT updated in the database
    notification.refresh_from_db()
    assert notification.message == "Initial message"
