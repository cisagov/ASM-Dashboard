"""User event log search tests."""
# Standard Python Libraries
from datetime import datetime
import json
import uuid

# Third-Party Libraries
from fastapi.testclient import TestClient
import pytest
from xfd_api.auth import create_jwt_token
from xfd_api.models import Log, User, UserType
from xfd_django.asgi import app

client = TestClient(app)


@pytest.mark.django_db(transaction=True)
def test_search_logs_success():
    """Test searching logs with filters as a GlobalViewAdmin."""
    user = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(uuid.uuid4().hex),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    log = Log.objects.create(
        payload=json.dumps({"user": {"id": "12345", "action": "login"}}),
        createdAt=datetime.now(),
        eventType="UserLogin",
        result="Success",
    )

    search_payload = {
        "eventType": {"value": "UserLogin"},
        "result": {"value": "Success"},
    }

    response = client.post(
        "/logs/search",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
        json=search_payload,
    )

    print(response.json())
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 1
    assert data["result"][0]["id"] == str(log.id)
    assert data["result"][0]["eventType"] == "UserLogin"
    assert data["result"][0]["result"] == "Success"


@pytest.mark.django_db(transaction=True)
def test_search_logs_unauthorized():
    """Test searching logs without authorization."""
    search_payload = {"eventType": {"value": "UserLogin"}}

    response = client.post("/logs/search", json=search_payload)

    assert response.status_code == 401
    assert response.json()["detail"] == "No valid authentication credentials provided"


@pytest.mark.django_db(transaction=True)
def test_search_logs_no_results():
    """Test searching logs when no logs match the filters."""
    user = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(uuid.uuid4().hex),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    search_payload = {
        "eventType": {"value": "NonExistentEvent"},
    }

    response = client.post(
        "/logs/search",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
        json=search_payload,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 0
    assert len(data["result"]) == 0


@pytest.mark.django_db(transaction=True)
def test_search_logs_by_date():
    """Test searching logs by timestamp filter."""
    user = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(uuid.uuid4().hex),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    log = Log.objects.create(
        payload=json.dumps({"user": {"id": "67890", "action": "logout"}}),
        createdAt=datetime(2023, 5, 10, 12, 0, 0),
        eventType="UserLogout",
        result="Success",
    )

    search_payload = {
        "timestamp": {"operator": "onOrAfter", "value": "2023-05-10T00:00:00"},
    }

    response = client.post(
        "/logs/search",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
        json=search_payload,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["count"] >= 1
    assert any(log_entry["id"] == str(log.id) for log_entry in data["result"])


@pytest.mark.django_db(transaction=True)
def test_search_logs_invalid_date_format():
    """Test searching logs with an invalid date format."""
    user = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(uuid.uuid4().hex),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    search_payload = {
        "timestamp": {"operator": "onOrAfter", "value": "invalid-date"},
    }

    response = client.post(
        "/logs/search",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
        json=search_payload,
    )

    assert response.status_code == 500
    assert "Invalid date format" in response.json()["detail"]
