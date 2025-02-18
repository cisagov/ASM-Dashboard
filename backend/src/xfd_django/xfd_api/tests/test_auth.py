"""Test auth API."""
# Standard Python Libraries
from unittest.mock import AsyncMock, patch

# Third-Party Libraries
from fastapi.testclient import TestClient
import pytest
from xfd_api.models import User
from xfd_django.asgi import app

client = TestClient(app)


@pytest.mark.django_db(transaction=True)
@patch("xfd_api.auth.get_jwt_from_code", new_callable=AsyncMock)
def test_okta_callback_success(mock_get_jwt_from_code):
    """Test successful Okta callback authentication with real process_user."""
    # Mock the response from Okta token exchange
    mock_get_jwt_from_code.return_value = {
        "decoded_token": {
            "email": "test@example.com",
            "sub": "okta-user-id-123",
            "given_name": "Test",
            "family_name": "User",
        }
    }

    # Simulate request payload
    payload = {"code": "test-auth-code"}

    response = client.post("/auth/okta-callback", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert "token" in data
    assert data["data"]["user"]["email"] == "test@example.com"
    assert response.cookies["crossfeed-token"] == data["token"]

    # Check that the user was actually created in the DB
    assert User.objects.filter(email="test@example.com").exists()


@pytest.mark.django_db(transaction=True)
@patch("xfd_api.auth.get_jwt_from_code", new_callable=AsyncMock)
def test_okta_callback_existing_user(mock_get_jwt_from_code):
    """Test Okta callback when the user already exists (should update last login)."""
    User.objects.create(
        email="test@example.com",
        oktaId="okta-user-id-123",
        firstName="Existing",
        lastName="User",
        userType="standard",
        invitePending=True,
        lastLoggedIn="2000-01-01T00:00:00Z",  # Old login timestamp
    )

    # Mock the response from Okta token exchange
    mock_get_jwt_from_code.return_value = {
        "decoded_token": {
            "email": "test@example.com",
            "sub": "okta-user-id-123",
            "given_name": "Existing",
            "family_name": "User",
        }
    }

    payload = {"code": "test-auth-code"}

    response = client.post("/auth/okta-callback", json=payload)

    assert response.status_code == 200

    # Ensure user still exists and was NOT duplicated
    assert User.objects.filter(email="test@example.com").count() == 1

    # Ensure last login timestamp was updated
    updated_user = User.objects.get(email="test@example.com")
    assert updated_user.lastLoggedIn != "2000-01-01T00:00:00Z"


@pytest.mark.django_db(transaction=True)
def test_okta_callback_missing_code():
    """Test Okta callback with missing auth code (should fail)."""
    payload = {}  # No code provided

    response = client.post("/auth/okta-callback", json=payload)

    assert response.json()["status_code"] == 400
    assert response.json()["detail"] == "Code not found in request body"
