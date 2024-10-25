# Standard Python Libraries
from datetime import datetime
import secrets

# Third-Party Libraries
from fastapi.testclient import TestClient
import pytest
from xfd_api.auth import create_jwt_token
from xfd_api.models import User, UserType
from xfd_django.asgi import app

# Initialize the test client with the FastAPI app
client = TestClient(app)


@pytest.mark.django_db(transaction=True)
def test_standard_user_not_authorized_to_access_pe_proxy():
    """Test that a standard user is not authorized to access P&E proxy."""
    # Create a standard user
    user = User.objects.create(
        firstName="Standard",
        lastName="User",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Generate a JWT token for the user
    token = create_jwt_token(user)

    # Make a GET request to the P&E proxy endpoint with the user's token
    response = client.get("/pe", headers={"Authorization": f"Bearer {token}"})

    # Assert that the user receives a 403 Unauthorized response
    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized"}


@pytest.mark.django_db(transaction=True)
def test_global_admin_authorized_to_access_pe_proxy():
    """Test that a global admin is authorized to access P&E proxy."""
    # Create a global admin user
    user = User.objects.create(
        firstName="Admin",
        lastName="User",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Generate a JWT token for the global admin
    token = create_jwt_token(user)

    # Make a GET request to the P&E proxy endpoint with the global admin's token
    response = client.get("/pe", headers={"Authorization": f"Bearer {token}"})

    # Assert that the global admin is authorized and receives either a 200 or 504 response
    assert response.status_code in [200, 504]


@pytest.mark.django_db(transaction=True)
def test_global_view_user_authorized_to_access_pe_proxy():
    """Test that a global view user is authorized to access P&E proxy."""
    # Create a global view user
    user = User.objects.create(
        firstName="View",
        lastName="User",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Make a GET request to the P&E proxy endpoint with the global view user's token
    response = client.get(
        "/pe", headers={"Authorization": "Bearer " + create_jwt_token(user)}
    )
    print(response.json())
    # Assert that the global view user is authorized and receives either a 200 or 504 response
    assert response.status_code in [200, 504]
