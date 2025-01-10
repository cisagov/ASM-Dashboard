"""Test user."""
# Standard Python Libraries
from datetime import datetime
import secrets

# Third-Party Libraries
from fastapi.testclient import TestClient
import pytest
from xfd_api.auth import create_jwt_token
from xfd_api.models import Organization, Role, User, UserType
from xfd_django.asgi import app

client = TestClient(app)


@pytest.mark.django_db(transaction=True)
def test_invite_by_regular_user_should_not_work():
    """Invite by a regular user should not work."""
    user = User.objects.create(
        firstName="first",
        lastName="last",
        email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    organization = Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test-{}".format(secrets.token_hex(4))],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Assign standard user role to the user for the organization
    Role.objects.create(
        user=user,
        organization=organization,
        role="user",
    )

    response = client.post(
        "/users",
        json={
            "firstName": "first name",
            "lastName": "last name",
            "email": "{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
        },
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized access."}


@pytest.mark.django_db(transaction=True)
def test_invite_by_global_admin_should_work():
    """Invite by a global admin should work."""
    user = User.objects.create(
        firstName="first",
        lastName="last",
        email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    email = "{}@crossfeed.cisa.gov".format(secrets.token_hex(4))
    response = client.post(
        "/users",
        json={"firstName": "first name", "lastName": "last name", "email": email},
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == email
    assert data["invitePending"] is True
    assert data["firstName"] == "first name"
    assert data["lastName"] == "last name"
    assert data["roles"] == []
    assert data["userType"] == UserType.STANDARD


@pytest.mark.django_db(transaction=True)
def test_invite_by_global_admin_with_user_type_setting():
    """Invite by a global admin should work if setting user type."""
    user = User.objects.create(
        firstName="first",
        lastName="last",
        email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    email = "{}@crossfeed.cisa.gov".format(secrets.token_hex(4))
    response = client.post(
        "/users",
        json={
            "firstName": "first name",
            "lastName": "last name",
            "email": email,
            "userType": UserType.GLOBAL_ADMIN,
        },
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == email
    assert data["invitePending"] is True
    assert data["firstName"] == "first name"
    assert data["lastName"] == "last name"
    assert data["roles"] == []
    assert data["userType"] == UserType.GLOBAL_ADMIN


@pytest.mark.django_db(transaction=True)
def test_invite_by_global_view_should_not_work():
    """Invite by a global view should not work."""
    user = User.objects.create(
        firstName="first",
        lastName="last",
        email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    response = client.post(
        "/users",
        json={
            "firstName": "first name",
            "lastName": "last name",
            "email": "{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
        },
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    print(response.json())
    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized access."}


@pytest.mark.django_db(transaction=True)
def test_invite_by_organization_admin_should_work():
    """Invite by an organization admin should work."""
    user = User.objects.create(
        firstName="first",
        lastName="last",
        email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    organization = Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test-{}".format(secrets.token_hex(4))],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    # Assign admin role to the user for the organization
    Role.objects.create(
        user=user,
        organization=organization,
        role="admin",
    )

    email = "{}@crossfeed.cisa.gov".format(secrets.token_hex(4))
    print("here")
    response = client.post(
        "/users",
        json={
            "firstName": "first name",
            "lastName": "last name",
            "email": email,
            "organization": str(organization.id),
            "organizationAdmin": False,
        },
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == email
    assert data["invitePending"] is True
    assert data["firstName"] == "first name"
    assert data["lastName"] == "last name"
    assert data["roles"][0]["approved"] is True
    assert data["roles"][0]["role"] == "user"
    assert data["roles"][0]["organization"]["id"] == str(organization.id)


@pytest.mark.django_db(transaction=True)
def test_invite_by_organization_admin_should_not_work_if_setting_user_type():
    """Invite by an organization admin should not work if setting user type."""
    user = User.objects.create(
        firstName="first",
        lastName="last",
        email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization = Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test-{}".format(secrets.token_hex(4))],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    # Assign admin role to the user for the organization
    Role.objects.create(
        user=user,
        organization=organization,
        role="admin",
    )

    email = "{}@crossfeed.cisa.gov".format(secrets.token_hex(4))
    response = client.post(
        "/users",
        json={
            "firstName": "first name",
            "lastName": "last name",
            "email": email,
            "organization": str(organization.id),
            "organizationAdmin": False,
            "userType": UserType.GLOBAL_ADMIN,
        },
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized access."}


@pytest.mark.django_db(transaction=True)
def test_invite_existing_user_by_different_org_admin_should_not_modify_other_user_details():
    """Invite existing user by a different organization admin should work, and should not modify other user details."""
    organization = Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test-{}".format(secrets.token_hex(4))],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    organization2 = Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test-{}".format(secrets.token_hex(4))],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    email = "{}@crossfeed.cisa.gov".format(secrets.token_hex(4))
    user = User.objects.create(
        firstName="first name", lastName="last name", email=email
    )
    Role.objects.create(
        role="user", approved=False, organization=organization, user=user
    )

    user2 = User.objects.create(
        firstName="first",
        lastName="last",
        email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Admin role for second organization
    Role.objects.create(
        user=user2,
        organization=organization2,
        role="admin",
    )

    response = client.post(
        "/users",
        json={
            "firstName": "first name",
            "lastName": "last name",
            "email": email,
            "organization": str(organization.id),
        },
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user2))},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == email
    assert data["firstName"] == "first name"
    assert data["lastName"] == "last name"
    assert data["roles"][0]["approved"] is False
    assert data["roles"][0]["role"] == "user"
    assert data["roles"][0]["organization"]["id"] == str(organization.id)

    # Ensure that the other user's details were not modified
    user = User.objects.get(email=email)
    assert user.firstName == "first name"
    assert user.lastName == "last name"
    assert user.email == email
