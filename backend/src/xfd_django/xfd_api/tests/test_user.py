"""Test user."""
# Standard Python Libraries
from datetime import datetime
import secrets
from unittest.mock import patch

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
        email=f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    organization = Organization.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        rootDomains=[f"test-{secrets.token_hex(4)}"],
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
            "email": f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
        },
        headers={"Authorization": f"Bearer {create_jwt_token(user)}"},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized access."}


@pytest.mark.django_db(transaction=True)
def test_invite_by_global_admin_should_work():
    """Invite by a global admin should work."""
    user = User.objects.create(
        firstName="first",
        lastName="last",
        email=f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    email = f"{secrets.token_hex(4)}@crossfeed.cisa.gov"
    response = client.post(
        "/users",
        json={"firstName": "first name", "lastName": "last name", "email": email},
        headers={"Authorization": f"Bearer {create_jwt_token(user)}"},
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
        email=f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    email = f"{secrets.token_hex(4)}@crossfeed.cisa.gov"
    response = client.post(
        "/users",
        json={
            "firstName": "first name",
            "lastName": "last name",
            "email": email,
            "userType": UserType.GLOBAL_ADMIN,
        },
        headers={"Authorization": f"Bearer {create_jwt_token(user)}"},
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
        email=f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    response = client.post(
        "/users",
        json={
            "firstName": "first name",
            "lastName": "last name",
            "email": f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
        },
        headers={"Authorization": f"Bearer {create_jwt_token(user)}"},
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
        email=f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    organization = Organization.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        rootDomains=[f"test-{secrets.token_hex(4)}"],
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

    email = f"{secrets.token_hex(4)}@crossfeed.cisa.gov"
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
        headers={"Authorization": f"Bearer {create_jwt_token(user)}"},
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
        email=f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization = Organization.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        rootDomains=[f"test-{secrets.token_hex(4)}"],
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

    email = f"{secrets.token_hex(4)}@crossfeed.cisa.gov"
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
        headers={"Authorization": f"Bearer {create_jwt_token(user)}"},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized access."}


@pytest.mark.django_db(transaction=True)
def test_invite_existing_user_by_different_org_admin_should_not_modify_other_user_details():
    """Invite existing user by a different organization admin should work, and should not modify other user details."""
    organization = Organization.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        rootDomains=[f"test-{secrets.token_hex(4)}"],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    organization2 = Organization.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        rootDomains=[f"test-{secrets.token_hex(4)}"],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    email = f"{secrets.token_hex(4)}@crossfeed.cisa.gov"
    user = User.objects.create(
        firstName="first name", lastName="last name", email=email
    )
    Role.objects.create(
        role="user", approved=False, organization=organization, user=user
    )

    user2 = User.objects.create(
        firstName="first",
        lastName="last",
        email=f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Assign admin role to the user for the organization
    Role.objects.create(
        user=user2,
        organization=organization2,
        role="admin",
    )

    response = client.post(
        "/users",
        json={
            "firstName": "new first name",
            "lastName": "new last name",
            "email": email,
            "organization": str(organization2.id),
            "organizationAdmin": False,
        },
        headers={"Authorization": f"Bearer {create_jwt_token(user2)}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(user.id)
    assert data["email"] == email
    assert data["invitePending"] is False
    assert data["firstName"] == "first name"
    assert data["lastName"] == "last name"
    role_for_org2 = [
        role
        for role in data["roles"]
        if role["organization"]["id"] == str(organization2.id)
    ]
    assert role_for_org2, f"No role found for organization {organization2.id}"
    assert role_for_org2[0]["approved"] is True
    assert role_for_org2[0]["role"] == "user"


@pytest.mark.django_db(transaction=True)
def test_invite_existing_user_by_different_org_admin_should_modify_user_name_if_initially_blank():
    """Invite existing user by a different organization admin should modify user name if user name is initially blank."""
    organization = Organization.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        rootDomains=[f"test-{secrets.token_hex(4)}"],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    organization2 = Organization.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        rootDomains=[f"test-{secrets.token_hex(4)}"],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    email = f"{secrets.token_hex(4)}@crossfeed.cisa.gov"
    user = User.objects.create(firstName="", lastName="", email=email)
    Role.objects.create(
        role="user", approved=False, organization=organization, user=user
    )

    user2 = User.objects.create(
        firstName="first",
        lastName="last",
        email=f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Assign admin role to the user for the organization
    Role.objects.create(
        user=user2,
        organization=organization2,
        role="admin",
    )

    response = client.post(
        "/users",
        json={
            "firstName": "new first name",
            "lastName": "new last name",
            "email": email,
            "organization": str(organization2.id),
            "organizationAdmin": False,
        },
        headers={"Authorization": f"Bearer {create_jwt_token(user2)}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(user.id)
    assert data["email"] == email
    assert data["invitePending"] is False
    assert data["firstName"] == "new first name"
    assert data["lastName"] == "new last name"
    role_for_org2 = [
        role
        for role in data["roles"]
        if role["organization"]["id"] == str(organization2.id)
    ]
    assert role_for_org2, f"No role found for organization {organization2.id}"
    assert role_for_org2[0]["approved"] is True
    assert role_for_org2[0]["role"] == "user"


@pytest.mark.django_db(transaction=True)
def test_invite_existing_user_by_same_org_admin_should_update_user_org_role():
    """Invite existing user by same organization admin should work, and should update the user organization role."""
    organization = Organization.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        rootDomains=[f"test-{secrets.token_hex(4)}"],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    admin_user = User.objects.create(
        firstName="first",
        lastName="last",
        email=f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
    )
    email = f"{secrets.token_hex(4)}@crossfeed.cisa.gov"
    user = User.objects.create(firstName="first", lastName="last", email=email)
    Role.objects.create(
        role="user",
        approved=False,
        organization=organization,
        user=user,
        createdBy=admin_user,
        approvedBy=admin_user,
    )

    user2 = User.objects.create(
        firstName="first",
        lastName="last",
        email=f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Assign admin role to the user for the organization
    Role.objects.create(
        user=user2,
        organization=organization,
        role="admin",
    )

    response = client.post(
        "/users",
        json={
            "firstName": "first",
            "lastName": "last",
            "email": email,
            "organization": str(organization.id),
            "organizationAdmin": True,
        },
        headers={"Authorization": f"Bearer {create_jwt_token(user2)}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(user.id)
    assert data["email"] == email
    assert data["invitePending"] is False
    assert data["firstName"] == "first"
    assert data["lastName"] == "last"
    assert data["roles"][0]["approved"] is True
    assert data["roles"][0]["role"] == "admin"


@pytest.mark.django_db(transaction=True)
def test_invite_existing_user_by_global_admin_should_update_user_type():
    """Invite existing user by global admin that updates user type should work."""
    User.objects.create(
        firstName="first",
        lastName="last",
        email=f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
    )
    email = f"{secrets.token_hex(4)}@crossfeed.cisa.gov"
    user = User.objects.create(firstName="first", lastName="last", email=email)

    user2 = User.objects.create(
        firstName="first",
        lastName="last",
        email=f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.post(
        "/users",
        json={
            "firstName": "first",
            "lastName": "last",
            "email": email,
            "userType": UserType.GLOBAL_ADMIN,
        },
        headers={"Authorization": f"Bearer {create_jwt_token(user2)}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(user.id)
    assert data["email"] == email
    assert data["invitePending"] is False
    assert data["firstName"] == "first"
    assert data["lastName"] == "last"
    assert data["roles"] == []
    assert data["userType"] == UserType.GLOBAL_ADMIN


@pytest.mark.django_db(transaction=True)
def test_invite_existing_user_by_global_view_should_not_work():
    """Invite existing user by global view should not work."""
    User.objects.create(
        firstName="first",
        lastName="last",
        email=f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
    )
    email = f"{secrets.token_hex(4)}@crossfeed.cisa.gov"
    User.objects.create(firstName="first", lastName="last", email=email)

    user2 = User.objects.create(
        firstName="first",
        lastName="last",
        email=f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.post(
        "/users",
        json={"firstName": "first", "lastName": "last", "email": email},
        headers={"Authorization": f"Bearer {create_jwt_token(user2)}"},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized access."}


@pytest.mark.django_db(transaction=True)
@patch("xfd_api.api_methods.user.send_registration_approved_email")
def test_register_approve_success(mock_email):
    """Test successful user registration approval."""
    mock_email.return_value = "test"
    current_user = User.objects.create(
        firstName="Admin",
        lastName="User",
        email=f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
        userType=UserType.GLOBAL_ADMIN,
        regionId="region-1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    user_to_approve = User.objects.create(
        firstName="Test",
        lastName="User",
        email=f"{secrets.token_hex(4)}@example.com",
        regionId="region-1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Mock email sending
    response = client.put(
        f"/users/{user_to_approve.id}/register/approve",
        headers={"Authorization": f"Bearer {create_jwt_token(current_user)}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["body"] == "User registration approved."
    mock_email.assert_called_once_with(
        user_to_approve.email,
        subject="CyHy Dashboard Registration Approved",
        first_name=user_to_approve.firstName,
        last_name=user_to_approve.lastName,
        template="crossfeed_approval_notification.html",
    )


@pytest.mark.django_db(transaction=True)
def test_register_approve_unauthorized_region():
    """Test approval with unauthorized region access."""
    current_user = User.objects.create(
        firstName="Admin",
        lastName="User",
        email=f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
        userType=UserType.REGIONAL_ADMIN,
        regionId="1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    user_to_approve = User.objects.create(
        firstName="Test",
        lastName="User",
        email=f"{secrets.token_hex(4)}@example.com",
        regionId="2",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.put(
        f"/users/{user_to_approve.id}/register/approve",
        headers={"Authorization": f"Bearer {create_jwt_token(current_user)}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Unauthorized region access."


@pytest.mark.django_db(transaction=True)
@patch("xfd_api.api_methods.user.send_registration_denied_email")
def test_register_deny_success(mock_denied_email):
    """Test successful user registration denial."""
    mock_denied_email.return_value = "test"
    current_user = User.objects.create(
        firstName="Admin",
        lastName="User",
        email=f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
        userType=UserType.GLOBAL_ADMIN,
        regionId="1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    user_to_deny = User.objects.create(
        firstName="Test",
        lastName="User",
        email=f"{secrets.token_hex(4)}@example.com",
        regionId="1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    response = client.put(
        f"/users/{user_to_deny.id}/register/deny",
        headers={"Authorization": f"Bearer {create_jwt_token(current_user)}"},
    )

    assert response.status_code == 200
    assert response.json()["body"] == "User registration denied."
    mock_denied_email.assert_called_once_with(
        user_to_deny.email,
        subject="CyHy Dashboard Registration Denied",
        first_name=user_to_deny.firstName,
        last_name=user_to_deny.lastName,
        template="crossfeed_denial_notification.html",
    )


@pytest.mark.django_db(transaction=True)
def test_register_deny_unauthorized_region():
    """Test registration denial with unauthorized region access."""
    current_user = User.objects.create(
        firstName="Admin",
        lastName="User",
        email=f"{secrets.token_hex(4)}@crossfeed.cisa.gov",
        userType=UserType.REGIONAL_ADMIN,
        regionId="1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    user_to_deny = User.objects.create(
        firstName="Test",
        lastName="User",
        email=f"{secrets.token_hex(4)}@example.com",
        regionId="2",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.put(
        f"/users/{user_to_deny.id}/register/deny",
        headers={"Authorization": f"Bearer {create_jwt_token(current_user)}"},
    )

    print(response.json())
    assert response.status_code == 403
    assert response.json()["detail"] == "Unauthorized region access."
