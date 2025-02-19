"""Test user."""
# Standard Python Libraries
from datetime import datetime
import secrets
from unittest.mock import patch
import uuid

# Third-Party Libraries
from fastapi.testclient import TestClient
import pytest
from xfd_api.auth import create_jwt_token
from xfd_api.models import ApiKey, Organization, Role, User, UserType
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
            "organization": "{}".format(organization.id),
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
            "organization": "{}".format(organization.id),
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
            "organization": "{}".format(organization2.id),
            "organizationAdmin": False,
        },
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user2))},
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
    assert role_for_org2, "No role found for organization {}".format(organization2.id)
    assert role_for_org2[0]["approved"] is True
    assert role_for_org2[0]["role"] == "user"


@pytest.mark.django_db(transaction=True)
def test_invite_existing_user_by_different_org_admin_should_modify_user_name_if_initially_blank():
    """Invite existing user by a different organization admin should modify user name if user name is initially blank."""
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
    user = User.objects.create(firstName="", lastName="", email=email)
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
            "organization": "{}".format(organization2.id),
            "organizationAdmin": False,
        },
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user2))},
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
    assert role_for_org2, "No role found for organization {}".format(organization2.id)
    assert role_for_org2[0]["approved"] is True
    assert role_for_org2[0]["role"] == "user"


@pytest.mark.django_db(transaction=True)
def test_invite_existing_user_by_same_org_admin_should_update_user_org_role():
    """Invite existing user by same organization admin should work, and should update the user organization role."""
    organization = Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test-{}".format(secrets.token_hex(4))],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    admin_user = User.objects.create(
        firstName="first",
        lastName="last",
        email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
    )
    email = "{}@crossfeed.cisa.gov".format(secrets.token_hex(4))
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
        email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
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
            "organization": "{}".format(organization.id),
            "organizationAdmin": True,
        },
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user2))},
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
        email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
    )
    email = "{}@crossfeed.cisa.gov".format(secrets.token_hex(4))
    user = User.objects.create(firstName="first", lastName="last", email=email)

    user2 = User.objects.create(
        firstName="first",
        lastName="last",
        email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
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
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user2))},
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
        email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
    )
    email = "{}@crossfeed.cisa.gov".format(secrets.token_hex(4))
    User.objects.create(firstName="first", lastName="last", email=email)

    user2 = User.objects.create(
        firstName="first",
        lastName="last",
        email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.post(
        "/users",
        json={"firstName": "first", "lastName": "last", "email": email},
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user2))},
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
        email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        regionId="region-1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    user_to_approve = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        regionId="region-1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    # Mock email sending
    response = client.put(
        "/users/{}/register/approve".format(user_to_approve.id),
        headers={"Authorization": "Bearer {}".format(create_jwt_token(current_user))},
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
        email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
        regionId="1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    user_to_approve = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        regionId="2",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.put(
        "/users/{}/register/approve".format(user_to_approve.id),
        headers={"Authorization": "Bearer {}".format(create_jwt_token(current_user))},
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
        email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        regionId="1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    user_to_deny = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        regionId="1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    response = client.put(
        "/users/{}/register/deny".format(user_to_deny.id),
        headers={"Authorization": "Bearer {}".format(create_jwt_token(current_user))},
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
        email="{}@crossfeed.cisa.gov".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
        regionId="1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    user_to_deny = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        regionId="2",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.put(
        "/users/{}/register/deny".format(user_to_deny.id),
        headers={"Authorization": "Bearer {}".format(create_jwt_token(current_user))},
    )

    print(response.json())
    assert response.status_code == 403
    assert response.json()["detail"] == "Unauthorized region access."


@pytest.mark.django_db(transaction=True)
def test_accept_terms_success():
    """Test that a user can successfully accept the latest terms of service."""
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    version = "1.0"

    response = client.post(
        "/users/me/acceptTerms",
        json={"version": version},
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["id"] == str(user.id)
    assert data["acceptedTermsVersion"] == version
    assert data["dateAcceptedTerms"] is not None


@pytest.mark.django_db(transaction=True)
def test_accept_terms_missing_version():
    """Test that missing version in request body returns a 400 error."""
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.post(
        "/users/me/acceptTerms",
        json={},  # No version provided
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 422


@pytest.mark.django_db(transaction=True)
def test_accept_terms_no_auth():
    """Test that an unauthenticated request returns 401."""
    response = client.post(
        "/users/me/acceptTerms",
        json={"version": "1.0"},
    )

    assert response.status_code == 401


@pytest.mark.django_db(transaction=True)
def test_delete_user_as_admin():
    """Test that a global admin can successfully delete a user."""
    admin_user = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    target_user = User.objects.create(
        firstName="Target",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.delete(
        "/users/{}".format(target_user.id),
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin_user))},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert response.json()[
        "message"
    ] == "User {} has been deleted successfully.".format(target_user.id)

    # Ensure the user is deleted from the database
    assert not User.objects.filter(id=target_user.id).exists()


@pytest.mark.django_db(transaction=True)
def test_delete_user_as_standard_user_fails():
    """Test that a standard user cannot delete another user."""
    user = User.objects.create(
        firstName="Standard",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    target_user = User.objects.create(
        firstName="Target",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.delete(
        "/users/{}".format(target_user.id),
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Unauthorized access."

    # Ensure the user still exists
    assert User.objects.filter(id=target_user.id).exists()


@pytest.mark.django_db(transaction=True)
def test_delete_nonexistent_user():
    """Test that deleting a nonexistent user returns 404."""
    admin_user = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    fake_user_id = uuid.uuid4()

    response = client.delete(
        "/users/{}".format(fake_user_id),
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin_user))},
    )

    assert response.status_code == 500


@pytest.mark.django_db(transaction=True)
def test_delete_user_no_auth():
    """Test that an unauthenticated request returns 401."""
    target_user = User.objects.create(
        firstName="Target",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.delete("/users/{}".format(target_user.id))

    assert response.status_code == 401


@pytest.mark.django_db(transaction=True)
def test_get_users_as_global_admin():
    """Test that a global admin can retrieve all users."""
    global_admin = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user1 = User.objects.create(
        firstName="Test",
        lastName="User1",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user2 = User.objects.create(
        firstName="Test",
        lastName="User2",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/users",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(global_admin))},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 2  # Should at least return the created users
    returned_user_ids = {user["id"] for user in data}
    assert str(user1.id) in returned_user_ids
    assert str(user2.id) in returned_user_ids


@pytest.mark.django_db(transaction=True)
def test_get_users_as_standard_user_fails():
    """Test that a standard user cannot retrieve all users."""
    standard_user = User.objects.create(
        firstName="Standard",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/users",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(standard_user))},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized"


@pytest.mark.django_db(transaction=True)
def test_get_users_no_auth():
    """Test that an unauthenticated request returns 401."""
    response = client.get("/users")

    assert response.status_code == 401


@pytest.mark.django_db(transaction=True)
def test_get_users_with_roles():
    """Test that users and their roles are correctly returned."""
    global_admin = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization = Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test-" + secrets.token_hex(4)],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    Role.objects.create(
        user=user,
        organization=organization,
        role="member",
        approved=True,
    )

    response = client.get(
        "/users",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(global_admin))},
    )

    assert response.status_code == 200
    data = response.json()
    found_user = next((u for u in data if u["id"] == str(user.id)), None)
    assert found_user is not None
    assert len(found_user["roles"]) == 1
    assert found_user["roles"][0]["organization"]["id"] == str(organization.id)
    assert found_user["roles"][0]["role"] == "member"


@pytest.mark.django_db(transaction=True)
def test_get_users_by_region_id_as_regional_admin():
    """Test that a regional admin can retrieve users by region ID."""
    regional_admin = User.objects.create(
        firstName="Admin",
        lastName="Regional",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
        regionId="1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user1 = User.objects.create(
        firstName="Test",
        lastName="User1",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        regionId="1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user2 = User.objects.create(
        firstName="Test",
        lastName="User2",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        regionId="1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/users/regionId/1",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(regional_admin))},
    )
    print(response.json())

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3
    returned_user_ids = {user["id"] for user in data}
    assert str(user1.id) in returned_user_ids
    assert str(user2.id) in returned_user_ids


@pytest.mark.django_db(transaction=True)
def test_get_users_by_region_id_as_standard_user_fails():
    """Test that a standard user cannot retrieve users by region ID."""
    standard_user = User.objects.create(
        firstName="Standard",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        regionId="R1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/users/regionId/R1",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(standard_user))},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized"


@pytest.mark.django_db(transaction=True)
def test_get_users_by_region_id_no_auth():
    """Test that an unauthenticated request returns 401."""
    response = client.get("/users/regionId/R1")

    assert response.status_code == 401


@pytest.mark.django_db(transaction=True)
def test_get_users_by_region_id_not_found():
    """Test that retrieving users for a non-existent region returns 404."""
    regional_admin = User.objects.create(
        firstName="Admin",
        lastName="Regional",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
        regionId="R1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/users/regionId/R999",  # Non-existent region
        headers={"Authorization": "Bearer {}".format(create_jwt_token(regional_admin))},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "No users found for the specified regionId"


@pytest.mark.django_db(transaction=True)
def test_get_users_by_state_as_regional_admin():
    """Test that a regional admin can retrieve users by state."""
    regional_admin = User.objects.create(
        firstName="Admin",
        lastName="Regional",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
        state="CA",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user1 = User.objects.create(
        firstName="Test",
        lastName="User1",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        state="CA",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user2 = User.objects.create(
        firstName="Test",
        lastName="User2",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        state="CA",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/users/state/CA",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(regional_admin))},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3
    returned_user_ids = {user["id"] for user in data}
    assert str(user1.id) in returned_user_ids
    assert str(user2.id) in returned_user_ids


@pytest.mark.django_db(transaction=True)
def test_get_users_by_state_as_standard_user_fails():
    """Test that a standard user cannot retrieve users by state."""
    standard_user = User.objects.create(
        firstName="Standard",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        state="CA",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/users/state/CA",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(standard_user))},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized"


@pytest.mark.django_db(transaction=True)
def test_get_users_by_state_no_auth():
    """Test that an unauthenticated request returns 401."""
    response = client.get("/users/state/CA")

    assert response.status_code == 401


@pytest.mark.django_db(transaction=True)
def test_get_users_by_state_not_found():
    """Test that retrieving users for a non-existent state returns 404."""
    regional_admin = User.objects.create(
        firstName="Admin",
        lastName="Regional",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
        state="CA",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/users/state/ZZ",  # Non-existent state
        headers={"Authorization": "Bearer {}".format(create_jwt_token(regional_admin))},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "No users found for the specified state"


@pytest.mark.django_db(transaction=True)
def test_get_users_v2_as_regional_admin():
    """Test that a regional admin can retrieve users with filters."""
    regional_admin = User.objects.create(
        firstName="Admin",
        lastName="Regional",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
        state="CA",
        regionId="R1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user1 = User.objects.create(
        firstName="User1",
        lastName="Test",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        state="CA",
        regionId="R1",
        invitePending=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    User.objects.create(
        firstName="User2",
        lastName="Test",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        state="CA",
        regionId="R1",
        invitePending=True,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/v2/users?state=CA&regionId=R1&invitePending=False",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(regional_admin))},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert data[1]["id"] == str(user1.id)
    assert data[0]["state"] == "CA"
    assert data[0]["regionId"] == "R1"


@pytest.mark.django_db(transaction=True)
def test_get_users_v2_as_standard_user_fails():
    """Test that a standard user cannot retrieve users with filters."""
    standard_user = User.objects.create(
        firstName="Standard",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        state="CA",
        regionId="R1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/v2/users?state=CA",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(standard_user))},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized"


@pytest.mark.django_db(transaction=True)
def test_get_users_v2_no_auth():
    """Test that an unauthenticated request returns 401."""
    response = client.get("/v2/users?state=CA")

    assert response.status_code == 401


@pytest.mark.django_db(transaction=True)
def test_get_users_v2_no_filters():
    """Test that a regional admin can retrieve users without filters."""
    regional_admin = User.objects.create(
        firstName="Admin",
        lastName="Regional",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    User.objects.create(
        firstName="User1",
        lastName="Test",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        state="CA",
        regionId="R1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    User.objects.create(
        firstName="User2",
        lastName="Test",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        state="TX",
        regionId="R2",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/v2/users",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(regional_admin))},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3


@pytest.mark.django_db(transaction=True)
def test_get_users_v2_empty_results():
    """Test that a valid request with no matching users returns an empty list."""
    regional_admin = User.objects.create(
        firstName="Admin",
        lastName="Regional",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/v2/users?state=ZZ",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(regional_admin))},
    )

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.django_db(transaction=True)
def test_update_user_v2_as_global_admin():
    """Test that a global admin can update user details."""
    global_admin = User.objects.create(
        firstName="Admin",
        lastName="Global",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user = User.objects.create(
        firstName="User",
        lastName="Test",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        state="CA",
        regionId="R1",
        invitePending=True,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    payload = {"firstName": "Updated", "lastName": "User"}

    response = client.put(
        "/v2/users/{}".format(user.id),
        json=payload,
        headers={"Authorization": "Bearer {}".format(create_jwt_token(global_admin))},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(user.id)
    assert data["firstName"] == "Updated"
    assert data["lastName"] == "User"


@pytest.mark.django_db(transaction=True)
def test_update_user_v2_as_standard_user_fails():
    """Test that a standard user cannot update another user's details."""
    standard_user = User.objects.create(
        firstName="Standard",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    target_user = User.objects.create(
        firstName="Target",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    payload = {"firstName": "Hacked", "lastName": "User"}

    response = client.put(
        "/v2/users/{}".format(target_user.id),
        json=payload,
        headers={"Authorization": "Bearer {}".format(create_jwt_token(standard_user))},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Unauthorized access."


@pytest.mark.django_db(transaction=True)
def test_update_user_v2_no_auth():
    """Test that an unauthenticated request returns 401."""
    user = User.objects.create(
        firstName="User",
        lastName="Test",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    payload = {"firstName": "Anonymous"}

    response = client.put("/v2/users/{}".format(user.id), json=payload)

    assert response.status_code == 401


@pytest.mark.django_db(transaction=True)
def test_update_user_v2_non_existent_user():
    """Test that updating a non-existent user returns a 404."""
    global_admin = User.objects.create(
        firstName="Admin",
        lastName="Global",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    fake_user_id = "00000000-0000-0000-0000-000000000000"

    payload = {"firstName": "DoesNotExist"}

    response = client.put(
        "/v2/users/{}".format(fake_user_id),
        json=payload,
        headers={"Authorization": "Bearer {}".format(create_jwt_token(global_admin))},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"


@pytest.mark.django_db(transaction=True)
def test_update_user_v2_update_userType_by_non_admin_fails():
    """Test that only a global admin can update userType."""
    regional_admin = User.objects.create(
        firstName="Admin",
        lastName="Regional",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user = User.objects.create(
        firstName="User",
        lastName="Test",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    payload = {"userType": UserType.GLOBAL_ADMIN}

    response = client.put(
        "/v2/users/{}".format(user.id),
        json=payload,
        headers={"Authorization": "Bearer {}".format(create_jwt_token(regional_admin))},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Only global admins can update userType."


@pytest.mark.django_db(transaction=True)
def test_get_me_success():
    """Test that an authenticated user can retrieve their own user data."""
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/users/me",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(user.id)
    assert data["email"] == user.email
    assert data["userType"] == user.userType


@pytest.mark.django_db(transaction=True)
def test_get_me_with_roles():
    """Test that a user with roles retrieves their associated organizations."""
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization = Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test-" + secrets.token_hex(4)],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    Role.objects.create(
        user=user,
        organization=organization,
        role="admin",
        approved=True,
    )

    response = client.get(
        "/users/me",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data["roles"]) == 1
    assert data["roles"][0]["role"] == "admin"
    assert data["roles"][0]["organization"]["id"] == str(organization.id)
    assert data["roles"][0]["organization"]["name"] == organization.name


@pytest.mark.django_db(transaction=True)
def test_get_me_with_api_keys():
    """Test that a user retrieves their associated API keys."""
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    api_key = ApiKey.objects.create(
        user=user,
        hashedKey="fakehashedkey",
        lastFour="1234",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/users/me",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data["apiKeys"]) == 1
    assert data["apiKeys"][0]["id"] == str(api_key.id)
    assert data["apiKeys"][0]["lastFour"] == "1234"


@pytest.mark.django_db(transaction=True)
def test_get_me_unauthenticated():
    """Test that an unauthenticated request returns a 401 error."""
    response = client.get("/users/me")

    assert response.status_code == 401
