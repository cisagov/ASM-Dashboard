"""Test organizations."""
# Standard Python Libraries
from datetime import datetime
import secrets
from unittest.mock import patch
import uuid

# Third-Party Libraries
from fastapi.testclient import TestClient
import pytest
from xfd_api.auth import create_jwt_token
from xfd_api.models import (
    Organization,
    OrganizationTag,
    Role,
    Scan,
    ScanTask,
    User,
    UserType,
)
from xfd_django.asgi import app

client = TestClient(app)


# Test: Creating an organization by global admin should succeed
@pytest.mark.django_db(transaction=True)
def test_create_org_by_global_admin():
    """Test organization by global admin should succeed."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    name = "test-{}".format(secrets.token_hex(4))
    acronym = secrets.token_hex(2)

    response = client.post(
        "/organizations/",
        json={
            "ipBlocks": [],
            "acronym": acronym,
            "name": name,
            "rootDomains": ["cisa.gov"],
            "isPassive": False,
            "tags": [{"name": "test"}],
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["createdBy"]["id"] == str(user.id)
    assert data["name"] == name
    assert data["tags"][0]["name"] == "test"


# Test: Cannot add organization with the same acronym
@pytest.mark.django_db(transaction=True)
def test_create_duplicate_org_fails():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    name = "test-{}".format(secrets.token_hex(4))
    acronym = secrets.token_hex(2)

    client.post(
        "/organizations/",
        json={
            "ipBlocks": [],
            "acronym": acronym,
            "name": name,
            "rootDomains": ["cisa.gov"],
            "isPassive": False,
            "tags": [],
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    # Attempt to create another organization with the same acronym
    response = client.post(
        "/organizations/",
        json={
            "ipBlocks": [],
            "acronym": acronym,
            "name": name,
            "rootDomains": ["cisa.gov"],
            "isPassive": False,
            "tags": [],
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 500


# Test: Creating an organization by global view user should fail
@pytest.mark.django_db(transaction=True)
def test_create_org_by_global_view_fails():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    print(user)

    name = "test-{}".format(secrets.token_hex(4))
    acronym = secrets.token_hex(2)

    response = client.post(
        "/organizations/",
        json={
            "ipBlocks": [],
            "acronym": acronym,
            "name": name,
            "rootDomains": ["cisa.gov"],
            "isPassive": False,
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized access."}


# Test: Update organization by global admin
@pytest.mark.django_db(transaction=True)
def test_update_org_by_global_admin():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization = Organization.objects.create(
        acronym=secrets.token_hex(2),
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test.com"],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    new_name = "test-{}".format(secrets.token_hex(4))
    new_acronym = secrets.token_hex(2)
    new_root_domains = ["newdomain.com"]
    new_ip_blocks = ["1.1.1.1"]
    is_passive = True
    tags = [{"name": "updated"}]

    response = client.put(
        "/organizations/{}".format(organization.id),
        json={
            "name": new_name,
            "acronym": new_acronym,
            "rootDomains": new_root_domains,
            "ipBlocks": new_ip_blocks,
            "isPassive": is_passive,
            "tags": tags,
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == new_name
    assert data["rootDomains"] == new_root_domains
    assert data["ipBlocks"] == new_ip_blocks
    assert data["isPassive"] == is_passive
    assert data["tags"][0]["name"] == tags[0]["name"]


# Test: Update organization by global view should fail
@pytest.mark.django_db(transaction=True)
def test_update_org_by_global_view_fails():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization = Organization.objects.create(
        acronym=secrets.token_hex(2),
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test.com"],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    new_name = "test-{}".format(secrets.token_hex(4))
    new_acronym = secrets.token_hex(2)
    new_root_domains = ["newdomain.com"]
    new_ip_blocks = ["1.1.1.1"]
    is_passive = True
    tags = [{"name": "updated"}]

    response = client.put(
        "/organizations/{}".format(organization.id),
        json={
            "name": new_name,
            "acronym": new_acronym,
            "rootDomains": new_root_domains,
            "ipBlocks": new_ip_blocks,
            "isPassive": is_passive,
            "tags": tags,
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized access."}


# Test: Deleting an organization by global admin should succeed
@pytest.mark.django_db(transaction=True)
def test_delete_org_by_global_admin():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization = Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test.com"],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.delete(
        "/organizations/{}".format(organization.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200


# Test: Deleting an organization by org admin should fail
@pytest.mark.django_db(transaction=True)
def test_delete_org_by_org_admin_fails():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization = Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test.com"],
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

    response = client.delete(
        "/organizations/{}".format(organization.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized access."}


# Test: Deleting an organization by global view should fail
@pytest.mark.django_db(transaction=True)
def test_delete_org_by_global_view_fails():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization = Organization.objects.create(
        acronym=secrets.token_hex(2),
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test.com"],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.delete(
        "/organizations/{}".format(organization.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized access."}


# Test: List organizations by global view should succeed
@pytest.mark.django_db(transaction=True)
def test_list_orgs_by_global_view_succeeds():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Create an organization
    Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test-{}".format(secrets.token_hex(4))],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/organizations",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1


# Test: List organizations by org member should only return their org
@pytest.mark.django_db(transaction=True)
def test_list_orgs_by_org_member_only_gets_their_org():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Create organizations
    organization1 = Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test-{}".format(secrets.token_hex(4))],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test-{}".format(secrets.token_hex(4))],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Assign user a role in organization1
    Role.objects.create(
        user=user,
        organization=organization1,
        role="user",
    )

    # Fetch organizations
    response = client.get(
        "/organizations",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["id"] == str(organization1.id)


# Test: Get organization by org admin user should pass
@pytest.mark.django_db(transaction=True)
def test_get_org_by_org_admin_succeeds():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
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

    response = client.get(
        "/organizations/{}".format(organization.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == organization.name


# Test: Get organization by org admin of different org should fail
@pytest.mark.django_db(transaction=True)
def test_get_org_by_org_admin_of_different_org_fails():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization1 = Organization.objects.create(
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

    # Assign admin role to the user for organization1
    Role.objects.create(
        user=user,
        organization=organization1,
        role="admin",
    )

    response = client.get(
        "/organizations/{}".format(organization2.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized"}


# Test: Get organization by org regular user should fail
@pytest.mark.django_db(transaction=True)
def test_get_org_by_org_regular_user_fails():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
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

    # Assign regular user role to the user for the organization
    Role.objects.create(
        user=user,
        organization=organization,
        role="user",
    )

    response = client.get(
        "/organizations/{}".format(organization.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized"}


# Test: Get organization by org admin should return associated scantasks
@pytest.mark.django_db(transaction=True)
def test_get_org_with_scan_tasks_by_org_admin_succeeds():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
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

    # Create a scan and scantask associated with the organization
    scan = Scan.objects.create(
        name="censys",
        arguments={},
        frequency=999999,
    )

    scan_task = ScanTask.objects.create(scan=scan, status="created", type="fargate")

    scan_task.organizations.add(organization)

    response = client.get(
        "/organizations/{}".format(organization.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == organization.name
    assert len(data["scanTasks"]) == 1
    assert data["scanTasks"][0]["id"] == str(scan_task.id)
    assert data["scanTasks"][0]["scan"]["id"] == str(scan.id)


# Test: Enabling a user-modifiable scan by org admin should succeed
@pytest.mark.django_db(transaction=True)
def test_enable_user_modifiable_scan_by_org_admin_succeeds():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
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
    )

    scan = Scan.objects.create(
        name="censys",
        arguments={},
        frequency=999999,
        isGranular=True,
        isUserModifiable=True,
    )

    response = client.post(
        "/organizations/{}/granularScans/{}/update".format(organization.id, scan.id),
        json={"enabled": True},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data["granularScans"]) == 1
    assert data["granularScans"][0]["id"] == str(scan.id)


# Test: Disabling a user-modifiable scan by org admin should succeed
@pytest.mark.django_db(transaction=True)
def test_disable_user_modifiable_scan_by_org_admin_succeeds():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
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
    )

    scan = Scan.objects.create(
        name="censys",
        arguments={},
        frequency=999999,
        isGranular=True,
        isUserModifiable=True,
    )

    scan_task = ScanTask.objects.create(
        scan=scan,
        status="created",
        type="fargate",
    )
    scan_task.organizations.add(organization)

    response = client.post(
        "/organizations/{}/granularScans/{}/update".format(organization.id, scan.id),
        json={"enabled": False},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data["granularScans"]) == 0


# Test: Enabling a user-modifiable scan by org user should fail
@pytest.mark.django_db(transaction=True)
def test_enable_user_modifiable_scan_by_org_user_fails():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
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
        role="user",
    )

    scan = Scan.objects.create(
        name="censys",
        arguments={},
        frequency=999999,
        isGranular=True,
        isUserModifiable=True,
    )

    response = client.post(
        "/organizations/{}/granularScans/{}/update".format(organization.id, scan.id),
        json={"enabled": True},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 403


# Test: Enabling a user-modifiable scan by global admin should succeed
@pytest.mark.django_db(transaction=True)
def test_enable_user_modifiable_scan_by_global_admin_succeeds():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
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

    scan = Scan.objects.create(
        name="censys",
        arguments={},
        frequency=999999,
        isGranular=True,
        isUserModifiable=True,
    )

    response = client.post(
        "/organizations/{}/granularScans/{}/update".format(organization.id, scan.id),
        json={"enabled": True},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data["granularScans"]) == 1
    assert data["granularScans"][0]["id"] == str(scan.id)


# Test: Enabling a non-user-modifiable scan by org admin should fail
@pytest.mark.django_db(transaction=True)
def test_enable_non_user_modifiable_scan_by_org_admin_fails():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
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
    )

    scan = Scan.objects.create(
        name="censys",
        arguments={},
        frequency=999999,
        isGranular=True,
        isUserModifiable=False,  # Not user-modifiable
    )

    response = client.post(
        "/organizations/{}/granularScans/{}/update".format(organization.id, scan.id),
        json={"enabled": True},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 404


# Test: Approving a role by global admin should succeed
@pytest.mark.django_db(transaction=True)
def test_approve_role_by_global_admin_succeeds():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user2 = User.objects.create(
        firstName="",
        lastName="",
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

    role = Role.objects.create(
        role="user", approved=False, organization=organization, user=user2
    )

    response = client.post(
        "/organizations/{}/roles/{}/approve".format(organization.id, role.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    role.refresh_from_db()
    assert role.approved is True


# Test: Approving a role by global view should fail
@pytest.mark.django_db(transaction=True)
def test_approve_role_by_global_view_fails():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user2 = User.objects.create(
        firstName="",
        lastName="",
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

    role = Role.objects.create(
        role="user", approved=False, organization=organization, user=user2
    )

    response = client.post(
        "/organizations/{}/roles/{}/approve".format(organization.id, role.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 403


# Test: Approving a role by org admin should succeed
@pytest.mark.django_db(transaction=True)
def test_approve_role_by_org_admin_succeeds():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user2 = User.objects.create(
        firstName="",
        lastName="",
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
    )

    role = Role.objects.create(
        role="user", approved=False, organization=organization, user=user2
    )

    response = client.post(
        "/organizations/{}/roles/{}/approve".format(organization.id, role.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    role.refresh_from_db()
    assert role.approved is True


# Test: Approving a role by org user should fail
@pytest.mark.django_db(transaction=True)
def test_approve_role_by_org_user_fails():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user2 = User.objects.create(
        firstName="",
        lastName="",
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
        role="user",
    )

    role = Role.objects.create(
        role="user", approved=False, organization=organization, user=user2
    )

    response = client.post(
        "/organizations/{}/roles/{}/approve".format(organization.id, role.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 403
    role.refresh_from_db()
    assert role.approved is False


# Test: removeRole by globalAdmin should work
@pytest.mark.django_db(transaction=True)
def test_remove_role_by_global_admin_succeeds():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user2 = User.objects.create(
        firstName="",
        lastName="",
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

    role = Role.objects.create(
        role="user", approved=False, organization=organization, user=user2
    )

    response = client.post(
        "/organizations/{}/roles/{}/remove".format(organization.id, role.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200


# Test: removeRole by globalView should fail
@pytest.mark.django_db(transaction=True)
def test_remove_role_by_global_view_fails():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user2 = User.objects.create(
        firstName="",
        lastName="",
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

    role = Role.objects.create(
        role="user", approved=False, organization=organization, user=user2
    )

    response = client.post(
        "/organizations/{}/roles/{}/remove".format(organization.id, role.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized access."}


# Test: removeRole by org admin should succeed
@pytest.mark.django_db(transaction=True)
def test_remove_role_by_org_admin_succeeds():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    user2 = User.objects.create(
        firstName="",
        lastName="",
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
    )

    role = Role.objects.create(
        role="user", approved=False, organization=organization, user=user2
    )

    response = client.post(
        "/organizations/{}/roles/{}/remove".format(organization.id, role.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200


# Test: removeRole by org user should fail
@pytest.mark.django_db(transaction=True)
def test_remove_role_by_org_user_fails():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user2 = User.objects.create(
        firstName="",
        lastName="",
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
        role="user",
    )

    role = Role.objects.create(
        role="user", approved=False, organization=organization, user=user2
    )

    response = client.post(
        "/organizations/{}/roles/{}/remove".format(organization.id, role.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Unauthorized access."}


# Test: getTags by globalAdmin should work
@pytest.mark.django_db(transaction=True)
def test_get_tags_by_global_admin_succeeds():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    OrganizationTag.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
    )

    response = client.get(
        "/organizations/tags",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    assert len(response.json()) >= 1


# Test: getTags by standard user should return no tags
@pytest.mark.django_db(transaction=True)
def test_get_tags_by_standard_user_returns_no_tags():
    """Test organization."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    OrganizationTag.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
    )

    response = client.get(
        "/organizations/tags",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    assert len(response.json()) == 0


@pytest.mark.django_db(transaction=True)
def test_get_organizations_by_state_as_regional_admin():
    """Test that a regional admin can retrieve organizations by state."""
    user = User.objects.create(
        firstName="Test",
        lastName="Admin",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization = Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test-" + secrets.token_hex(4)],
        ipBlocks=[],
        isPassive=False,
        state="CA",
    )

    response = client.get(
        "/organizations/state/CA",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["id"] == str(organization.id)
    assert response.json()[0]["state"] == "CA"


@pytest.mark.django_db(transaction=True)
def test_get_organizations_by_state_as_standard_user_fails():
    """Test that a standard user cannot retrieve organizations by state."""
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test-" + secrets.token_hex(4)],
        ipBlocks=[],
        isPassive=False,
        state="CA",
    )

    response = client.get(
        "/organizations/state/CA",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Unauthorized"


@pytest.mark.django_db(transaction=True)
def test_get_organizations_by_state_not_found():
    """Test that retrieving organizations for a non-existent state returns 404."""
    user = User.objects.create(
        firstName="Test",
        lastName="Admin",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/organizations/state/ZZ",  # Non-existent state code
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "No organizations found for the given state"


@pytest.mark.django_db(transaction=True)
def test_get_organizations_by_region_as_regional_admin():
    """Test that a regional admin can retrieve organizations by regionId."""
    user = User.objects.create(
        firstName="Test",
        lastName="Admin",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization = Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test-" + secrets.token_hex(4)],
        ipBlocks=[],
        isPassive=False,
        regionId="12345",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/organizations/regionId/12345",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["id"] == str(organization.id)
    assert response.json()[0]["regionId"] == "12345"


@pytest.mark.django_db(transaction=True)
def test_get_organizations_by_region_as_standard_user_fails():
    """Test that a standard user cannot retrieve organizations by regionId."""
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test-" + secrets.token_hex(4)],
        ipBlocks=[],
        isPassive=False,
        regionId="12345",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/organizations/regionId/12345",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Unauthorized"


@pytest.mark.django_db(transaction=True)
def test_get_organizations_by_region_not_found():
    """Test that retrieving organizations for a non-existent region returns 404."""
    user = User.objects.create(
        firstName="Test",
        lastName="Admin",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/organizations/regionId/99999",  # Non-existent regionId
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "No organizations found for the given region"


@pytest.mark.django_db(transaction=True)
def test_upsert_organization_create():
    """Test that a GlobalWriteAdmin can create a new organization."""
    user = User.objects.create(
        firstName="Test",
        lastName="Admin",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    name = "test-{}".format(secrets.token_hex(4))
    acronym = secrets.token_hex(2)
    payload = {
        "ipBlocks": [],
        "acronym": acronym,
        "name": name,
        "isPassive": False,
        "rootDomains": ["unauthorized.com"],
        "state": "CA",
        "stateName": "California",
        "country": "USA",
        "type": "Government",
    }

    response = client.post(
        "/organizations_upsert",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
        json=payload,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["acronym"] == acronym
    assert data["name"] == name
    assert data["state"] == "CA"
    assert data["createdBy"]["email"] == user.email


@pytest.mark.django_db(transaction=True)
def test_upsert_organization_update():
    """Test that a GlobalWriteAdmin can update an existing organization."""
    user = User.objects.create(
        firstName="Test",
        lastName="Admin",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    Organization.objects.create(
        acronym="TEST",
        name="Old Name",
        rootDomains=["old.com"],
        ipBlocks=["192.168.2.0/24"],
        isPassive=True,
        state="NY",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    name = "test-{}".format(secrets.token_hex(4))
    acronym = secrets.token_hex(2)
    payload = {
        "acronym": acronym,
        "name": name,
        "rootDomains": ["updated.com"],
        "ipBlocks": ["192.168.3.0/24"],
        "isPassive": False,
        "state": "CA",
    }

    response = client.post(
        "/organizations_upsert",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
        json=payload,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["acronym"] == acronym
    assert data["name"] == name
    assert data["rootDomains"] == ["updated.com"]
    assert data["ipBlocks"] == ["192.168.3.0/24"]
    assert data["isPassive"] is False
    assert data["state"] == "CA"


@pytest.mark.django_db(transaction=True)
def test_upsert_organization_unauthorized():
    """Test that a Standard user cannot create or update an organization."""
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    name = "test-{}".format(secrets.token_hex(4))
    acronym = secrets.token_hex(2)
    payload = {
        "ipBlocks": [],
        "acronym": acronym,
        "name": name,
        "isPassive": False,
        "rootDomains": ["unauthorized.com"],
        "state": "CA",
    }

    response = client.post(
        "/organizations_upsert",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
        json=payload,
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Unauthorized access. View logs for details."


@pytest.mark.django_db(transaction=True)
def test_upsert_organization_invalid_parent():
    """Test that upserting an organization with a non-existent parent fails."""
    user = User.objects.create(
        firstName="Test",
        lastName="Admin",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    name = "test-{}".format(secrets.token_hex(4))
    acronym = secrets.token_hex(2)
    payload = {
        "ipBlocks": [],
        "acronym": acronym,
        "name": name,
        "isPassive": False,
        "rootDomains": ["invalidparent.com"],
        "state": "CA",
        "parent": str(uuid.uuid4()),  # Random UUID for non-existent parent
    }

    response = client.post(
        "/organizations_upsert",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
        json=payload,
    )

    assert response.status_code == 500


@pytest.mark.django_db(transaction=True)
def test_add_user_to_org_v2_success():
    """Test successfully adding a user to an organization by a regional admin."""
    admin = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
        regionId="region-1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization = Organization.objects.create(
        name="Test Organization",
        rootDomains=["test.com"],
        ipBlocks=[],
        isPassive=False,
        state="CA",
        regionId="region-1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        regionId="region-1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    payload = {
        "userId": str(user.id),
        "role": "member",
    }

    response = client.post(
        "/v2/organizations/{}/users".format(str(organization.id)),
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin))},
        json=payload,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["organization"]["id"] == str(organization.id)
    assert data["user"]["id"] == str(user.id)
    assert data["role"] == "member"
    assert data["approved"] is True
    assert data["approvedBy"]["id"] == str(admin.id)


@pytest.mark.django_db(transaction=True)
def test_add_user_to_org_v2_unauthorized():
    """Test that a standard user cannot add a user to an organization."""
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization = Organization.objects.create(
        name="Test Organization",
        rootDomains=["test.com"],
        ipBlocks=[],
        isPassive=False,
        state="CA",
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

    payload = {
        "userId": str(target_user.id),
        "role": "member",
    }

    response = client.post(
        "/v2/organizations/{}/users".format(str(organization.id)),
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
        json=payload,
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Unauthorized access."


@pytest.mark.django_db(transaction=True)
def test_add_user_to_org_v2_invalid_user_id():
    """Test adding a user with an invalid user ID format."""
    admin = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization = Organization.objects.create(
        name="Test Organization",
        rootDomains=["test.com"],
        ipBlocks=[],
        isPassive=False,
        state="CA",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    payload = {
        "userId": "invalid-user-id",
        "role": "member",
    }

    response = client.post(
        "/v2/organizations/{}/users".format(str(organization.id)),
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin))},
        json=payload,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Invalid user ID."


@pytest.mark.django_db(transaction=True)
def test_add_user_to_org_v2_invalid_organization_id():
    """Test adding a user with an invalid organization ID format."""
    admin = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
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

    payload = {
        "userId": str(user.id),
        "role": "member",
    }

    response = client.post(
        "/v2/organizations/{}/users".format("invalid-org-id"),
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin))},
        json=payload,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Invalid organization ID."


@pytest.mark.django_db(transaction=True)
def test_add_user_to_org_v2_user_not_found():
    """Test adding a non-existent user to an organization."""
    admin = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization = Organization.objects.create(
        name="Test Organization",
        rootDomains=["test.com"],
        ipBlocks=[],
        isPassive=False,
        state="CA",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    payload = {
        "userId": str(uuid.uuid4()),  # Non-existent user
        "role": "member",
    }

    response = client.post(
        "/v2/organizations/{}/users".format(str(organization.id)),
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin))},
        json=payload,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found."


@pytest.mark.django_db(transaction=True)
def test_add_user_to_org_v2_organization_not_found():
    """Test adding a user to a non-existent organization."""
    admin = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
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

    payload = {
        "userId": str(user.id),
        "role": "member",
    }

    response = client.post(
        "/v2/organizations/{}/users".format(str(uuid.uuid4())),  # Non-existent org
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin))},
        json=payload,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Organization not found."


@pytest.mark.django_db(transaction=True)
def test_add_user_to_org_v2_region_mismatch():
    """Test adding a user to an organization where the region does not match."""
    admin = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.REGIONAL_ADMIN,
        regionId="region-1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization = Organization.objects.create(
        name="Test Organization",
        rootDomains=["test.com"],
        ipBlocks=[],
        isPassive=False,
        state="CA",
        regionId="region-2",  # Different region
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        regionId="region-2",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    payload = {
        "userId": str(user.id),
        "role": "member",
    }

    response = client.post(
        "/v2/organizations/{}/users".format(str(organization.id)),
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin))},
        json=payload,
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Unauthorized access due to region mismatch."


@pytest.mark.django_db(transaction=True)
def test_list_organizations_v2_as_global_admin():
    """Test that a GlobalViewAdmin can retrieve all organizations."""
    admin = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization1 = Organization.objects.create(
        name="Test Organization 1",
        rootDomains=["test1.com"],
        ipBlocks=[],
        isPassive=False,
        state="CA",
        regionId="region-1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization2 = Organization.objects.create(
        name="Test Organization 2",
        rootDomains=["test2.com"],
        ipBlocks=[],
        isPassive=False,
        state="NY",
        regionId="region-2",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/v2/organizations",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin))},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    org_ids = [org["id"] for org in data]
    assert str(organization1.id) in org_ids
    assert str(organization2.id) in org_ids


@pytest.mark.django_db(transaction=True)
def test_list_organizations_v2_as_member():
    """Test that a user with organization membership can retrieve only their organizations."""
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization1 = Organization.objects.create(
        name="Test Organization 1",
        rootDomains=["test1.com"],
        ipBlocks=[],
        isPassive=False,
        state="CA",
        regionId="region-1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    Organization.objects.create(
        name="Test Organization 2",
        rootDomains=["test2.com"],
        ipBlocks=[],
        isPassive=False,
        state="NY",
        regionId="region-2",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Assign user to only one organization
    Role.objects.create(user=user, organization=organization1, role="member")

    response = client.get(
        "/v2/organizations",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["id"] == str(organization1.id)


@pytest.mark.django_db(transaction=True)
def test_list_organizations_v2_as_user_without_membership():
    """Test that a user with no organization membership gets an empty list."""
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    Organization.objects.create(
        name="Test Organization 1",
        rootDomains=["test1.com"],
        ipBlocks=[],
        isPassive=False,
        state="CA",
        regionId="region-1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/v2/organizations",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.django_db(transaction=True)
def test_list_organizations_v2_filter_by_state():
    """Test filtering organizations by state."""
    admin = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization1 = Organization.objects.create(
        name="Test Organization 1",
        rootDomains=["test1.com"],
        ipBlocks=[],
        isPassive=False,
        state="CA",
        regionId="region-1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    Organization.objects.create(
        name="Test Organization 2",
        rootDomains=["test2.com"],
        ipBlocks=[],
        isPassive=False,
        state="NY",
        regionId="region-2",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/v2/organizations?state=CA",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin))},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["state"] == "CA"
    assert data[0]["id"] == str(organization1.id)


@pytest.mark.django_db(transaction=True)
def test_list_organizations_v2_filter_by_region():
    """Test filtering organizations by region."""
    admin = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    Organization.objects.create(
        name="Test Organization 1",
        rootDomains=["test1.com"],
        ipBlocks=[],
        isPassive=False,
        state="CA",
        regionId="region-1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization2 = Organization.objects.create(
        name="Test Organization 2",
        rootDomains=["test2.com"],
        ipBlocks=[],
        isPassive=False,
        state="NY",
        regionId="region-2",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/v2/organizations?regionId=region-2",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin))},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["regionId"] == "region-2"
    assert data[0]["id"] == str(organization2.id)


@pytest.mark.django_db(transaction=True)
def test_list_organizations_v2_no_auth():
    """Test that an unauthenticated request returns 401."""
    response = client.get("/v2/organizations")
    assert response.status_code == 401


@pytest.mark.django_db(transaction=True)
def test_list_organizations_v2_invalid_filter():
    """Test that an invalid state filter does not return organizations."""
    admin = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    Organization.objects.create(
        name="Test Organization",
        rootDomains=["test.com"],
        ipBlocks=[],
        isPassive=False,
        state="CA",
        regionId="region-1",
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/v2/organizations?state=ZZ",  # Non-existent state code
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin))},
    )

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.django_db(transaction=True)
@patch("xfd_api.tasks.es_client.ESClient.search_organizations")
def test_search_organizations_as_global_admin(mock_search):
    """Test that a GlobalViewAdmin can search organizations."""
    admin = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Mock Elasticsearch response
    mock_search.return_value = {
        "hits": {"hits": [{"_source": {"name": "Test Org", "regionId": "region-1"}}]}
    }

    payload = {"searchTerm": "Test Org", "regions": []}

    response = client.post(
        "/search/organizations",
        json=payload,
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin))},
    )

    assert response.status_code == 200
    data = response.json()
    assert "body" in data
    assert len(data["body"]["hits"]["hits"]) == 1
    assert data["body"]["hits"]["hits"][0]["_source"]["name"] == "Test Org"


@pytest.mark.django_db(transaction=True)
@patch("xfd_api.tasks.es_client.ESClient.search_organizations")
def test_search_organizations_filter_by_region(mock_search):
    """Test that the search filters organizations by region."""
    admin = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Mock Elasticsearch response
    mock_search.return_value = {
        "hits": {"hits": [{"_source": {"name": "Region Org", "regionId": "region-3"}}]}
    }

    payload = {"searchTerm": "", "regions": ["region-3"]}

    response = client.post(
        "/search/organizations",
        json=payload,
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin))},
    )

    assert response.status_code == 200
    data = response.json()
    assert "body" in data
    assert len(data["body"]["hits"]["hits"]) == 1
    assert data["body"]["hits"]["hits"][0]["_source"]["regionId"] == "region-3"


@pytest.mark.django_db(transaction=True)
@patch("xfd_api.tasks.es_client.ESClient.search_organizations")
def test_search_organizations_no_results(mock_search):
    """Test searching for organizations when no results are found."""
    admin = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Mock Elasticsearch response (no results)
    mock_search.return_value = {"hits": {"hits": []}}

    payload = {"searchTerm": "Nonexistent Org", "regions": []}

    response = client.post(
        "/search/organizations",
        json=payload,
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin))},
    )

    assert response.status_code == 200
    data = response.json()
    assert "body" in data
    assert len(data["body"]["hits"]["hits"]) == 0


@pytest.mark.django_db(transaction=True)
def test_search_organizations_no_auth():
    """Test that an unauthenticated request returns 401."""
    payload = {"searchTerm": "Test", "regions": []}
    response = client.post("/search/organizations", json=payload)
    assert response.status_code == 401


@pytest.mark.django_db(transaction=True)
def test_search_organizations_no_access():
    """Test that a user without the necessary permissions gets an empty result."""
    user = User.objects.create(
        firstName="Unauthorized",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    payload = {"searchTerm": "Restricted Org", "regions": []}

    response = client.post(
        "/search/organizations",
        json=payload,
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.django_db(transaction=True)
def test_get_all_regions_as_global_admin():
    """Test that a GlobalViewAdmin can retrieve all regions."""
    admin = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["test.com"],
        ipBlocks=[],
        isPassive=False,
        regionId="region-1",
    )

    Organization.objects.create(
        name="test-{}".format(secrets.token_hex(4)),
        rootDomains=["example.com"],
        ipBlocks=[],
        isPassive=False,
        regionId="region-2",
    )

    response = client.get(
        "/regions",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin))},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert {"regionId": "region-1"} in data
    assert {"regionId": "region-2"} in data


@pytest.mark.django_db(transaction=True)
def test_get_all_regions_as_standard_user_fails():
    """Test that a standard user cannot retrieve regions (should return 403)."""
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/regions",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Unauthorized"


@pytest.mark.django_db(transaction=True)
def test_get_all_regions_no_auth():
    """Test that an unauthenticated request returns 401."""
    response = client.get("/regions")
    assert response.status_code == 401


@pytest.mark.django_db(transaction=True)
def test_get_all_regions_empty():
    """Test that an empty result is returned if no organizations have regionIds."""
    admin = User.objects.create(
        firstName="Admin",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        "/regions",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(admin))},
    )

    assert response.status_code == 200
    assert response.json() == []
