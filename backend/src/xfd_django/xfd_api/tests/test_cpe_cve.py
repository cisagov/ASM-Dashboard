"""Test CVE/CPE."""
# Standard Python Libraries
from datetime import datetime
import secrets
import uuid

# Third-Party Libraries
from fastapi.testclient import TestClient
import pytest
from xfd_api.auth import create_jwt_token
from xfd_api.models import Cpe, Cve, User, UserType
from xfd_django.asgi import app

client = TestClient(app)


@pytest.mark.django_db(transaction=True)
def test_get_cpe_by_id_success():
    """Test successfully retrieving a CPE by ID."""
    # Create a user to authenticate the request
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Create a sample CPE record
    cpe = Cpe.objects.create(
        id=uuid.uuid4(),
        name="cpe:/o:test_os:1.0",
        version="1.0.0",
        vendor="TestVendor",
        lastSeenAt=datetime.now(),
    )

    # Make the request
    response = client.get(
        "/cpes/{}".format(cpe.id),
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(cpe.id)
    assert data["name"] == "cpe:/o:test_os:1.0"


@pytest.mark.django_db(transaction=True)
def test_get_cpe_by_id_not_found():
    """Test retrieving a non-existent CPE should return a 500 error."""
    # Create a user to authenticate the request
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    fake_cpe_id = uuid.uuid4()

    # Make the request with a non-existent CPE ID
    response = client.get(
        "/cpes/{}".format(fake_cpe_id),
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 500
    assert "detail" in response.json()


@pytest.mark.django_db(transaction=True)
def test_get_cve_by_id_success():
    """Test successfully retrieving a CVE by ID."""
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    cve = Cve.objects.create(
        id=uuid.uuid4(),
        name="CVE-2024-1234",
        description="Test CVE description",
        publishedAt=datetime.now(),
        modifiedAt=datetime.now(),
        status="Active",
        cvssV3BaseScore="9.8",
        cvssV3BaseSeverity="Critical",
        weaknesses="None",
        references="https://cve.mitre.org",
    )

    response = client.get(
        "/cves/{}".format(cve.id),
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(cve.id)
    assert data["name"] == "CVE-2024-1234"


@pytest.mark.django_db(transaction=True)
def test_get_cve_by_id_not_found():
    """Test retrieving a non-existent CVE should return a 500 error."""
    # Create a user to authenticate the request
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    fake_cve_id = uuid.uuid4()

    # Make the request with a non-existent CVE ID
    response = client.get(
        "/cves/{}".format(fake_cve_id),
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 500
    assert "detail" in response.json()


@pytest.mark.django_db(transaction=True)
def test_get_cve_by_name_success():
    """Test successfully retrieving a CVE by name."""
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    cve = Cve.objects.create(
        id=uuid.uuid4(),
        name="CVE-2024-5678",
        description="Another test CVE",
        publishedAt=datetime.now(),
        modifiedAt=datetime.now(),
        status="Resolved",
        cvssV2BaseScore="5.0",
        cvssV2BaseSeverity="Medium",
    )

    response = client.get(
        "/cves/name/{}".format(cve.name),
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "CVE-2024-5678"
    assert data["description"] == "Another test CVE"
    assert data["status"] == "Resolved"


@pytest.mark.django_db(transaction=True)
def test_get_cve_by_name_not_found():
    """Test retrieving a non-existent CVE by name should return a 500 error."""
    # Create a user to authenticate the request
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Make the request with a non-existent CVE name
    response = client.get(
        "/cves/name/CVE-9999-9999",
        headers={"Authorization": "Bearer {}".format(create_jwt_token(user))},
    )

    assert response.status_code == 500
    assert "detail" in response.json()
