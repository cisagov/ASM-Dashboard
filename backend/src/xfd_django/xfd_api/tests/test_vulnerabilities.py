# Standard Python Libraries
from datetime import datetime
import logging
import secrets

# Configure logging
logging.basicConfig(level=logging.DEBUG)  # Set the logging level to DEBUG
logger = logging.getLogger(__name__)


# Third-Party Libraries
from fastapi.testclient import TestClient
import pytest
from xfd_api.auth import create_jwt_token
from xfd_api.models import User, UserType, Vulnerability
from xfd_django.asgi import app

client = TestClient(app)

test_id = "c0effe93-3647-475a-a0c5-0b629c348588"
bad_id = "c0effe93-3647-475a-a0c5-0b629c348590"
filters = {
    "id": "d39a8536-0b64-45b6-b621-5d954329221c",
    "title": "DNS Twist Domains",
    "cpe": "cpe:/a:openbsd:openssh:7.4",
    "severity": "Low",
    "domain": "84313a29-0009-45dc-8a2d-1ff7e0ba0030",
    "state": "open",
    "substate": "unconfirmed",
    "organization": "fff159cb-efc8-4ea8-be51-e6b65e38d3e9",
    "isKev": False,
}


@pytest.mark.django_db(transaction=True)
def test_get_vulnerability_by_id():
    # Get vulnerability by Id.
    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        f"/vulnerabilities/{test_id}",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    data = response.json()

    assert response.status_code == 200
    assert data["id"] == test_id


@pytest.mark.django_db(transaction=True)
def test_get_vulnerability_by_id_fails_404():
    # Get error 404 if vulnerability does not exist
    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.get(
        f"/vulnerabilities/{bad_id}",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 404


@pytest.mark.django_db(transaction=True)
def test_update_vulnerability():
    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    vulnerability = Vulnerability.objects.create(
        title="Old Vulnerability",
        description="Old description.",
        severity="Medium",
        cvss=5.0,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
        needsPopulation=True,
        source="source1",
        notes="old notes",
        actions=[],
        structuredData={},
        isKev=False,
        kevResults={},
        domain_id="",
        service_id="",
    )

    new_data = {
        "id": str(vulnerability.id),
        "createdAt": str(vulnerability.createdAt),
        "updatedAt": str(datetime.now()),
        "lastSeen": str(datetime.now()),
        "title": "Updated Vulnerability",
        "cve": vulnerability.cve,
        "cwe": vulnerability.cwe,
        "cpe": vulnerability.cpe,
        "description": "Updated description.",
        "references": None,
        "severity": "High",
        "cvss": 7.5,
        "needsPopulation": False,
        "state": vulnerability.state,
        "substate": vulnerability.substate,
        "source": "source2",
        "notes": "updated notes",
        "actions": ["action1"],
        "structuredData": {"key": "value"},
        "isKev": True,
        "domain_id": None,
        "service_id": None,
    }

    response = client.put(
        f"/vulnerabilities/{vulnerability.id}",
        json=new_data,
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200

    vulnerability.refresh_from_db()
    assert vulnerability.title == new_data["title"]
    assert vulnerability.description == new_data["description"]
    assert vulnerability.needsPopulation == new_data["needsPopulation"]
    assert vulnerability.source == new_data["source"]
    assert vulnerability.notes == new_data["notes"]

    assert vulnerability.id == vulnerability.id


@pytest.mark.django_db(transaction=True)
def test_update_vulnerability_fails_404():
    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    vulnerability = Vulnerability.objects.create(
        title="Old Vulnerability",
        description="Old description.",
        severity="Medium",
        cvss=5.0,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
        needsPopulation=True,
        source="source1",
        notes="old notes",
        actions=[],
        structuredData={},
        isKev=False,
        kevResults={},
        domain_id="",
        service_id="",
    )

    new_data = {
        "id": str(vulnerability.id),
        "createdAt": str(vulnerability.createdAt),
        "updatedAt": str(datetime.now()),
        "lastSeen": str(datetime.now()),
        "title": "Updated Vulnerability",
        "cve": vulnerability.cve,
        "cwe": vulnerability.cwe,
        "cpe": vulnerability.cpe,
        "description": "Updated description.",
        "references": None,
        "severity": "High",
        "cvss": 7.5,
        "needsPopulation": False,
        "state": vulnerability.state,
        "substate": vulnerability.substate,
        "source": "source2",
        "notes": "updated notes",
        "actions": ["action1"],
        "structuredData": {"key": "value"},
        "isKev": True,
        "domain_id": None,
        "service_id": None,
    }

    response = client.put(
        f"/vulnerabilities/{bad_id}",
        json=new_data,
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 404


@pytest.mark.django_db(transaction=True)
def test_update_vulnerability_fails_422():
    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    vulnerability = Vulnerability.objects.create(
        title="Old Vulnerability",
        description="Old description.",
        severity="Medium",
        cvss=5.0,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
        needsPopulation=True,
        source="source1",
        notes="old notes",
        actions=[],
        structuredData={},
        isKev=False,
        kevResults={},
        domain_id="",
        service_id="",
    )

    new_data = {
        "title": "Updated Vulnerability",
        "cve": vulnerability.cve,
        "cwe": vulnerability.cwe,
        "cpe": vulnerability.cpe,
        "description": "Updated description.",
        "references": None,
        "severity": "High",
        "cvss": 7.5,
        "needsPopulation": False,
        "state": vulnerability.state,
        "substate": vulnerability.substate,
        "source": "source2",
        "notes": "updated notes",
        "actions": ["action1"],
        "structuredData": {"key": "value"},
        "isKev": True,
        "domain_id": None,
        "service_id": None,
    }

    response = client.put(
        f"/vulnerabilities/{vulnerability.id}",
        json=new_data,
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 422


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_id():
    # Search vulnerabilities by ip.
    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.post(
        "/vulnerabilities/search",
        json={"page": 1, "filters": {"id": filters["id"]}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert data is not None
    for vulnerability in data:
        assert vulnerability["id"] == filters["id"]


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_title():
    # Test search vulnerabilities by title

    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.post(
        "/vulnerabilities/search",
        json={"page": 1, "filters": {"title": filters["title"]}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert data is not None
    for vulnerability in data:
        assert vulnerability["title"] == filters["title"]


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_cpe():
    # Test search vulnerabilities by cpe

    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.post(
        "/vulnerabilities/search",
        json={"page": 1, "filters": {"cpe": filters["cpe"]}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert data is not None
    for vulnerability in data:
        assert vulnerability["cpe"] == filters["cpe"]


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_severity():
    # Test search vulnerabilities by severity

    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.post(
        "/vulnerabilities/search",
        json={"page": 1, "filters": {"severity": filters["severity"]}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert data is not None
    for vulnerability in data:
        assert vulnerability["severity"] == filters["severity"]


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_domain_id():
    # Test search vulnerabilities by domain id

    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.post(
        "/vulnerabilities/search",
        json={"page": 1, "filters": {"domain": filters["domain"]}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert data is not None
    for vulnerability in data:
        assert vulnerability["domain_id"] == filters["domain"]


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_state():
    # Test search vulnerabilities by state

    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.post(
        "/vulnerabilities/search",
        json={"page": 1, "filters": {"state": filters["state"]}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert data is not None
    for vulnerability in data:
        assert vulnerability["state"] == filters["state"]


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_substate():
    # Test search vulnerabilities by state

    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.post(
        "/vulnerabilities/search",
        json={"page": 1, "filters": {"substate": filters["substate"]}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert data is not None
    for vulnerability in data:
        assert vulnerability["substate"] == filters["substate"]


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_organization_id():
    # Test search vulnerabilities by state

    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.post(
        "/vulnerabilities/search",
        json={
            "page": 1,
            "filters": {"organization": filters["organization"]},
            "pageSize": 25,
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert data is not None


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_is_kev():
    # Test search vulnerabilities by state

    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.post(
        "/vulnerabilities/search",
        json={"page": 1, "filters": {"isKev": filters["isKev"]}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert data is not None
    for vulnerability in data:
        assert vulnerability["isKev"] == filters["isKev"]


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_multiple_criteria():
    # Test search vulnerabilities by state

    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.post(
        "/vulnerabilities/search",
        json={
            "page": 1,
            "filters": {"state": filters["state"], "substate": filters["substate"]},
            "pageSize": 25,
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert data is not None
    for vulnerability in data:
        assert vulnerability["state"] == filters["state"]
        assert vulnerability["substate"] == filters["substate"]


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_does_not_exist():
    # Test search vulnerabilities by state

    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    response = client.post(
        "/vulnerabilities/search",
        json={"page": 1, "filters": {"title": "Does Not Exist"}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 404
