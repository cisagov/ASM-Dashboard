"""Test vulnerability."""
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
from xfd_api.models import Domain, Organization, Service, User, UserType, Vulnerability
from xfd_django.asgi import app

client = TestClient(app)

bad_id = "c0effe93-3647-475a-a0c5-0b629c348590"
search_fields = {
    "title": "DNS Twist Domains",
    "cpe": "cpe:/a:openbsd:openssh:7.4",
    "severity": "Low",
    "state": "open",
    "substate": "unconfirmed",
    "isKev": False,
}


@pytest.fixture
def user():
    """Create user fixture."""
    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    yield user
    user.delete()  # Clean up after the test


@pytest.fixture
def organization():
    """Create org fixture."""
    organization = Organization.objects.create(
        name="Test Organization",
        rootDomains=["crossfeed.local"],
        ipBlocks=[],
        isPassive=False,
    )
    yield organization
    organization.delete()


@pytest.fixture
def domain(organization):
    """Create domain fixture."""
    domain = Domain.objects.create(
        reverseName="local.crossfeed.example",
        ip="127.116.195.151",  # Ensure this IP is the one you expect
        organization=organization,
        name="example.crossfeed.local",
        isFceb=True,
    )
    assert domain.organization == organization
    yield domain
    domain.delete()


@pytest.fixture
def service(domain):
    """Create service fixture."""
    service = Service.objects.create(
        serviceSource="shodan",
        port="80",
        service="http",
        products="test test test",
        censysIpv4Results={},
        intrigueIdentResults={},
        shodanResults={},
        wappalyzerResults=[],
        domain=domain,
    )
    assert service.domain == domain
    yield service
    service.delete()


@pytest.fixture
def vulnerability(domain, service):
    """Create vulnerability fixture."""
    vulnerability = Vulnerability.objects.create(
        title=search_fields["title"],
        cpe=search_fields["cpe"],
        severity=search_fields["severity"],
        description="Test description",
        references=[],
        needsPopulation=False,
        state=search_fields["state"],
        substate=search_fields["substate"],
        source="test",
        notes="test",
        actions=[],
        structuredData={},
        isKev=search_fields["isKev"],
        domain=domain,
        service=service,
    )
    assert vulnerability.domain == domain
    assert vulnerability.service == service
    yield vulnerability
    vulnerability.delete()


@pytest.fixture
def old_vulnerability():
    """Create old vulnerability fixture."""
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
    yield vulnerability
    vulnerability.delete()


@pytest.mark.django_db(transaction=True)
def test_get_vulnerability_by_id(user, vulnerability):
    """Test vulnerability."""
    # Get vulnerability by Id.
    response = client.get(
        "/vulnerabilities/{}/".format(vulnerability.id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    data = response.json()

    assert response.status_code == 200
    assert data["id"] == str(vulnerability.id)
    assert data["domain"]["id"] == str(vulnerability.domain.id)
    assert data["severity"] == vulnerability.severity


@pytest.mark.django_db(transaction=True)
def test_get_vulnerability_by_id_fails_404(user, vulnerability):
    """Test vulnerability."""
    # Get error 404 if vulnerability does not exist
    response = client.get(
        "/vulnerabilities/{}/".format(bad_id),
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 404


@pytest.mark.django_db(transaction=True)
def test_update_vulnerability(user, vulnerability):
    """Test vulnerability."""
    original_vuln_id = str(vulnerability.id)
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
        "severity": "Medium",
        "cvss": None,
        "needsPopulation": False,
        "state": vulnerability.state,
        "substate": vulnerability.substate,
        "source": "source2",
        "notes": "updated notes",
        "actions": ["action1"],
        "structuredData": {"key": "value"},
        "isKev": True,
        "domain_id": str(vulnerability.domain.id),
        "service_id": str(vulnerability.service.id),
    }

    response = client.put(
        "/vulnerabilities/{}/".format(vulnerability.id),
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
    assert vulnerability.severity == new_data["severity"]
    assert vulnerability.cvss == new_data["cvss"]
    assert vulnerability.isKev == new_data["isKev"]
    assert vulnerability.actions == new_data["actions"]

    assert str(vulnerability.id) == original_vuln_id


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_title(user, vulnerability):
    """Test search vulnerabilities by title."""
    response = client.post(
        "/vulnerabilities/search",
        json={"page": 1, "filters": {"title": search_fields["title"]}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert data is not None, "Response is empty"
    assert "result" in data, "Response does not contain 'result' key"
    assert len(data["result"]) > 0, "No result found for the given title"
    for vuln in data["result"]:
        assert (
            vuln["title"] == search_fields["title"]
        ), "Vulnerability title {} does not match the expected {}".format(
            vuln["title"], search_fields["title"]
        )


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_state(user, vulnerability):
    """Test search vulnerabilities by state."""
    state_to_search = search_fields["state"]

    response = client.post(
        "/vulnerabilities/search",
        json={"page": 1, "filters": {"state": state_to_search}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200

    data = response.json()

    assert data is not None, "Response is empty"
    assert "result" in data, "Response does not contain 'result' key"
    assert len(data["result"]) > 0, "No vulnerabilities found for the given state"

    for vuln in data["result"]:
        assert vuln["state"] == state_to_search


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_substate(user, vulnerability):
    """Test search vulnerabilities by substate."""
    substate_to_search = search_fields["substate"]

    response = client.post(
        "/vulnerabilities/search",
        json={"page": 1, "filters": {"substate": substate_to_search}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()

    assert data is not None, "Response is empty"
    assert "result" in data, "Response does not contain 'result' key"
    assert len(data["result"]) > 0, "No vulnerabilities found for the given substate"

    for vuln in data["result"]:
        assert vuln["substate"] == substate_to_search
