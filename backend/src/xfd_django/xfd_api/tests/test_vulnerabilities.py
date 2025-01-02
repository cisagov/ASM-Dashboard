# Standard Python Libraries
from datetime import datetime, timedelta
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
    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    yield user
    user.delete()  # Clean up after the test


@pytest.fixture
def organization():
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
    assert vulnerability.title == search_fields["title"]
    assert vulnerability.cpe == search_fields["cpe"]
    assert vulnerability.severity == search_fields["severity"]
    assert vulnerability.state == search_fields["state"]
    assert vulnerability.substate == search_fields["substate"]
    assert vulnerability.isKev == search_fields["isKev"]
    yield vulnerability
    vulnerability.delete()


@pytest.fixture
def old_vulnerability():
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
    # Get vulnerability by Id.
    response = client.get(
        f"/vulnerabilities/{str(vulnerability.id)}",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    data = response.json()

    assert response.status_code == 200
    assert data["id"] == str(vulnerability.id)
    assert data["domain"]["id"] == str(vulnerability.domain.id)
    assert data["severity"] == vulnerability.severity


@pytest.mark.django_db(transaction=True)
def test_get_vulnerability_by_id_fails_404(user, vulnerability):
    # Get error 404 if vulnerability does not exist
    response = client.get(
        f"/vulnerabilities/{bad_id}",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 404


@pytest.mark.django_db(transaction=True)
def test_update_vulnerability(user, vulnerability):
    original_vuln_id = str(vulnerability.id)
    now = datetime.now()
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
        f"/vulnerabilities/{str(vulnerability.id)}",
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
def test_update_vulnerability_fails_404(user, vulnerability):
    vulnerability = vulnerability
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
        "cvss": 7.5,
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
        f"/vulnerabilities/{bad_id}",
        json=new_data,
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 404


@pytest.mark.django_db(transaction=True)
def test_update_vulnerability_fails_422(user, vulnerability):
    vulnerability = vulnerability

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
def test_search_vulnerabilities_id(user, vulnerability):
    # Search vulnerabilities by ip.
    response = client.post(
        "/vulnerabilities/search",
        json={"page": 1, "filters": {"id": str(vulnerability.id)}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()
    assert data is not None, "Response is empty"
    assert "result" in data, "Response does not contain 'result' key"
    assert len(data["result"]) > 0, "No result found for the given ID"
    for vuln in data["result"]:
        assert vuln["id"] == str(
            vulnerability.id
        ), f"Vulnerability ID {vuln['id']} does not match the expected {vulnerability.id}"


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_title(user, vulnerability):
    # Test search vulnerabilities by title

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
        ), f"Vulnerability title {vuln['title']} does not match the expected {search_fields['title']}"


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_cpe(user, vulnerability):
    # Test search vulnerabilities by cpe
    response = client.post(
        "/vulnerabilities/search",
        json={"page": 1, "filters": {"cpe": search_fields["cpe"]}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()

    assert data is not None, "Response is empty"
    assert "result" in data, "Response does not contain 'result' key"
    assert len(data["result"]) > 0, "No result found for the given CPE"

    for vuln in data["result"]:
        assert (
            vuln["cpe"] == search_fields["cpe"]
        ), f"Vulnerability CPE {vuln['cpe']} does not match the expected {search_fields['cpe']}"


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_severity(user, vulnerability):
    # Test search vulnerabilities by severity
    response = client.post(
        "/vulnerabilities/search",
        json={
            "page": 1,
            "filters": {"severity": search_fields["severity"]},
            "pageSize": 25,
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    data = response.json()

    assert data is not None, "Response is empty"
    assert "result" in data, "Response does not contain 'result' key"

    assert len(data["result"]) > 0, "No result found for the given severity"

    for vuln in data["result"]:
        assert (
            vuln["severity"] == search_fields["severity"]
        ), f"Vulnerability severity {vuln['severity']} does not match the expected {search_fields['severity']}"


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_domain_id(user, vulnerability):
    # Test search vulnerabilities by domain id
    domain_name = str(vulnerability.domain.name)
    response = client.post(
        "/vulnerabilities/search",
        json={"page": 1, "filters": {"domain": domain_name}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200

    data = response.json()

    assert data is not None, "Response is empty"
    assert "result" in data, "Response does not contain 'result' key"
    assert len(data["result"]) > 0, "No vulnerabilities found for the given domain"

    for vuln in data["result"]:
        assert (
            str(vuln["domain"]["name"]) == domain_name
        ), f"Vulnerability with ID {vuln['id']} does not have the expected domain_id {domain_name}"


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_state(user, vulnerability):
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
        assert (
            vuln["state"] == state_to_search
        ), f"Vulnerability with ID {vuln['id']} does not have the expected state {state_to_search}"


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_substate(user, vulnerability):
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
        assert (
            vuln["substate"] == substate_to_search
        ), f"Vulnerability with ID {vuln['id']} does not have the expected substate {substate_to_search}"


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_organization_id(user, vulnerability):
    organization_id = str(vulnerability.domain.organization.id)

    response = client.post(
        "/vulnerabilities/search",
        json={
            "page": 1,
            "filters": {"organization": organization_id},
            "pageSize": 25,
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200

    data = response.json()
    assert data is not None, "Response is empty"
    assert "result" in data, "Response does not contain 'result' key"
    assert len(data["result"]) > 0, "No result found for the given organization"

    for vulnerability_data in data["result"]:
        domain_id = vulnerability_data.get("domain_id", None)
        if domain_id:
            domain = Domain.objects.get(id=domain_id)
            assert (
                str(domain.organization.id) == organization_id
            ), f"Vulnerability with ID {vulnerability_data.get('id', 'N/A')} does not belong to the expected organization"
        else:
            print(
                f"Warning: 'domain_id' key not found in vulnerability with ID {vulnerability_data.get('id', 'N/A')}"
            )


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_is_kev(user, vulnerability):
    is_kev_to_search = search_fields["isKev"]

    response = client.post(
        "/vulnerabilities/search",
        json={"page": 1, "filters": {"isKev": is_kev_to_search}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200

    data = response.json()

    assert data is not None, "Response is empty"
    assert "result" in data, "Response does not contain 'result' key"
    assert (
        len(data["result"]) > 0
    ), f"No vulnerabilities found for the given isKev value {is_kev_to_search}"

    for vuln in data["result"]:
        assert (
            vuln["isKev"] == is_kev_to_search
        ), f"Vulnerability with ID {vuln['id']} does not have the expected 'isKev' value {is_kev_to_search}"


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_by_multiple_criteria(user, vulnerability):
    state_to_search = search_fields["state"]
    substate_to_search = search_fields["substate"]

    response = client.post(
        "/vulnerabilities/search",
        json={
            "page": 1,
            "filters": {
                "state": state_to_search,
                "substate": substate_to_search,
            },
            "pageSize": 25,
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200

    data = response.json()

    assert data is not None, "Response is empty"
    assert "result" in data, "Response does not contain 'result' key"
    assert (
        len(data["result"]) > 0
    ), f"No vulnerabilities found for the given 'state' = {state_to_search} and 'substate' = {substate_to_search}"

    for vuln in data["result"]:
        assert (
            vuln["state"] == state_to_search
        ), f"Vulnerability with ID {vuln['id']} does not have the expected 'state' value {state_to_search}"
        assert (
            vuln["substate"] == substate_to_search
        ), f"Vulnerability with ID {vuln['id']} does not have the expected 'substate' value {substate_to_search}"


@pytest.mark.django_db(transaction=True)
def test_search_vulnerabilities_does_not_exist(user, vulnerability):
    # Test search vulnerabilities by state
    response = client.post(
        "/vulnerabilities/search",
        json={"page": 1, "filters": {"title": "Does Not Exist"}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 404
