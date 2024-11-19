# Standard Python Libraries
from datetime import datetime
import secrets

# Third-Party Libraries
from fastapi.testclient import TestClient
import pytest
from xfd_api.auth import create_jwt_token
from xfd_api.models import User, UserType
from xfd_django.asgi import app

client = TestClient(app)


test_id = "960b7db7-f3af-411d-a247-33371739050b"
bad_id = "960b7db7-f3af-411d-a247-333717390999"
filters = {
    "ports": "80",
    "service": "6d9ecf5a-db5d-4b77-9752-a88a5d247631",
    "reverseName": "local.crossfeed.quizzical-wing",
    "ip": "127.116.195.151",
    "organization": "5ef69132-d3ab-43d2-bbe4-a1c79962af9c",
    "organizationName": "Wizardly Agency",
    "vulnerabilities": "c0effe93-3647-475a-a0c5-0b629c348588",
    "tag": "",
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


@pytest.mark.django_db(transaction=True)
def test_get_domain_by_id(user):
    # Get domain by Id.
    response = client.get(
        f"/domain/{test_id}",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    data = response.json()

    assert response.status_code == 200
    assert data["id"] == test_id


@pytest.mark.django_db(transaction=True)
def test_get_domain_by_id_fails_404(user):
    # Get domain by Id.
    response = client.get(
        f"/domain/{bad_id}",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    data = response.json()

    assert response.status_code == 404


@pytest.mark.django_db(transaction=True)
def test_search_domain_by_ip(user):
    # Search domains by ip
    response = client.post(
        "/domain/search",
        json={"page": 1, "filters": {"ip": filters["ip"]}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    data = response.json()
    for domain in data:
        assert domain["ip"] == filters["ip"]


@pytest.mark.django_db(transaction=True)
def test_search_domain_by_port(user):
    # Test search domains by port
    response = client.post(
        "/domain/search",
        json={"page": 1, "filters": {"ports": filters["ports"]}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    for domain in data:
        assert domain["id"] != ""


@pytest.mark.django_db(transaction=True)
def test_search_domain_by_service(user):
    # Test search domains by service_id
    response = client.post(
        "/domain/search",
        json={"page": 1, "filters": {"service": filters["service"]}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    for domain in data:
        assert domain["id"] != ""


@pytest.mark.django_db(transaction=True)
def test_search_domain_by_organization(user):
    # Test search domains by organization
    response = client.post(
        "/domain/search",
        json={
            "page": 1,
            "filters": {"organization": filters["organization"]},
            "pageSize": 25,
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    data = response.json()
    for domain in data:
        assert domain["organization_id"] == filters["organization"]


@pytest.mark.django_db(transaction=True)
def test_search_domain_by_organization_name(user):
    # Test search domains by organization
    response = client.post(
        "/domain/search",
        json={
            "page": 1,
            "filters": {"organizationName": filters["organizationName"]},
            "pageSize": 25,
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    for domain in data:
        assert domain["id"] != ""


@pytest.mark.django_db(transaction=True)
def test_search_domain_by_vulnerabilities(user):
    # Test search domains by vulnerabilities
    response = client.post(
        "/domain/search",
        json={
            "page": 1,
            "filters": {"vulnerabilities": filters["vulnerabilities"]},
            "pageSize": 25,
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    data = response.json()
    assert data is not None
    for domain in data:
        assert domain["id"] != ""


@pytest.mark.django_db(transaction=True)
def test_search_domains_multiple_criteria(user):
    # Test search domains by multiple criteria
    response = client.post(
        "/domain/search",
        json={
            "page": 1,
            "filters": {"ip": filters["ip"], "ports": filters["ports"]},
            "pageSize": 25,
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    data = response.json()
    for domain in data:
        assert domain["ip"] == filters["ip"]


@pytest.mark.django_db(transaction=True)
def test_search_domains_does_not_exist(user):
    # Test search domains if record does not exist
    response = client.post(
        "/domain/search",
        json={"page": 1, "filters": {"ip": "Does not exist"}, "pageSize": 25},
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 404
