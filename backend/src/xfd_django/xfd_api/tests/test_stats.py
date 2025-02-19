"""Test Stats endpoint."""
# Standard Python Libraries
from asyncio import Semaphore
from datetime import datetime
from decimal import Decimal
import secrets

# Third-Party Libraries
from django.core.management import call_command
from fastapi.testclient import TestClient
import pytest
from redis import asyncio as aioredis
from xfd_api.auth import create_jwt_token
from xfd_api.models import (
    Domain,
    Organization,
    Role,
    Service,
    User,
    UserType,
    Vulnerability,
)
from xfd_api.views import get_redis_client
from xfd_django.asgi import app

client = TestClient(app)


@pytest.fixture(scope="session")
def redis_client():
    """Ensure Redis is properly initialized before tests."""
    redis_url = "redis://redis"
    client = aioredis.from_url(
        redis_url,
        encoding="utf-8",
        decode_responses=True,
        max_connections=100,
        socket_timeout=5,
    )

    yield client  # Redis client available for tests

    client.flushdb()  # Clean Redis after tests
    client.close()


@pytest.fixture(scope="session", autouse=True)
def ensure_fastapi_state(redis_client):
    """Ensure FastAPI's app.state.redis is set before running any tests."""
    print("Setting up FastAPI Redis state...")
    app.state.redis = redis_client  # Inject into FastAPI state
    app.state.redis_semaphore = Semaphore(20)
    yield
    print("Cleaning up FastAPI Redis state...")
    del app.state.redis  # Cleanup after tests


@pytest.fixture(scope="session", autouse=True)
def override_redis_dependency(redis_client):
    """Ensure FastAPI's Redis dependency is overridden globally for tests."""
    app.dependency_overrides[get_redis_client] = lambda: redis_client
    yield
    app.dependency_overrides.pop(get_redis_client)


@pytest.mark.django_db(transaction=True)
def test_get_stats_by_org_user():
    """Test retrieving stats as an organization user."""
    organization = Organization.objects.create(
        name="test-" + secrets.token_hex(4),
        rootDomains=["test-" + secrets.token_hex(4)],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization2 = Organization.objects.create(
        name="test-" + secrets.token_hex(4),
        rootDomains=["test-" + secrets.token_hex(4)],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    domain = Domain.objects.create(
        name="test-" + secrets.token_hex(4), isFceb=True, organization=organization
    )

    Vulnerability.objects.create(
        title="vuln title", domain=domain, cvss=Decimal(9.0), severity="Critical"
    )

    Service.objects.create(service="http", port=80, domain=domain)

    Domain.objects.create(
        name="test-" + secrets.token_hex(4), isFceb=True, organization=organization2
    )

    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    Role.objects.create(
        user=user,
        organization=organization,
        role="user",
    )

    # Populate redis
    call_command("populate_services_cache")
    call_command("populate_ports_cache")
    call_command("populate_vulns_cache")
    call_command("populate_most_common_vulns_cache")
    call_command("populate_latest_vulns_cache")
    call_command("populate_severity_count_cache")
    call_command("populate_by_orgs_cache")

    response = client.post(
        "/stats",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
        json={"filters": {"organizations": [str(organization.id)]}},
    )

    assert response.status_code == 200
    data = response.json()
    assert "domains" in data["result"]
    assert "numVulnerabilities" in data["result"]["domains"]
    assert data["result"]["domains"]["numVulnerabilities"][0][
        "id"
    ] == "{}|Critical".format(domain.name)


@pytest.mark.django_db(transaction=True)
def test_get_stats_by_global_view_user():
    """Test retrieving stats as a GlobalView user with organization filtering."""
    organization = Organization.objects.create(
        name="test-" + secrets.token_hex(4),
        rootDomains=["test-" + secrets.token_hex(4)],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    organization2 = Organization.objects.create(
        name="test-" + secrets.token_hex(4),
        rootDomains=["test-" + secrets.token_hex(4)],
        ipBlocks=[],
        isPassive=False,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    domain = Domain.objects.create(
        name="test-" + secrets.token_hex(4), isFceb=True, organization=organization
    )

    Vulnerability.objects.create(
        title="vuln title", domain=domain, cvss=Decimal(8.0), severity="High"
    )

    Service.objects.create(service="http", port=80, domain=domain)

    domain2 = Domain.objects.create(
        name="test-" + secrets.token_hex(4), isFceb=True, organization=organization2
    )

    Vulnerability.objects.create(
        title="vuln title 2", domain=domain2, cvss=Decimal(1.0), severity="Low"
    )

    Service.objects.create(service="https", port=443, domain=domain2)

    user = User.objects.create(
        firstName="",
        lastName="",
        email="{}@example.com".format(secrets.token_hex(4)),
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Populate redis
    call_command("populate_services_cache")
    call_command("populate_ports_cache")
    call_command("populate_vulns_cache")
    call_command("populate_most_common_vulns_cache")
    call_command("populate_latest_vulns_cache")
    call_command("populate_severity_count_cache")
    call_command("populate_by_orgs_cache")

    response = client.post(
        "/stats",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
        json={"filters": {"organizations": [str(organization.id)]}},
    )

    assert response.status_code == 200
    data = response.json()
    assert "domains" in data["result"]
    assert "numVulnerabilities" in data["result"]["domains"]
    assert data["result"]["domains"]["numVulnerabilities"][0]["id"] == "{}|High".format(
        domain.name
    )
