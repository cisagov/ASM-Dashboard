"""Integration test for domain API."""
# Standard Python Libraries
import os
import random

# Third-Party Libraries
import pytest
import requests

BASE_URL = os.environ.get("BACKEND_DOMAIN")
X_API_KEY = os.environ.get("X_API_KEY")
BAD_ID = "01234567-0123-4567-8901-12345"


def get_domains():
    """Get a tuple of domain IDs for testing."""
    response = requests.post(
        "{}/domain/search".format(BASE_URL),
        json={
            "page": 1,
            "pageSize": 10,
        },
        headers={"X-API-KEY": X_API_KEY},
        timeout=10,
    )

    assert response.status_code == 200
    data = response.json()
    assert data is not None, "Response is empty"
    assert "result" in data, "Results not found in response"
    assert len(data["result"]) > 0, "No results found"

    return data["result"]


domains = get_domains()


# mark tests with integration tag, run with pytest -m integration
@pytest.mark.integration
def test_get_domain_by_id():
    """Test get domain by id."""
    selected_domain = random.choice(domains)
    domain_id = selected_domain["id"]

    response = requests.get(
        "{}/domain/{}".format(BASE_URL, domain_id),
        headers={"X-API-KEY": X_API_KEY},
        timeout=10,
    )

    assert response.status_code == 200
    data = response.json()
    assert data is not None, "Response is empty"
    assert data["id"] == domain_id


@pytest.mark.integration
def test_get_domain_by_id_fails_404():
    """Test get domain by id fails with 404."""
    response = requests.get(
        "{}/domain/{}".format(BASE_URL, BAD_ID),
        headers={"X-API-KEY": X_API_KEY},
        timeout=10,
    )

    assert response.status_code == 404
    data = response.json()
    assert data is not None, "Response is empty"
    assert response.status_code == 404


@pytest.mark.integration
def test_search_domain_by_ip():
    """Test search domain by IP."""
    selected_domain = random.choice(domains)
    domain_ip = selected_domain["ip"]

    url = "{}/domain/search".format(BASE_URL)
    json = {
        "page": 1,
        "filters": {
            "ip": domain_ip,
        },
        "pageSize": 10,
    }
    response = requests.post(
        url, json=json, headers={"X-API-KEY": X_API_KEY}, timeout=10
    )
    assert response.status_code == 200
    data = response.json()
    assert data is not None, "Response is empty"
    assert "result" in data, "Results not found in response"
    assert len(data["result"]) > 0, "No results found"

    # Validate result contain the correct IP
    for domain in data["result"]:
        assert domain["ip"] == domain_ip, "IP does not match"
