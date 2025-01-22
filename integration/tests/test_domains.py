"""Integration test for domain API."""
# Standard Python Libraries
import os

# Third-Party Libraries
import pytest
import requests

BASE_URL = os.environ.get("BACKEND_DOMAIN")
X_API_KEY = os.environ.get("X_API_KEY")
DOMAIN_ID = os.environ.get("DOMAIN_UID")

BAD_ID = "01234567-0123-4567-8901-12345"


# mark tests with integration tag, run with pytest -m integration
@pytest.mark.integration
def test_get_domain_by_id():
    """Test get domain by id."""
    url = "{}/domain/{}".format(BASE_URL, DOMAIN_ID)
    print(url)
    response = requests.get(url, headers={"X-API-KEY": X_API_KEY}, timeout=10)

    assert response.status_code == 200
    data = response.json()
    assert data is not None, "Response is empty"
    assert data["id"] == DOMAIN_ID


@pytest.mark.integration
def test_get_domain_by_id_fails_404():
    """Test get domain by id fails with 404."""
    url = "{}/domain/{}".format(BASE_URL, BAD_ID)
    # Get domain by Id.
    response = requests.get(url, headers={"X-API-KEY": X_API_KEY}, timeout=10)

    assert response.status_code == 404
    data = response.json()
    assert data is not None, "Response is empty"
    assert response.status_code == 404


@pytest.mark.integration
def test_search_domain_by_ip():
    """Test search domain by IP."""
    url = "{}/domain/search".format(BASE_URL)
    json = {
        "page": 1,
        "filters": {
            "ip": os.environ.get("SEARCH_IP"),
            "pageSize": 10,
        },
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
        assert domain["ip"] == os.environ.get("SEARCH_IP"), "IP does not match"
