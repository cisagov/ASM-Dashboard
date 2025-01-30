"""Integration test for vulnerabilities API."""
# Standard Python Libraries
import os

# Third-Party Libraries
import requests

BASE_URL = os.environ.get("BACKEND_DOMAIN")
X_API_KEY = os.environ.get("X_API_KEY")


def get_vulnerability_ids():
    """Get a tuple of vulnerability IDs for testing."""
    url = "{}/vulnerabilities/search".format(BASE_URL)
    json = {
        "page": 1,
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

    # Extract domain IDs
    vulnerability_ids = [vulnerability["id"] for vulnerability in data["result"]]
    return tuple(vulnerability_ids)
