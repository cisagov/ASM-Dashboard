"""Integration test for vulnerabilities API."""
# Standard Python Libraries
import os
import random

# Third-Party Libraries
import pytest
import requests

# Configuration
BASE_URL = os.environ.get("BACKEND_DOMAIN")
X_API_KEY = os.environ.get("X_API_KEY")
BAD_ID = "c0effe93-3647-475a-a0c5-0b629c348590"


def get_vulnerabilities():
    """Get a tuple of vulnerability IDs for testing."""
    response = requests.post(
        "{}/vulnerabilities/search".format(BASE_URL),
        json={"page": 1, "pageSize": 10},
        headers={"X-API-KEY": X_API_KEY},
        timeout=10,
    )
    assert response.status_code == 200
    data = response.json()
    assert data is not None, "Response is empty"
    assert "result" in data, "Results not found in response"
    assert len(data["result"]) > 0, "No results found"

    return data["result"]


vulnerabilities = get_vulnerabilities()


# mark tests with integration tag, run with pytest -m integration
@pytest.mark.integration
def test_get_vulnerability_by_id():
    """Test get vulnerability by ID."""
    select_vulnerability = random.choice(vulnerabilities)
    vulnerability_id = select_vulnerability["id"]
    response = requests.get(
        "{}/vulnerabilities/{}".format(BASE_URL, vulnerability_id),
        headers={"X-API-KEY": X_API_KEY},
        timeout=10,
    )

    assert response.status_code == 200, "Expected status 200, got {}".format(
        response.status_code
    )
    data = response.json()
    assert data is not None, "Response is empty"
    assert data["id"] == vulnerability_id, "Expected ID {}, got {}".format(
        select_vulnerability, data["id"]
    )


@pytest.mark.integration
def test_get_vulnerability_by_id_fails_404():
    """Test get vulnerability by ID fails with 404."""
    response = requests.get(
        "{}/vulnerabilities/{}".format(BASE_URL, BAD_ID),
        headers={"X-API-KEY": X_API_KEY},
        timeout=10,
    )

    assert response.status_code == 404, "Expected status 404, got {}".format(
        response.status_code
    )
    data = response.json()
    assert data is not None, "Response is empty"

    # Check for the error message in the "detail" key
    assert "detail" in data, "Expected 'detail' in response"
    assert (
        data["detail"] == "Vulnerability not found."
    ), "Unexpected error message: {}".format(data["detail"])


@pytest.mark.integration
def test_search_vulnerabilities():
    """Test search vulnerabilities."""
    response = requests.post(
        "{}/vulnerabilities/search".format(BASE_URL),
        json={"page": 1, "filters": {"severity": "high"}, "pageSize": 10},
        headers={"X-API-KEY": X_API_KEY},
        timeout=10,
    )

    assert response.status_code == 200, "Expected status 200, got {}".format(
        response.status_code
    )
    data = response.json()
    assert data is not None, "Response is empty"
    assert "result" in data, "Results not found in response"
    assert len(data["result"]) > 0, "No results found"

    # Validate that results include vulnerabilities with high severity (case-insensitive)
    for vulnerability in data["result"]:
        assert (
            vulnerability["severity"].lower() == "high"
        ), "Expected severity 'high', got {}".format(vulnerability["severity"])


@pytest.mark.integration
def test_get_update_and_revert_vulnerability_by_id():
    """Test get vulnerability by ID, update fields, and revert back to original."""
    # Step 1: Retrieve the original data using GET
    select_vulnerability = random.choice(vulnerabilities)
    vulnerability_id = select_vulnerability["id"]
    url = "{}/vulnerabilities/{}".format(BASE_URL, vulnerability_id)
    response = requests.get(url, headers={"X-API-KEY": X_API_KEY}, timeout=10)
    assert response.status_code == 200, "Expected status 200, got {}".format(
        response.status_code
    )
    original_data = response.json()

    assert original_data is not None, "Response is empty"
    assert original_data["id"] == vulnerability_id, "Expected ID {}, got {}".format(
        vulnerability_id, original_data["id"]
    )

    # Extract domain_id and service_id from the nested objects

    if original_data["domain"] is not None:
        domain_id = original_data["domain"]["id"] if "domain" in original_data else None
        original_data.pop("domain", None)
        original_data["domain_id"] = domain_id
    else:
        original_data["domain_id"] = None
    if original_data["service"] is not None:
        service_id = (
            original_data["service"]["id"] if "service" in original_data else None
        )
        original_data.pop("service", None)
        original_data["service_id"] = service_id
    else:
        original_data["service_id"] = None

    # Step 2: Update a few fields using PUT
    updated_data = original_data.copy()  # Start with the original data
    updated_data["title"] = "Updated Title for Testing"  # Modify the title
    updated_data[
        "description"
    ] = "This is an updated description."  # Modify the description

    # Perform the update
    update_response = requests.put(
        url, json=updated_data, headers={"X-API-KEY": X_API_KEY}, timeout=10
    )
    assert update_response.status_code == 200, "Expected status 200, got {}".format(
        update_response.status_code
    )
    updated_response_data = update_response.json()

    # Validate the updated fields
    assert (
        updated_response_data["title"] == "Updated Title for Testing"
    ), "Title was not updated correctly"
    assert (
        updated_response_data["description"] == "This is an updated description."
    ), "Description was not updated correctly"

    # Step 3: Revert to the original data using PUT
    revert_response = requests.put(
        url, json=original_data, headers={"X-API-KEY": X_API_KEY}, timeout=10
    )
    assert revert_response.status_code == 200, "Expected status 200, got {}".format(
        revert_response.status_code
    )
    reverted_data = revert_response.json()

    # Validate that the original data was restored
    assert (
        reverted_data["title"] == original_data["title"]
    ), "Title was not reverted correctly"
    assert (
        reverted_data["description"] == original_data["description"]
    ), "Description was not reverted correctly"


@pytest.mark.integration
def test_update_vulnerability_by_id_fails_404():
    """Test update vulnerability by ID fails with 404."""
    response = requests.put(
        "{}/vulnerabilities/{}".format(BASE_URL, BAD_ID),  # Use a non-existent ID
        json={
            "id": BAD_ID,
            "createdAt": "2024-12-03T16:56:58.684835",
            "updatedAt": "2025-01-24T19:05:00.000Z",
            "lastSeen": None,
            "title": "Non-existent Vulnerability",
            "cve": "CVE-404-0001",
            "cwe": "CWE-404",
            "cpe": "cpe:/a:nonexistent:software:1.0",
            "description": "This vulnerability does not exist.",
            "references": [],
            "cvss": 5.0,
            "severity": "Medium",
            "needsPopulation": False,
            "state": "closed",
            "substate": "confirmed",
            "source": "testSource",
            "notes": "This is a test for a non-existent vulnerability.",
            "actions": [],
            "structuredData": {},
            "isKev": False,
            "domain_id": "0c4ee5b6-ff18-458c-adcc-dfe121fb54c5",
            "service_id": "9ac326f0-29ad-4e2c-a6bf-e330c91aa872",
        },
        headers={"X-API-KEY": X_API_KEY},
        timeout=10,
    )

    assert response.status_code == 404, "Expected status 404, got {}".format(
        response.status_code
    )
    data = response.json()
    assert "detail" in data, "Error detail missing in response"
    assert data["detail"] == "Vulnerability not found.", "Unexpected error message"


@pytest.mark.integration
def test_update_vulnerability_by_id_fails_422():
    """Test update vulnerability by ID fails with 422 due to invalid payload."""
    select_vulnerability = random.choice(vulnerabilities)
    vulnerability_id = select_vulnerability["id"]
    response = requests.put(
        "{}/vulnerabilities/{}".format(BASE_URL, vulnerability_id),
        json={
            "id": vulnerability_id,
            "createdAt": "invalid-date",
            "updatedAt": "2025-01-24T19:05:00.000Z",
            "lastSeen": None,
            "title": None,
            "cve": "CVE-INVALID-422",
            "cwe": "CWE-INVALID",
            "cpe": None,
            "description": 12345,
            "references": "invalid-references",
            "cvss": "invalid-cvss",
            "severity": "InvalidSeverity",
            "needsPopulation": "not-a-boolean",
            "state": 123,
            "substate": [],
            "source": False,
            "notes": 999,
            "actions": "invalid-actions",
            "structuredData": "not-a-dict",
            "isKev": "not-a-boolean",
            "domain_id": "invalid-domain-id",
            "service_id": "invalid-service-id",
        },
        headers={"X-API-KEY": X_API_KEY},
        timeout=10,
    )

    assert response.status_code == 422, "Expected status 422, got {}".format(
        response.status_code
    )
    data = response.json()

    # Validate that the response contains a list of validation errors
    assert isinstance(
        data["detail"], list
    ), "Expected 'detail' to be a list of validation errors"

    # Check that 'createdAt' error is included
    created_at_error = next(
        (error for error in data["detail"] if "createdAt" in error.get("loc", [])), None
    )
    assert created_at_error is not None, "'createdAt' validation error is missing"
    assert (
        "Input should be a valid datetime" in created_at_error["msg"]
    ), "Unexpected error message: {}".format(created_at_error["msg"])

    # Check that 'title' error is included (optional warning if missing)
    title_error = next(
        (error for error in data["detail"] if "title" in error.get("loc", [])), None
    )
    if title_error is None:
        print(
            "Warning: 'title' validation error is missing. Validation might not be implemented."
        )
    else:
        assert (
            title_error["msg"] == "Field required"
        ), "Unexpected error message: {}".format(title_error["msg"])
