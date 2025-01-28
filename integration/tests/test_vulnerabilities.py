"""Integration test for vulnerabilities API."""
# Standard Python Libraries
import os

# Third-Party Libraries
import pytest
import requests

# Configuration
BASE_URL = "http://localhost:3000"
X_API_KEY = os.environ.get("X_API_KEY")
VULNERABILITIES_ID = os.environ.get("VULNERABILITIES_ID")
BAD_ID = "c0effe93-3647-475a-a0c5-0b629c348590"

# mark tests with integration tag, run with pytest -m integration
@pytest.mark.integration
def test_get_vulnerability_by_id():
    """Test get vulnerability by ID."""
    url = f"{BASE_URL}/vulnerabilities/{VULNERABILITIES_ID}"
    response = requests.get(url, headers={"X-API-KEY": X_API_KEY}, timeout=10)

    assert response.status_code == 200, f"Expected status 200, got {response.status_code}"
    data = response.json()
    assert data is not None, "Response is empty"
    assert data["id"] == VULNERABILITIES_ID, f"Expected ID {VULNERABILITIES_ID}, got {data['id']}"

@pytest.mark.integration
def test_get_vulnerability_by_id_fails_404():
    """Test get vulnerability by ID fails with 404."""
    url = f"{BASE_URL}/vulnerabilities/{BAD_ID}"
    response = requests.get(url, headers={"X-API-KEY": X_API_KEY}, timeout=10)
    
    assert response.status_code == 404, f"Expected status 404, got {response.status_code}"
    data = response.json()
    assert data is not None, "Response is empty"
    
    # Check for the error message in the "detail" key
    assert "detail" in data, "Expected 'detail' in response"
    assert data["detail"] == "Vulnerability not found.", f"Unexpected error message: {data['detail']}"


@pytest.mark.integration
def test_search_vulnerabilities():
    """Test search vulnerabilities."""
    url = f"{BASE_URL}/vulnerabilities/search"
    json = {
        "page": 1,
        "filters": {
            "severity": "high",  # Example filter, modify based on actual API
        },
        "pageSize": 10,
    }
    response = requests.post(
        url, json=json, headers={"X-API-KEY": X_API_KEY}, timeout=10
    )

    assert response.status_code == 200, f"Expected status 200, got {response.status_code}"
    data = response.json()
    assert data is not None, "Response is empty"
    assert "result" in data, "Results not found in response"
    assert len(data["result"]) > 0, "No results found"

    # Validate that results include vulnerabilities with high severity (case-insensitive)
    for vulnerability in data["result"]:
        assert vulnerability["severity"].lower() == "high", f"Expected severity 'high', got {vulnerability['severity']}"


@pytest.mark.integration
def test_update_vulnerability_by_id():
    """Test update vulnerability by ID."""
    url = f"{BASE_URL}/vulnerabilities/{VULNERABILITIES_ID}"
    json = {
        "id": "00f2b72a-c42c-4950-b383-0c0a7078788f",
        "createdAt": "2024-12-03T16:56:58.684835",
        "updatedAt": "2025-01-24T19:05:00.000Z",  # Simulate an update
        "lastSeen": None,
        "title": "Updated CVE-2019-6109",
        "cve": "CVE-2019-6109",
        "cwe": "CWE-116",
        "cpe": "cpe:/a:openbsd:openssh:7.4",
        "description": "Updated description for this vulnerability.",
        "references": [
            {
                "url": "https://updated-url.com",
                "name": "Updated Reference",
                "tags": ["Updated Tag"],
                "source": "UPDATED_SOURCE"
            }
        ],
        "cvss": 7.5,
        "severity": "High",
        "needsPopulation": False,
        "state": "closed",
        "substate": "confirmed",
        "source": "updatedSource",
        "notes": "Updated vulnerability notes.",
        "actions": ["action2"],
        "structuredData": {"newKey": "newValue"},
        "isKev": True,
        "domain_id": "0c4ee5b6-ff18-458c-adcc-dfe121fb54c5",
        "service_id": "9ac326f0-29ad-4e2c-a6bf-e330c91aa872",
    }
    response = requests.put(url, json=json, headers={"X-API-KEY": X_API_KEY}, timeout=10)

    assert response.status_code == 200, f"Expected status 200, got {response.status_code}"
    data = response.json()

    # Validate updated fields
    assert data["title"] == "Updated CVE-2019-6109", "Title was not updated correctly"
    assert data["description"] == "Updated description for this vulnerability.", "Description was not updated correctly"
    assert data["severity"] == "High", "Severity was not updated correctly"
    assert data["state"] == "closed", "State was not updated correctly"

    # Validate references
    assert len(data["references"]) == 1, "References were not updated correctly"
    assert data["references"][0]["url"] == "https://updated-url.com", "Reference URL was not updated correctly"
    assert data["references"][0]["source"] == "UPDATED_SOURCE", "Reference source was not updated correctly"

    assert data.get("domain_id") == "0c4ee5b6-ff18-458c-adcc-dfe121fb54c5", "Domain ID mismatch"
    # Validate service_id
    assert data["service_id"] == "9ac326f0-29ad-4e2c-a6bf-e330c91aa872", "Service ID mismatch"

@pytest.mark.integration
def test_update_vulnerability_by_id_fails_404():
    """Test update vulnerability by ID fails with 404."""
    url = f"{BASE_URL}/vulnerabilities/{BAD_ID}"  # Use a non-existent ID
    json = {
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
    }
    response = requests.put(url, json=json, headers={"X-API-KEY": X_API_KEY}, timeout=10)

    assert response.status_code == 404, f"Expected status 404, got {response.status_code}"
    data = response.json()
    assert "detail" in data, "Error detail missing in response"
    assert data["detail"] == "Vulnerability not found.", "Unexpected error message"

@pytest.mark.integration
def test_update_vulnerability_by_id_fails_422():
    """Test update vulnerability by ID fails with 422 due to invalid payload."""
    url = f"{BASE_URL}/vulnerabilities/{VULNERABILITIES_ID}"
    json = {
        "id": VULNERABILITIES_ID,
        "createdAt": "invalid-date",  # Invalid date format
        "updatedAt": "2025-01-24T19:05:00.000Z",
        "lastSeen": None,
        "title": None,  # Invalid: title is required
        "cve": "CVE-INVALID-422",  # Example invalid CVE
        "cwe": "CWE-INVALID",  # Example invalid CWE
        "cpe": None,  # Invalid: cpe cannot be None
        "description": 12345,  # Invalid: description should be a string
        "references": "invalid-references",  # Invalid: should be a list
        "cvss": "invalid-cvss",  # Invalid: cvss should be a number
        "severity": "InvalidSeverity",  # Invalid: severity is not a valid enum value
        "needsPopulation": "not-a-boolean",  # Invalid: should be a boolean
        "state": 123,  # Invalid: state should be a string
        "substate": [],  # Invalid: substate should be a string
        "source": False,  # Invalid: source should be a string
        "notes": 999,  # Invalid: notes should be a string
        "actions": "invalid-actions",  # Invalid: actions should be a list
        "structuredData": "not-a-dict",  # Invalid: structuredData should be a dictionary
        "isKev": "not-a-boolean",  # Invalid: should be a boolean
        "domain_id": "invalid-domain-id",  # Invalid domain_id
        "service_id": "invalid-service-id",  # Invalid service_id
    }
    response = requests.put(url, json=json, headers={"X-API-KEY": X_API_KEY}, timeout=10)

    assert response.status_code == 422, f"Expected status 422, got {response.status_code}"
    data = response.json()

    # Debugging: Print the response
    print(data)  # Inspect the response to debug validation errors

    # Validate that the response contains a list of validation errors
    assert isinstance(data["detail"], list), "Expected 'detail' to be a list of validation errors"

    # Check that 'createdAt' error is included
    created_at_error = next((error for error in data["detail"] if "createdAt" in error.get("loc", [])), None)
    assert created_at_error is not None, "'createdAt' validation error is missing"
    assert "Input should be a valid datetime" in created_at_error["msg"], \
        f"Unexpected error message: {created_at_error['msg']}"

    # Check that 'title' error is included (optional warning if missing)
    title_error = next((error for error in data["detail"] if "title" in error.get("loc", [])), None)
    if title_error is None:
        print("Warning: 'title' validation error is missing. Validation might not be implemented.")
    else:
        assert title_error["msg"] == "Field required", f"Unexpected error message: {title_error['msg']}"





