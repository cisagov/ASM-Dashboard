"""Helper methods that are used for Cybersixgill data scripts."""
# Standard Python Libraries
import os
import time

# Third-Party Libraries
import requests


def csg_token():
    """Get authentication token for Cybersixgill API."""
    # Call API
    url = "https://api.cybersixgill.com/auth/token/"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cache-Control": "no-cache",
    }
    data = {
        "grant_type": "client_credentials",
        "client_id": os.environ.get("SIXGILL_CLIENT_ID"),
        "client_secret": os.environ.get("SIXGILL_CLIENT_SECRET"),
    }
    resp = requests.post(url, headers=headers, data=data)
    # Retry statement in case API falters
    retry_count, max_retries, time_delay = 0, 10, 5
    while resp.status_code != 200 and retry_count < max_retries:
        print(f"Retrying Cybersixgill /auth/token endpoint (code {resp.status_code}), attempt {retry_count+1} of {max_retries}")
        time.sleep(time_delay)
        resp = requests.post(url, headers=headers, data=data)
        retry_count += 1
    # Return result
    if retry_count == max_retries:
        raise Exception(
            "Error: Failed to retrieve Cybersixgill authentication token."
        )
    else:
        return resp.json()["access_token"]