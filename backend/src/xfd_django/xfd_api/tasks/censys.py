"""Cesys scan."""
import os
import re
import time
import requests
import socket

from xfd_api.models import Domain, Scan
from xfd_api.helpers.save_domains_to_db import save_domains_to_db
from xfd_api.helpers.get_root_domains import get_root_domains

# Constants controlling pagination and rate limiting
RESULT_LIMIT = 1000
RESULTS_PER_PAGE = 100


def fetch_page(root_domain, next_token=None):
    """
    Fetch a single page of certificate search results from Censys.

    Uses basic auth from environment variables and POSTs JSON data.
    """
    url = "https://search.censys.io/api/v2/certificates/search"
    auth = (
        os.environ.get("CENSYS_API_ID"),
        os.environ.get("CENSYS_API_SECRET"),
    )
    headers = {"Content-Type": "application/json"}
    payload = {
        "q": root_domain,
        "per_page": RESULTS_PER_PAGE,
        "fields": ["names"],
    }
    if next_token:
        payload["cursor"] = next_token

    response = requests.post(url, json=payload, headers=headers, auth=auth)
    response.raise_for_status()  # raises an exception for HTTP errors
    return response.json()


def fetch_censys_data(root_domain):
    """
    Fetch certificate data for a given root domain, handling pagination.

    Logs the total number of certificates found and only retrieves up to RESULT_LIMIT.
    """
    print("Fetching certificates for {}".format(root_domain))
    data = fetch_page(root_domain)
    total = data.get("result", {}).get("total", 0)
    print("Censys found {} certificates for {}. Fetching {} of them...".format(
        total, root_domain, min(total, RESULT_LIMIT)
    ))
    result_count = 0
    # Assume the API returns a "links" object with a "next" key for pagination
    next_token = data.get("result", {}).get("links", {}).get("next")
    while next_token and result_count < RESULT_LIMIT:
        next_page = fetch_page(root_domain, next_token)
        hits = next_page.get("result", {}).get("hits", [])
        data["result"]["hits"].extend(hits)
        next_token = next_page.get("result", {}).get("links", {}).get("next")
        result_count += RESULTS_PER_PAGE
    return data


def handler(command_options):
    """
    Run the Censys scan.

      - Retrieves root domains for the given organization.
      - For each root domain, fetches certificate data from Censys.
      - Normalizes found subdomain names (removing leading "*." and "www.").
      - Deduplicates subdomains and performs a DNS lookup to fetch the IP address.
      - Converts the raw data into Domain model instances and saves them.
    """
    organization_id = command_options.get("organizationId")
    organization_name = command_options.get("organizationName")
    scan_id = command_options.get("scanId")

    print("Running Censys on: {}".format(organization_name))

    # Retrieve root domains
    root_domains = get_root_domains(organization_id)

    # Use a set to de-duplicate domain names.
    unique_names = set()
    found_domains = []  # List of dicts to later convert to Domain instances.

    for root_domain in root_domains:
        data = fetch_censys_data(root_domain)
        hits = data.get("result", {}).get("hits", [])
        for hit in hits:

            names = hit.get("names")
            if not names:
                continue
            for name in names:
                # Normalize the domain name: remove any "*." and a leading "www."
                normalized_name = re.sub(r"\*\.", "", name)
                normalized_name = re.sub(r"^www\.", "", normalized_name)
                if normalized_name.endswith(root_domain) and normalized_name not in unique_names:
                    unique_names.add(normalized_name)
                    found_domains.append({
                        "name": normalized_name,
                        "organization_id": organization_id,
                        "fromRootDomain": root_domain,
                        "subdomainSource": "censys",
                        "discoveredBy_id": scan_id,
                    })
        # Pause to respect rate limits
        time.sleep(1)

    print("Saving {} subdomains to database...".format(organization_name))

    domains_to_save = []
    for domain_data in found_domains:
        try:
            domain_name = domain_data["name"]
            ip = socket.gethostbyname(domain_name)
        except (socket.gaierror, UnicodeError) as e:
            ip = None
            
        domain_data["ip"] = ip
        domain_instance = Domain(**domain_data)
        domains_to_save.append(domain_instance)

    # Save or update the domains using a helper function that handles DB logic
    save_domains_to_db(domains_to_save)
    print("Censys saved or updated {} subdomains for {}".format(
        len(domains_to_save), organization_name
    ))
