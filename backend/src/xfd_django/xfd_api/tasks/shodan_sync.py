"""ShodanSync scan."""
# Standard Python Libraries
import datetime
import os
import time

# Third-Party Libraries
import django
from django.utils import timezone
import requests
from xfd_mini_dl.models import DataSource, Organization, ShodanAssets, ShodanVulns

# Django setup
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()

# Constants
MAX_RETRIES = 3  # Max retries for failed tasks
TIMEOUT = 60  # Timeout in seconds for waiting on task completion


def handler(event):
    """Retrieve and save shodan vulnerabilities and assets from the DMZ."""
    try:
        main()
        return {
            "statusCode": 200,
            "body": "DMZ Shodan Vulnerabilities and Asset sync completed successfully.",
        }
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}


def main():
    """Fetch and save DMZ Shodan vulnerabilities and assets."""
    try:
        all_orgs = Organization.objects.all()
        # all_orgs = Organization.objects.filter(acronym__in=['USAGM', 'DHS'])

        shodan_datasource, created = DataSource.objects.get_or_create(
            name="Shodan",
            defaults={
                "description": "Scans the internet for publicly accessible devices, concentrating on SCADA (supervisory control and data acquisition) systems.",
                "last_run": timezone.now().date(),  # Sets the current date and time
            },
        )

        # Step 1: Get the current date and time in UTC
        current_time = datetime.datetime.now(datetime.timezone.utc)
        # Step 2: Subtract days from the current date
        days_ago = current_time - datetime.timedelta(days=15)
        # Step 3: Convert to an ISO 8601 string with timezone (e.g., UTC)
        since_timestamp_str = days_ago.isoformat()

        for org in all_orgs:
            print(
                "Processing organization: {acronym}, {name}".format(
                    acronym=org.acronym, name=org.name
                )
            )
            done = False
            page = 1
            total_pages = 2
            per_page = 200
            retry_count = 0

            while not done:
                data = fetch_dmz_shodan_task(
                    org.acronym, page, per_page, since_timestamp_str
                )
                print(data)
                if not data or data.get("status") != "Processing":
                    print(
                        "Failed to start Shodan Sync task for org: {acronym}, {name}".format(
                            acronym=org.acronym, name=org.name
                        )
                    )

                    retry_count += 1

                    if retry_count >= MAX_RETRIES:
                        print(
                            "Max retries reached for org: {acronym}. Moving to next organization.".format(
                                acronym=org.acronym
                            )
                        )
                        break  # Skip to next organization

                    time.sleep(5)
                    continue

                response = fetch_dmz_shodan_data(data.get("task_id", None))

                while response and response.get("status") == "Pending":
                    time.sleep(1)
                    response = fetch_dmz_shodan_data(data.get("task_id", None))

                if response and response.get("status") == "Completed":
                    shodan_asset_array = (
                        response.get("result", {})
                        .get("data", {})
                        .get("shodan_assets", [])
                    )
                    shodan_vuln_array = (
                        response.get("result", {})
                        .get("data", {})
                        .get("shodan_vulns", [])
                    )
                    total_pages = response.get("result", {}).get("total_pages", 1)
                    current_page = response.get("result", {}).get("current_page", 1)
                    print("vulns")
                    print(shodan_vuln_array)
                    print("assets")
                    print(shodan_asset_array)
                    save_findings_to_db(
                        shodan_asset_array, shodan_vuln_array, org, shodan_datasource
                    )

                    if current_page >= total_pages:
                        done = True
                    page += 1
                else:
                    raise Exception(
                        "Task error: {error} - Status: {status}".format(
                            error=response.get("error"), status=response.get("status")
                        )
                    )
    except Exception as e:
        print("Scan failed to complete: {error}".format(error=e))


def fetch_dmz_shodan_task(org_acronym, page, per_page, since_timestamp):
    """Fetch shodan task id."""
    print(
        "Fetching shodan vulnerability and asset task for organization: {acronym}".format(
            acronym=org_acronym
        )
    )
    headers = {
        "X-API-KEY": os.getenv("CF_API_KEY"),
        "access_token": os.getenv("PE_API_KEY"),
        "Content-Type": "",
    }

    data = {
        "org_acronym": org_acronym,
        "page": page,
        "per_page": per_page,
        "since_timestamp": since_timestamp,
    }

    try:
        response = requests.post(
            "https://api.staging-cd.crossfeed.cyber.dhs.gov/pe/apiv1/get_mdl_shodan_data",
            headers=headers,
            json=data,
            timeout=20,  # Timeout in seconds
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print("Error fetching DMZ task: {error}".format(error=e))
        return None


def fetch_dmz_shodan_data(task_id):
    """Fetch DMZ Shodan vulnerability and asset data for a task."""
    url = "https://api.staging-cd.crossfeed.cyber.dhs.gov/pe/apiv1/get_mdl_shodan_data/task/{t_id}".format(
        t_id=task_id
    )
    headers = {
        "X-API-KEY": os.getenv("CF_API_KEY"),
        "access_token": os.getenv("PE_API_KEY"),
        "Content-Type": "",
    }

    try:
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print("Error fetching DMZ Shodan data: {error}".format(error=e))
        return None


def save_findings_to_db(shodan_asset_array, shodan_vuln_array, org, data_source):
    """Save Shodan assets and vulns data to the mini datalake using Django ORM."""
    if shodan_asset_array:
        for asset in shodan_asset_array:
            try:
                ShodanAssets.objects.update_or_create(
                    timestamp=asset.get("timestamp"),
                    ip=asset.get("ip"),
                    port=asset.get("port"),
                    protocol=asset.get("protocol"),
                    organization=org,
                    defaults={
                        "organization_name": asset.get("organization_name"),
                        "product": asset.get("product"),
                        "server": asset.get("server"),
                        "tags": asset.get("tags"),
                        "domains": asset.get("domains"),
                        "hostnames": asset.get("hostnames"),
                        "isp": asset.get("isp"),
                        "asn": asset.get("asn"),
                        "country_code": asset.get("country_code"),
                        "location": asset.get("location"),
                        "data_source": data_source,
                    },
                )
            except Exception as e:
                print("Error saving Shodan Asset: {error}".format(error=e))

    if shodan_vuln_array:
        for asset in shodan_vuln_array:
            try:
                ShodanVulns.objects.update_or_create(
                    timestamp=asset.get("timestamp"),
                    ip=asset.get("ip"),
                    port=asset.get("port"),
                    protocol=asset.get("protocol"),
                    organization=org,
                    defaults={
                        "organization_name": asset.get("organization_name"),
                        "cve": asset.get("cve"),
                        "severity": asset.get("severity"),
                        "cvss": asset.get("cvss"),
                        "summary": asset.get("summary"),
                        "product": asset.get("product"),
                        "attack_vector": asset.get("attack_vector"),
                        "av_description": asset.get("av_description"),
                        "attack_complexity": asset.get("attack_complexity"),
                        "ac_description": asset.get("ac_description"),
                        "confidentiality_impact": asset.get("confidentiality_impact"),
                        "ci_description": asset.get("ci_description"),
                        "integrity_impact": asset.get("integrity_impact"),
                        "ii_description": asset.get("ii_description"),
                        "availability_impact": asset.get("availability_impact"),
                        "ai_description": asset.get("ai_description"),
                        "tags": asset.get("tags"),
                        "domains": asset.get("domains"),
                        "hostnames": asset.get("hostnames"),
                        "isp": asset.get("isp"),
                        "asn": asset.get("asn"),
                        "type": asset.get("type"),
                        "name": asset.get("name"),
                        "potential_vulns": asset.get("potential_vulns"),
                        "mitigation": asset.get("mitigation"),
                        "server": asset.get("server"),
                        "is_verified": asset.get("is_verified"),
                        "banner": asset.get("banner"),
                        "version": asset.get("version"),
                        "cpe": asset.get("cpe"),
                        "data_source": data_source,
                    },
                )
            except Exception as e:
                print("Error saving Shodan Vuln: {error}".format(error=e))
