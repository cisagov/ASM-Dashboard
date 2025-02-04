"""ShodanSync scan."""
# Standard Python Libraries
from datetime import datetime, timedelta
import os
import time

# Third-Party Libraries
import django
from django.utils import timezone
import pytz
import requests
from xfd_mini_dl.models import (
    CredentialBreaches,
    CredentialExposures,
    DataSource,
    Organization,
)

# Django setup
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()

# Constants
MAX_RETRIES = 3  # Max retries for failed tasks
TIMEOUT = 60  # Timeout in seconds for waiting on task completion


def handler(event):
    """Retrieve and save credential breaches and exposures from the DMZ."""
    try:
        main()
        return {
            "statusCode": 200,
            "body": "DMZ credential breaches and exposures sync completed successfully.",
        }
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}


def main():
    """Fetch and save DMZ credential breaches and exposures."""
    all_orgs = Organization.objects.all()
    # all_orgs = Organization.objects.filter(acronym__in=['USAGM', 'DHS'])
    #    change this
    # shodan_datasource, created = DataSource.objects.get_or_create(
    #     name="Shodan",
    #     defaults={
    #         "description": "Scans the internet for publicly accessible devices, concentrating on SCADA (supervisory control and data acquisition) systems.",  # You can customize this text
    #         "last_run": timezone.now()  # Sets the current date and time
    #     }
    # )

    # Step 1: Get the current date and time in UTC
    current_time = datetime.now(pytz.UTC)
    # Step 2: Subtract days from the current date
    days_ago = current_time - timedelta(days=15)
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
            data = fetch_dmz_cred_task(org.acronym, page, per_page, since_timestamp_str)
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

            response = fetch_dmz_cred_data(data.get("task_id", None))

            while response and response.get("status") == "Pending":
                time.sleep(1)
                response = fetch_dmz_cred_data(data.get("task_id", None))

            if response and response.get("status") == "Completed":
                cred_exposures_array = (
                    response.get("result", {})
                    .get("data", {})
                    .get("credential_exposures", [])
                )
                cred_breaches_array = (
                    response.get("result", {})
                    .get("data", {})
                    .get("credential_breaches", [])
                )
                total_pages = response.get("result", {}).get("total_pages", 1)
                current_page = response.get("result", {}).get("current_page", 1)
                print("breaches")
                print(cred_breaches_array)
                print("exposures")
                print(cred_exposures_array)
                save_findings_to_db(cred_exposures_array, cred_breaches_array, org)

                if current_page >= total_pages:
                    done = True
                page += 1
            else:
                raise Exception(
                    "Task error: {error} - Status: {status}".format(
                        error=response.get("error"), status=response.get("status")
                    )
                )


def fetch_dmz_cred_task(org_acronym, page, per_page, since_timestamp):
    """Fetch cred task id."""
    print(
        "Fetching credential breach and exposure task for organization: {acronym}".format(
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
            "https://api.staging-cd.crossfeed.cyber.dhs.gov/pe/apiv1/get_mdl_cred_data",
            headers=headers,
            json=data,
            timeout=20,  # Timeout in seconds
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print("Error fetching DMZ task: {error}".format(error=e))
        return None


def fetch_dmz_cred_data(task_id):
    """Fetch DMZ Credential breach and exposure data for a task."""
    url = "https://api.staging-cd.crossfeed.cyber.dhs.gov/pe/apiv1/get_mdl_cred_data/task/{t_id}".format(
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


def save_findings_to_db(cred_exposures_array, cred_breaches_array, org):
    """Save credential exposure and breach data to the mini datalake using Django ORM."""
    if cred_breaches_array:
        breach_dict = {}
        data_source_dict = {}
        for breach in cred_breaches_array:
            try:
                if data_source_dict.get(
                    breach.get("data_source_name", "unknown"), None
                ):
                    continue
                else:
                    (
                        data_source_dict[breach.get("data_source_name", "unknown")],
                        created,
                    ) = DataSource.objects.get_or_create(
                        name=breach.get("data_source_name", "unknown"),
                        defaults={
                            "description": "Credentials and Breaches identified by {source}".format(
                                source=breach.get("data_source_name", "unknown")
                            ),
                            "last_run": timezone.now().date(),
                        },
                    )
                if breach_dict.get(breach.get("breach_name"), None):
                    continue
                else:
                    (
                        breach_dict[breach.get("breach_name")],
                        created,
                    ) = CredentialBreaches.objects.get_or_create(
                        breach_name=breach.get("breach_name"),
                        defaults={
                            "credential_breaches_uid": breach.get(
                                "credential_breaches_uid"
                            ),
                            "description": breach.get("description"),
                            "exposed_cred_count": breach.get("exposed_cred_count"),
                            "breach_date": datetime.fromisoformat(
                                breach.get("breach_date")
                            ).date(),
                            "added_date": breach.get("added_date"),
                            "modified_date": breach.get("modified_date"),
                            "data_classes": breach.get("data_classes"),
                            "password_included": breach.get("password_included"),
                            "is_verified": breach.get("is_verified"),
                            "is_fabricated": breach.get("is_fabricated"),
                            "is_sensitive": breach.get("is_sensitive"),
                            "is_retired": breach.get("is_retired"),
                            "is_spam_list": breach.get("is_spam_list"),
                            "data_source": data_source_dict[
                                breach.get("data_source_name", "unknown")
                            ],
                        },
                    )
            except Exception as e:
                print("Error saving Cred Breaches: {error}".format(error=e))

    if cred_exposures_array:
        for exposure in cred_exposures_array:
            try:
                CredentialExposures.objects.update_or_create(
                    breach_name=exposure.get("breach_name"),
                    email=exposure.get("email"),
                    defaults={
                        "credential_exposures_uid": exposure.get(
                            "credential_exposures_uid"
                        ),
                        "root_domain": exposure.get("root_domain"),
                        "sub_domain": exposure.get("sub_domain"),
                        "modified_date": exposure.get("modified_date"),
                        "name": exposure.get("name"),
                        "login_id": exposure.get("login_id"),
                        "phone": exposure.get("phone"),
                        "password": exposure.get("password"),
                        "hash_type": exposure.get("hash_type"),
                        "intelx_system_id": exposure.get("intelx_system_id"),
                        "organization": org,
                        "credential_breaches": breach_dict[exposure.get("breach_name")],
                        "data_source": data_source_dict[
                            breach.get("data_source_name", "unknown")
                        ],
                    },
                )
            except Exception as e:
                print("Error saving Credential Exposure: {error}".format(error=e))
