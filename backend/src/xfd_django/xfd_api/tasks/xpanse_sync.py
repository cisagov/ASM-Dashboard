"""XpanseSync scan."""
# Standard Python Libraries
import datetime
import os
import random
import time

# Third-Party Libraries
import django
from django.core.exceptions import ObjectDoesNotExist
import requests
from xfd_mini_dl.models import (
    Organization,
    XpanseAlerts,
    XpanseBusinessUnits,
    XpanseCveServiceMdl,
    XpanseCvesMdl,
    XpanseServicesMdl,
)

# Django setup
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()

# Constants
MAX_RETRIES = 3  # Max retries for failed tasks


def handler(event):
    """Retrieve and save Xpanse alerts from the DMZ."""
    try:
        main()
        return {
            "statusCode": 200,
            "body": "DMZ Xpanse Assets sync completed successfully.",
        }
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}


def main():
    """Fetch and save DMZ Xpanse alerts."""
    # Step 1: Get the current date and time in UTC
    current_time = datetime.datetime.now(datetime.timezone.utc)
    # Step 2: Subtract days from the current date
    days_ago = current_time - datetime.timedelta(days=15)
    # Step 3: Convert to an ISO 8601 string with timezone (e.g., UTC)
    modified_timestamp_str = days_ago.isoformat()
    if is_bu_pull_day():
        business_units = pull_and_save_business_units()
    else:
        business_units = list(XpanseBusinessUnits.objects.all())

    random.shuffle(business_units)

    for business_unit in business_units:
        done = False
        page = 1
        total_pages = 2
        per_page = 100
        retry_count = 0

        while not done:
            data = fetch_dmz_xpanse_alert_task(
                business_unit.cyhy_db_name.acronym,
                page,
                per_page,
                modified_timestamp_str,
            )
            if not data or data.get("status") != "Processing":
                retry_count += 1

                if retry_count >= MAX_RETRIES:
                    print(
                        "Max retries reached for org: {acronym}. Moving to next organization.".format(
                            acronym=business_unit.cyhy_db_name.acronym
                        )
                    )
                    break  # Skip to next organization

                time.sleep(5)
                continue
            response = fetch_dmz_xpanse_data(data.get("task_id"))

            while response and response.get("status") == "Pending":
                time.sleep(1)
                response = fetch_dmz_xpanse_data(data.get("task_id", None))
            if response and response.get("status") == "Completed":
                xpanse_alerts = response.get("result", {}).get("data", {})
                total_pages = response.get("result", {}).get("total_pages", 1)
                current_page = response.get("result", {}).get("current_page", 1)
                save_alerts_to_db(xpanse_alerts)
                print(len(xpanse_alerts))
                if current_page >= total_pages:
                    done = True
                page += 1
            else:
                raise Exception(
                    "Task error: {error} - Status: {status}".format(
                        error=response.get("error"), status=response.get("status")
                    )
                )


def is_bu_pull_day():
    """Check if today is a day to repull all business units."""
    today = datetime.datetime.today()
    day_of_month = today.day
    return day_of_month in (17, 2)


def pull_and_save_business_units():
    """Pull xpanse business units and save to db."""
    print("Fetching Xpanse Business Units")
    headers = {
        "X-API-KEY": os.getenv("CF_API_KEY"),
        "access_token": os.getenv("PE_API_KEY"),
        "Content-Type": "",
    }

    try:
        response = requests.get(
            "https://api.staging-cd.crossfeed.cyber.dhs.gov/pe/apiv1/linked_mdl_xpanse_business_units",
            headers=headers,
            timeout=20,  # Timeout in seconds
        )
        response.raise_for_status()

    except requests.exceptions.RequestException as e:
        print("Error fetching DMZ Business Unit pull: {error}".format(error=e))
        return None
    try:
        bu_list = []
        business_unit_list = response.json()

        for business_unit in business_unit_list:
            if business_unit.get("cyhy_db_name_id"):
                try:
                    organization = Organization.objects.get(
                        acronym=business_unit.get("cyhy_db_name_id")
                    )
                except ObjectDoesNotExist:
                    organization = None

                mdl_defaults = {
                    "state": business_unit.get("state"),
                    "county": business_unit.get("county"),
                    "city": business_unit.get("city"),
                    "sector": business_unit.get("sector"),
                    "entity_type": business_unit.get("entity_type"),
                    "region": business_unit.get("region"),
                    "rating": business_unit.get("rating"),
                    "cyhy_db_name": organization,
                }

                (
                    mdl_business_unit_object,
                    mdl_created,
                ) = XpanseBusinessUnits.objects.update_or_create(
                    entity_name=business_unit.get("entity_name"), defaults=mdl_defaults
                )
                bu_list.append(mdl_business_unit_object)
                break
        return bu_list
    except Exception as e:
        print("Error fetching DMZ Business Unit pull: {error}".format(error=e))
        return None


def fetch_dmz_xpanse_alert_task(org_acronym, page, per_page, modified_datetime):
    """Fetch xpanse alert task id."""
    print(
        "Fetching xpanse alert task for organization: {acronym}".format(
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
        "modified_datetime": modified_datetime,
    }

    try:
        response = requests.post(
            "https://api.staging-cd.crossfeed.cyber.dhs.gov/pe/apiv1/get_mdl_xpanse_alert",
            headers=headers,
            json=data,
            timeout=20,  # Timeout in seconds
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print("Error fetching DMZ task: {error}".format(error=e))
        return None


def fetch_dmz_xpanse_data(task_id):
    """Fetch DMZ xpanse alert data for a task."""
    url = "https://api.staging-cd.crossfeed.cyber.dhs.gov/pe/apiv1/mdl_xpanse_alerts_task_status/task/{task_id}".format(
        task_id=task_id
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
        print("Error fetching DMZ Xpanse data: {error}".format(error=e))
        return None


def save_alerts_to_db(alert_list):
    """Save a list of Xpanse alerts to the MDL."""
    for alert in alert_list:
        try:
            defaults = {
                "xpanse_alert_uid": alert.get("xpanse_alert_uid", None),
                "time_pulled_from_xpanse": alert.get("time_pulled_from_xpanse", None),
                "detection_timestamp": alert.get("detection_timestamp", None),
                "alert_name": alert.get("alert_name", None),
                "description": alert.get("description", None),
                "host_name": alert.get("host_name", None),
                "alert_action": alert.get("alert_action", None),
                "action_pretty": alert.get("action_pretty", None),
                "action_country": alert.get("action_country", None),
                "action_remote_port": alert.get("action_remote_port", None),
                "starred": alert.get("starred", None),
                "external_id": alert.get("external_id", None),
                "related_external_id": alert.get("related_external_id", None),
                "alert_occurrence": alert.get("alert_occurrence", None),
                "severity": alert.get("severity", None),
                "matching_status": alert.get("matching_status", None),
                "local_insert_ts": alert.get("local_insert_ts", None),
                "last_modified_ts": alert.get("last_modified_ts", None),
                "case_id": alert.get("case_id", None),
                "event_timestamp": alert.get("event_timestamp", None),
                "alert_type": alert.get("alert_type", None),
                "resolution_status": alert.get("resolution_status", None),
                "resolution_comment": alert.get("resolution_comment", None),
                "tags": alert.get("tags", None),
                "last_observed": alert.get("last_observed", None),
                "country_codes": alert.get("country_codes", None),
                "cloud_providers": alert.get("cloud_providers", None),
                "ipv4_addresses": alert.get("ipv4_addresses", None),
                "domain_names": alert.get("domain_names", None),
                "service_ids": alert.get("service_ids", None),
                "website_ids": alert.get("website_ids", None),
                "asset_ids": alert.get("asset_ids", None),
                "certificate": alert.get("certificate", None),
                "port_protocol": alert.get("port_protocol", None),
                "attack_surface_rule_name": alert.get("attack_surface_rule_name", None),
                "remediation_guidance": alert.get("remediation_guidance", None),
                "asset_identifiers": alert.get("asset_identifiers", None),
            }

            alert_object, created = XpanseAlerts.objects.update_or_create(
                alert_id=alert.get("alert_id"),
                defaults=defaults,
            )

            business_unit_list = []
            tags = (alert.get("tags", None),)
            for tag in tags[0]:
                if tag.startswith("BU:"):
                    business_unit_list.append(tag[3:].strip())

            business_unit_objects = []
            for b_u in business_unit_list:
                try:
                    business_unit_objects.append(
                        XpanseBusinessUnits.objects.get(entity_name=b_u)
                    )
                except Exception as e:
                    print(
                        "Failed to get business unit {business}: {error}".format(
                            business=b_u, error=e
                        )
                    )
                    continue

            alert_object.business_units.set(business_unit_objects)

            service_objects = []
            for service in alert.get("services", []):
                service_defaults = {
                    "xpanse_service_uid": service.get("xpanse_service_uid"),
                    "service_name": service.get("service_name"),
                    "service_type": service.get("service_type"),
                    "ip_address": service.get("ip_address"),
                    "domain": service.get("domain"),
                    "externally_detected_providers": service.get(
                        "externally_detected_providers"
                    ),
                    "is_active": service.get("is_active"),
                    "first_observed": service.get("first_observed"),
                    "last_observed": service.get("last_observed"),
                    "port": service.get("port"),
                    "protocol": service.get("protocol"),
                    "active_classifications": service.get("active_classifications"),
                    "inactive_classifications": service.get("inactive_classifications"),
                    "discovery_type": service.get("discovery_type"),
                    "externally_inferred_vulnerability_score": service.get(
                        "externally_inferred_vulnerability_score"
                    ),
                    "externally_inferred_cves": service.get("externally_inferred_cves"),
                    "service_key": service.get("service_key"),
                    "service_key_type": service.get("service_key_type"),
                }

                service_object, created = XpanseServicesMdl.objects.update_or_create(
                    service_id=service.get("service_id"),
                    defaults=service_defaults,
                )

                for cve in service.get("cves", []):
                    cve_defaults = {
                        "xpanse_cve_uid": cve.get("xpanse_cve_uid"),
                        "cvss_score_v2": cve.get("cvss_score_v2"),
                        "cve_severity_v2": cve.get("cve_severity_v2"),
                        "cvss_score_v3": cve.get("cvss_score_v3"),
                        "cve_severity_v3": cve.get("cve_severity_v3"),
                    }
                    cve_object, created = XpanseCvesMdl.objects.get_or_create(
                        cve_id=cve.get("cve_id"),
                        defaults=cve_defaults,
                    )

                    cve_service_default = {
                        "inferred_cve_match_type": cve.get("inferred_cve_match_type"),
                        "product": cve.get("product"),
                        "confidence": cve.get("confidence"),
                        "vendor": cve.get("vendor"),
                        "version_number": cve.get("version_number"),
                        "activity_status": cve.get("activity_status"),
                        "first_observed": cve.get("first_observed"),
                        "last_observed": cve.get("last_observed"),
                    }

                    (
                        cve_match_object,
                        created,
                    ) = XpanseCveServiceMdl.objects.update_or_create(
                        xpanse_inferred_cve=cve_object,
                        xpanse_service=service_object,
                        defaults=cve_service_default,
                    )

                service_objects.append(service_object)
            alert_object.services.set(service_objects)
            alert_object.save()

        except Exception as e:
            print("Failed to save alert: %s, moving on to the next alert." % (e))
            continue
