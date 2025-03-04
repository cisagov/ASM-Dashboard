"""Script to retrieve top 10 CVE data from Cybersixgill."""
# Standard Python Libraries
import json
import time

# Third-Party Libraries
from django.utils import timezone
import requests
from xfd_api.helpers.cybersixgill_helpers import csg_token
from xfd_mini_dl.models import DataSource, TopCves


def handler(event):
    """Retrieve and save Cybersixgill top 10 CVEs."""
    try:
        main()
        return {
            "statusCode": 200,
            "body": "Cybersixgill top 10 CVEs script completed successfully.",
        }
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}
    
def main():
    """Retrieve and save Cybersixgill top 10 CVEs."""
    try:
        # Retrieve Cybersixgill data
        top_cve_data = csg_dve_enrich()
        csg_datasource, created = DataSource.objects.get_or_create(
            name="Cybersixgill",
            defaults={
                "description": "Provides advanced alerts and search capabilities to Dark Websites and forums contained there. There is also a social media alerting capability.",
                "last_run": timezone.now().date(),
            },
        )
        # Process data
        result_list = top_cve_data.get("objects")
        top_10_cves = []
        for result in result_list:
            cve_id = result.get("name")
            dynamic_rating = result.get("x_sixgill_info").get("rating").get("current")
            if result.get("x_sixgill_info").get("nvd").get("v3") is None:
                nvd_v3_score = None
            else:
                nvd_v3_score = result.get("x_sixgill_info").get("nvd").get("v3").get("current")
            nvd_base_score = "{'v2': None, 'v3': " + str(nvd_v3_score) + "}"
            summary = result.get("description").strip()
            cve = {
                "cve_id": cve_id,
                "dynamic_rating": dynamic_rating,
                "nvd_base_score": nvd_base_score,
                "date": timezone.now().date(),
                "summary": summary,
                "data_source_uid": csg_datasource.data_source_uid,
            }
            top_10_cves.append(cve)
        top_10_cves = sorted(top_10_cves, key=lambda d: d["dynamic_rating"], reverse=True)
        # Insert data into database
        csg_insert_topcves(top_10_cves)
    except Exception as e:
        print("Scan failed to complete: {error}".format(error=e))

def csg_dve_enrich():
    """Query Cybersixgill's /enrich API endpoint."""
    # Call API
    url = "https://api.cybersixgill.com/dve_enrich/enrich"
    auth = csg_token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    data = json.dumps(
        {
            "filters": {
                "sixgill_rating_range": {"from": 6, "to": 10},
            },
            "results_size": 10,
            "enriched": True,
            "from_index": 0,
        }
    )
    resp = requests.post(url, headers=headers, data=data)
    # Retry statement in case Cybersixgill's API falters
    retry_count, max_retries, time_delay = 0, 10, 5
    while resp.status_code != 200 and retry_count < max_retries:
        print(f"Retrying Cybersixgill /dve_enrich/enrich endpoint (code {resp.status_code}), attempt {retry_count+1} of {max_retries}")
        time.sleep(time_delay)
        resp = requests.post(url, headers=headers, data=data)
        retry_count += 1
    # Return result
    if retry_count == max_retries:
        raise Exception(
            "Error: Failed to retrieve Cybersixgill dve_enrich data."
        )
    else:
        return resp.json()

def csg_insert_topcves(top_cve_data):
    """Save Cybersixgill top 10 CVE data to the mini datalake using Django ORM."""
    try:
        # Upsert each record
        for record in top_cve_data:
            TopCves.objects.update_or_create(
                cve_id=record.get("cve_id"),
                date=record.get("date"),
                defaults={
                    "dynamic_rating": record.get("dynamic_rating"),
                    "nvd_base_score": record.get("nvd_base_score"),
                    "summary": record.get("summary"),
                    "data_source_uid": record.get("data_source_uid"),
                },
            )
    except:
        raise Exception(
            "Error: Failed to insert Cybersixgill top 10 CVE data into database."
        )



# testing
main()

