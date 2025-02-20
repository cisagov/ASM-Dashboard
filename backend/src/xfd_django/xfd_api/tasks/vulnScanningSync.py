"""Task for synchronizing vulnerability scanning data.

This module handles fetching, processing, and saving vulnerability scans,
port scans, hosts, and tickets from Redshift into the Django models.
"""

# Standard Python Libraries
# Uncomment the above to run the script standalone
import datetime
from ipaddress import IPv4Network, IPv6Network
import json
import os
from typing import List

# Third-Party Libraries
import psycopg2
import requests
from xfd_api.utils.chunk import chunk_list_by_bytes
from xfd_api.utils.csv_utils import convert_to_csv, create_checksum
from xfd_api.utils.hash import hash_ip
from xfd_api.utils.scan_utils.vuln_scanning_sync_utils import (
    fetch_orgs_and_relations,
    save_cve_to_datalake,
    save_host,
    save_ip_to_datalake,
    save_organization_to_mdl,
    save_port_scan_to_datalake,
    save_ticket_to_datalake,
    save_vuln_scan,
)
from xfd_api.utils.validation import save_validation_checksum
from xfd_mini_dl.models import Cidr, Organization, Sector


async def handler(event):
    """Handle execution of the vulnerability scanning sync task.

    This function serves as the entry point for triggering the synchronization
    process. It calls the `main` function and returns the appropriate response
    based on the execution outcome.

    Args:
        event (dict): The event data that triggers the function.

    Returns:
        dict: Response containing the status code and message.
    """
    try:
        main()
        return {"statusCode": 200, "body": "VS Sync completed successfully"}
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}


# Used for loading test data from file for vuln_scans, port_scans, hosts, tickets
def load_test_data(data_set: str) -> list:
    """Load test data from local files for scanning simulations.

    Args:
        data_set (str): The type of data set to load (e.g., "requests", "vuln_scan").

    Returns:
        list: The parsed JSON data from the file.

    Raises:
        ValueError: If an unknown data_set is provided.
        FileNotFoundError: If the specified file does not exist.
    """
    file_paths = {
        "requests": "~/Downloads/requests_full_redshift.json",
        "vuln_scan": "~/Downloads/vuln_scan_sample.json",
        "port_scans": "~/Downloads/port_scans_sample.json",
        "hosts": "~/Downloads/hosts_sample.json",
        "tickets": "~/Downloads/tickets_sample.json",
    }

    file_path = file_paths.get(data_set)

    if file_path is None:
        raise ValueError(f"Unknown data set: {data_set}")

    expanded_path = os.path.expanduser(file_path)

    if not os.path.exists(expanded_path):
        raise FileNotFoundError(f"Test data file not found: {expanded_path}")

    with open(expanded_path, encoding="utf-8") as file:
        return json.load(file)


def query_redshift(query, params=None):
    """Execute a query on Redshift and return results as a list of dictionaries."""
    conn = psycopg2.connect(
        dbname=os.environ.get("REDSHIFT_DATABASE"),
        user=os.environ.get("REDSHIFT_USER"),
        password=os.environ.get("REDSHIFT_PASSWORD"),
        host=os.environ.get("REDSHIFT_HOST"),
        poert=5439,
    )

    try:
        cursor = conn.cursor(
            cursor_factory=psycopg2.extras.DictCursor
        )  # Use DictCursor for row dicts
        cursor.execute(query, params or ())
        results = cursor.fetchall()
        return [dict(row) for row in results]  # Convert to list of dicts
    finally:
        cursor.close()
        conn.close()


def main():
    """Execute the vulnerability scanning synchronization task.

    This function fetches data from Redshift, processes the data, and updates
    relevant Django models.
    """
    print("Starting VS Sync scan")
    request_list = []
    # Need to connect to redshift
    start_time = datetime.datetime.now()
    query = "SELECT * FROM vmtableau.requests;"
    result = query_redshift(query)
    end_time = datetime.datetime.now()
    duration_ms = start_time - end_time
    duration_seconds = duration_ms.total_seconds()
    print(
        f"[Redshift] [{duration_ms}ms] [{duration_seconds}s] [{len(result)} records] {query}"
    )
    # request_list = load_test_data("requests")[:100]
    request_list = load_test_data("requests")

    org_id_dict = {}
    parent_child_dict = {}
    sector_child_dict = {}
    non_sector_list = [
        "CRITICAL_INFRASTRUCTURE",
        "FEDERAL",
        "ROOT",
        "SLTT",
        "CATEGORIES",
        "INTERNATIONAL",
        "THIRD_PARTY",
    ]
    if request_list and isinstance(request_list, list):
        for request in request_list:
            request["agency"] = json.loads(request["agency"])
            request["networks"] = json.loads(request["networks"])
            request["report_types"] = json.loads(request["report_types"])
            request["scan_types"] = json.loads(request["scan_types"])
            request["children"] = (
                json.loads(request["children"])
                if request["children"] is not None
                else []
            )
            if "type" not in request["agency"]:
                if request["_id"] in non_sector_list:
                    # Go to the next request record
                    print("Record missing ID, skipping to next")
                    continue
                if (
                    "children" in request
                    and isinstance(request["children"], list)
                    and len(request["children"]) > 0
                ):
                    sector = {
                        "name": request["agency"]["name"],
                        "acronym": request["_id"],
                        "retired": True if request["retired"] else False,
                    }
                    try:
                        sector_obj, created = Sector.objects.update_or_create(
                            acronym=sector["acronym"],
                            defaults={
                                "name": sector["name"],
                                "retired": sector["retired"],
                            },
                        )
                        if created:
                            print("Created sector", sector_obj.id)
                        print("Updated sector", sector_obj.id)
                        sector_child_dict[sector_obj.id] = request["children"]
                    except Exception as e:
                        print("Error occured creating sector", e)

                continue
            if (
                "children" in request
                and isinstance(request["children"], list)
                and len(request["children"]) > 0
            ):
                parent_child_dict[request["_id"]] = request["children"]
            # Loop through the netwroks and create network objects
            network_list: List[Cidr] = []
            request_networks = (
                request["networks"] if isinstance(request["networks"], list) else []
            )
            for cidr in request_networks:
                try:
                    address = IPv6Network(cidr) if ":" in cidr else IPv4Network(cidr)
                    first_ip = address[0]
                    end_ip = address[-1]
                    network_list.append(
                        {"network": cidr, "start_ip": first_ip, "end_ip": end_ip}
                    )
                except Exception as e:
                    print("Invalid CIDR Format", e)
            # Create a location object
            location_dict = None
            if request.get("agency", {}).get("location", None):
                org_location = request["agency"]["location"]
                location_dict = {
                    "name": org_location["name"],
                    "country_abrv": org_location.get("country", ""),
                    "country": org_location.get("country_name"),
                    "county": org_location.get("county"),
                    "county_fips": org_location.get("county_fips"),
                    "gnis_id": org_location["gnis_id"],
                    "state_abrv": org_location.get("state"),
                    "stateFips": org_location.get("state_fips"),
                    "state": org_location.get("state_name"),
                }
            org_dict = {
                "name": request.get("agency").get("name"),
                "acronym": request["_id"],
                "retired": True if request["retired"] else False,
                "type": request.get("agency").get("type"),
                "stakeholder": True if request["stakeholder"] else False,
                "enrolled_in_vs_timestamp": request["enrolled"]
                if request["enrolled"]
                else datetime.datetime.now(),
                "period_start_vs_timestamp": request.get("period_start"),
                "report_types": json.dumps(request.get("report_types")),
                "scan_types": json.dumps(request.get("scan_types")),
                "is_passive": False,
            }

            # TO-DO Save organization to MDL and return org id
            org_record = save_organization_to_mdl(org_dict, network_list, location_dict)

            org_id_dict[request["_id"]] = org_record.id

            # For Any org that has child organizations, link them here
        for key in parent_child_dict.keys():
            item = parent_child_dict[key]
            org_id = org_id_dict[key]
            org = Organization.objects.get(id=org_id)
            if org:
                children_ids = []
                for acronym in item:
                    try:
                        if org_id_dict[acronym]:
                            children_ids.append(org_id_dict[acronym])
                    except KeyError:
                        print("Org id dict @ acronym did not exist")
                for id in children_ids:
                    try:
                        Organization.objects.filter(id=id).update(parent=org.id)
                        print("Succesfully linked child to parent")
                    except Exception as e:
                        print("Error occured linking child to parent", e)
        # Working on sectors
        for key in sector_child_dict.keys():
            item = sector_child_dict[key]
            sector = Sector.objects.get(id=key)
            organization_ids = []
            if sector:
                for acronym in item:
                    try:
                        if org_id_dict[acronym]:
                            organization_ids.append(org_id_dict[acronym])
                    except KeyError:
                        pass
            organizations = Organization.objects.filter(id__in=organization_ids)
            if len(organization_ids) > 0:
                sector.organizations.add(*organizations)
                print("Succesfully added organizations to sector")

    shaped_orgs = None
    try:
        shaped_orgs = fetch_orgs_and_relations()
    except Exception as e:
        print("Error occurred sending Data to /sync", e)

    if shaped_orgs:
        # Convert to CSV
        print("Shaped orgs exist, chunk them and process")

        # Updated to work with the new output format of chunk_list_by_bytes
        chunks = chunk_list_by_bytes(shaped_orgs, 4194304)

        for idx, chunk_info in enumerate(chunks):
            chunk = chunk_info["chunk"]
            bounds = chunk_info["bounds"]
            csv_data = convert_to_csv(chunk)
            body = {"data": csv_data}
            try:
                checksum = create_checksum(csv_data)
            except Exception as e:
                print("Error creating checksum for csv data", e)
            start = bounds["start"]
            end = bounds["end"]
            headers = {
                "x-checksum": checksum,
                "x-cursor": f"{start}-{end}",
                "Content-Type": "application/json",
                "Authorization": os.environ.get("DMZ_API_KEY"),
            }
            print("Sending chunk to /sync")
            save_validation_checksum(checksum, "LZ PUSH TO DMZ")
            response = requests.post(
                os.environ.get("DMZ_SYNC_ENDPOINT"),
                json=body,
                headers=headers,
                timeout=60,
            )
            if response.status_code == 200:
                print("CSV Succesfully sent to /sync")

    # Connect to Redshift and select vuln_scans table
    vuln_scans = []
    try:
        query = "SELECT * FROM vmtableau.vulns_scans WHERE time >= DATE_SUB(NOW(), INTERVAL 2 DAY);"
        start_time = datetime.datetime.now()
        result = query_redshift(query)
        end_time = datetime.datetime.now()
        duration_ms = start_time - end_time
        duration_seconds = duration_ms.total_seconds()
        print(
            f"[Redshift] [{duration_seconds}ms] [{duration_ms}ms]  [{len(vuln_scans)} records] {query}"
        )
        vuln_scans = result
    except Exception as e:
        print("Error while fetching vuln scans", e)
    try:
        if vuln_scans and isinstance(vuln_scans, list):
            for vuln in vuln_scans:
                owner = vuln.get("owner", None)
                owner_id = org_id_dict.get(owner, None)
                cve_id = None
                ip_id = None
                if vuln.get("ip", None) and isinstance(vuln, dict):
                    ip_id = save_ip_to_datalake(
                        {
                            "ip": vuln["ip"],
                            "ip_hash": hash_ip(vuln["ip"]),
                            "organization": {"id": owner_id},
                        }
                    )
                if vuln.get("cve", None) and isinstance(vuln, dict):
                    cve_id = save_cve_to_datalake({"name": vuln.get("cve")})
                vuln_scan_dict = {
                    "id": vuln.get("_id"),
                    "asset_inventory": (
                        True
                        if vuln.get("asset_inventory") == "true"
                        else False
                        if vuln.get("asset_inventory") == "false"
                        else vuln.get("asset_inventory")
                    ),
                    "bid": vuln.get("bid"),
                    "cert_id": vuln.get("cert"),
                    "cisa_known_exploited": vuln.get("cisa-known-exploited"),
                    "cisco_bug_id": vuln.get("cisco-bug-id"),
                    "cisco_sa": vuln.get("cisco-sa"),
                    "cpe": vuln.get("cpe"),
                    "cve_id": cve_id if cve_id else None,
                    "cve_string": vuln.get("cve"),
                    "cvss3_base_score": vuln.get("cvss3_base_score"),
                    "cvss3_temporal_score": vuln.get("cvss3_temporal_score"),
                    "cvss3_temporal_vector": vuln.get("cvss3_temporal_vector"),
                    "cvss3_vector": vuln.get("cvss3_vector"),
                    "cvss_base_score": vuln.get("cvss_base_score"),
                    "cvss_score_rationale": vuln.get("cvss_score_rationale"),
                    "cvss_score_source": vuln.get("cvss_score_source"),
                    "cvss_temporal_score": vuln.get("cvss_temporal_score"),
                    "cvss_temporal_vector": vuln.get("cvss_temporal_vector"),
                    "cvss_vector": vuln.get("cvss_vector"),
                    "cwe": vuln.get("cwe"),
                    "description": vuln.get("description")
                    if len(vuln.get("description")) < 255
                    else "",
                    "exploit_available": vuln.get("exploit_available"),
                    "exploitability_ease": vuln.get("exploit_ease"),
                    "exploited_by_malware": (
                        True
                        if vuln.get("exploited_by_malware") == "true"
                        else False
                        if vuln.get("exploited_by_malware") == "false"
                        else vuln.get("exploited_by_malware")
                    ),
                    "f_name": vuln.get("fname"),
                    "ip_id": ip_id.ip_hash if ip_id else None,
                    "ip_string": vuln.get("ip"),
                    "latest": (
                        True
                        if vuln.get("latests") == "true"
                        else False
                        if vuln.get("latest") == "false"
                        else vuln.get("latest")
                    ),
                    "organization_id": org_id_dict.get(
                        vuln.get("owner"), None
                    ),  # Link to organization
                    "owner": vuln.get("owner"),
                    "osvdb_Id": vuln.get("osvdb"),
                    "patch_publication_timestamp": vuln.get("patch_publication_date"),
                    "plugin_family": vuln.get("plugin_family"),
                    "plugin_id": vuln.get("plugin_id"),
                    "plugin_modification_date": vuln.get("plugin_modification_date"),
                    "plugin_name": vuln.get("plugin_name"),
                    "plugin_output": vuln.get("plugin_output"),
                    "plugin_publication_date": vuln.get("plugin_publication_date"),
                    "plugin_type": vuln.get("plugin_type"),
                    "port": vuln.get("port"),
                    "port_protocol": vuln.get("protocol"),
                    "risk_factor": vuln.get("risk_factor"),
                    "script_version": vuln.get("script_version"),
                    "see_also": vuln.get("see_also"),
                    "service": vuln.get("service"),
                    "severity": vuln.get("severity"),
                    "solution": vuln.get("solution"),
                    "source": vuln.get("source"),
                    "synopsis": vuln.get("synopsis"),
                    "thorough_tests": (
                        True
                        if vuln.get("thorough_tests") == "true"
                        else False
                        if vuln.get("thorough_tests") == "false"
                        else vuln.get("thorough_tests")
                    ),
                    "vuln_detection_timestamp": vuln.get("time"),
                    "vuln_publication_timestamp": vuln.get("vuln_publication_date"),
                    "xref": vuln.get("xref"),
                    "other_findings": vuln,  # Remaining keys in vuln
                }
                try:
                    save_vuln_scan(vuln_scan_dict)
                except Exception as e:
                    print("Error while creating vuln scan", e)
    except Exception as e:
        print("Error while processing vuln scans", e)

    host_scans = []
    try:
        query = "SELECT * FROM vmtableau.hosts WHERE last_change >= DATE_SUB(NOW(), INTERVAL 2 DAY);"
        start_time = datetime.datetime.now()
        host_scan_rows = query_redshift(query)
        end_time = datetime.datetime.now()
        duration_ms = start_time - end_time
        duration_seconds = duration_ms.total_seconds()
        print(
            f"[Redshift] [{duration_seconds}ms] [{duration_ms}ms]  [{len(vuln_scans)} records] {query}"
        )
        host_scans = host_scan_rows
    except Exception as e:
        print("Error while fetching host scan data", e)
    try:
        if host_scans and isinstance(host_scans, list):
            for host in host_scans:
                owner = host.get("owner", None)
                owner_id = org_id_dict.get(owner, None)
                ip_id = None
                if host.get("ip", None) and isinstance(host, dict):
                    ip_record = save_ip_to_datalake(
                        {
                            "ip": host["ip"],
                            "ip_hash": hash_ip(host["ip"]),
                            "organization": {"id": owner_id},
                        }
                    )
                    ip_id = ip_record.ip_hash
                host_dict = {
                    "id": host.get("_id", None),
                    "ip_string": host.get("ip", None),
                    "ip_id": ip_id if ip_id is not None else None,
                    "updated_timestamp": host.get("last_change", None),
                    "latest_netscan1_timestamp": host.get("latest_scan", {}).get(
                        "NETSCAN1"
                    ),
                    "latest_netscan2_timestamp": host.get("latest_scan", {}).get(
                        "NETSCAN2"
                    ),
                    "latest_vulnscan_timestamp": host.get("latest_scan", {}).get(
                        "VULNSCAN"
                    ),
                    "latest_portscan_timestamp": host.get("latest_scan", {}).get(
                        "PORTSCAN"
                    ),
                    "latest_scan_completion_timestamp": host.get("latest_scan", {}).get(
                        "DONE"
                    ),
                    "location_longitude": host.get("loc", [None, None])[1],
                    "location_latitude": host.get("loc", [None, None])[0],
                    "priority": host.get("priority", 0),
                    "next_scan_timestamp": host.get("next_scan"),
                    "rand": host.get("r"),
                    "curr_stage": host.get("stage"),
                    "host_live": host.get("state", {}).get("up", None),
                    "host_live_reason": host.get("state", {}).get("reason", None),
                    "status": host.get("status", None),
                    "organization_id": org_id_dict.get(host.get("owner"), None),
                }
                save_host(host_dict)
    except Exception as e:
        print("Error while processing host scan data", e)

    tickets = []
    try:
        query = " SELET * FROM vmtablea.tickets WHERE last_change >= DATE_SB(NOW(), INTERVAL 2 DAY);"
        start_time = datetime.datetime.now()
        ticket_rows = query_redshift(query)
        end_time = datetime.datetime.now()
        duration_ms = start_time - end_time
        duration_seconds = duration_ms.total_seconds()
        print(
            f"[Redshift] [{duration_seconds}ms] [{duration_ms}ms]  [{len(tickets)} records] {query}"
        )
        tickets = ticket_rows
    except Exception as e:
        print("Error while fetching ticket data", e)

    try:
        for ticket in tickets:
            details = json.loads(ticket.get("details", ""))
            loc = json.loads(ticket.get("loc", ""))
            ip_id = None
            cve_id = None
            if ticket.get("ip"):
                owner = ticket.get("owner", None)
                ip_record = save_ip_to_datalake(
                    {
                        "ip": ticket["ip"],
                        "ip_hash": hash_ip(ticket["ip"]),
                        "organization": {"id": org_id_dict.get(ticket["owner"])},
                    }
                )
                ip_id = ip_record.ip_hash
            if details.get("cve", None):
                cve_id = save_cve_to_datalake({"name": details["cve"]})
            ticket_dict = {
                "id": ticket["_id"].replace("ObjectId('", "").replace("')", ""),
                "cve_string": details["cve"],
                "cve": cve_id,
                "cvss_base_score": details["cvss_base_score"],
                "cvss_version": None,
                "kev": None,
                "vuln_name": details["name"],
                "cvss_score_source": details["score_source"],
                "cvss_severity": details["severity"],
                "vpr_score": None,
                "false_positive": ticket["false_positive"],
                "ip_string": ticket["ip"],
                "ip": ip_id,
                "updated_timestamp": ticket["last_change"],
                "location_longitude": loc[1],
                "location_latitude": loc[0],
                "found_in_latest_host_scan": ticket["open"],
                "organization": org_id_dict[ticket["owner"]],
                "vuln_port": ticket["port"],
                "port_protocol": ticket["protocol"],
                "snapshots_bool": False
                if ticket.get("snapshots", None) is None
                or ticket.get("snapshots", None)
                else True,
                "vuln_source": ticket["source"],
                "vuln_source_id": ticket["source_id"],
                "closed_timestamp": ticket["time_closed"],
                "opened_timestamp": ticket["time_opened"],
            }
            save_ticket_to_datalake(ticket_dict)

    except Exception as e:
        print("error processing ticket data", e)

    port_scans = []
    try:
        query = "SELECT * FROM vmtableau.port_scans WHERE time >= DATE_SUB(NOW(), INTERVAL 2 DAY);"
        start_time = datetime.datetime.now()
        port_scan_rows = query_redshift(query)
        end_time = datetime.datetime.now()
        duration_ms = start_time - end_time
        duration_seconds = duration_ms.total_seconds()
        print(
            f"[Redshift] [{duration_seconds}ms] [{duration_ms}ms]  [{len(port_scan_rows)} records] {query}"
        )
        port_scans = port_scan_rows
    except Exception as e:
        print("Error occured while fetching port_scans", e)

    try:
        for port_scan in port_scans:
            ip_id = None
            owner_acronymn = port_scan.get("Owner", None)
            owner_id = org_id_dict.get(owner, None)
            if not owner_id:
                print(
                    f"{owner_acronymn} is not a recognized organization, skipping host"
                )
                continue
            if port_scan.get("ip", None):
                ip_record = save_ip_to_datalake(
                    {
                        "ip": port_scan.get("ip"),
                        "ip_hash": hash_ip(port_scan.get("ip")),
                        "organization": {"id": owner_id},
                    }
                )
                ip_id = ip_record.ip_hash
            port_scan_service = (
                json.loads(port_scan["service"])
                if port_scan.get("service", None)
                else {}
            )
            port_scan_dict = {
                "id": port_scan["_id"].replace("ObjectId('", "").replace("')", ""),
                "ip_string": port_scan.get("ip"),
                "ip": ip_id if ip_id is not None else None,
                "organization_id": owner_id,
                "latest": port_scan.get("latest", None),
                "port": port_scan.get("port", None),
                "protocol": port_scan.get("protocol", None),
                "reason": port_scan.get("reason", None),
                "service": port_scan_service,
                "service_name": port_scan_service.get("name"),
                "service_confidence": port_scan_service.get("conf"),
                "service_method": port_scan_service.get("method"),
                "source": port_scan.get("source", None),
                "state": port_scan.get("state", None),
                "time_scanned": port_scan.get("time"),
            }
            save_port_scan_to_datalake(port_scan_dict)

    except Exception as e:
        print("Error occured while processing port_scan data", e)
