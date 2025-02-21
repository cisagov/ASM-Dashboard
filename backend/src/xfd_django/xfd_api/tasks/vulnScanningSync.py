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
from xfd_mini_dl.models import Organization, Sector


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
    """Execute the vulnerability scanning synchronization task."""
    print("Starting VS Sync scan")

    # Load request data
    request_list = load_test_data("requests")
    org_id_dict = process_orgs(request_list)

    # Process Organizations & Relations
    process_organizations_and_relations(org_id_dict)

    # Process Vulnerability Scans
    vuln_scans = fetch_from_redshift(
        "SELECT * FROM vmtableau.vulns_scans WHERE time >= DATE_SUB(NOW(), INTERVAL 2 DAY);"
    )
    if vuln_scans:
        process_vulnerability_scans(vuln_scans, org_id_dict)

    # Process Host Scans
    host_scans = fetch_from_redshift(
        "SELECT * FROM vmtableau.hosts WHERE last_change >= DATE_SUB(NOW(), INTERVAL 2 DAY);"
    )
    if host_scans:
        process_host_scans(host_scans, org_id_dict)

    # Process Tickets
    tickets = fetch_from_redshift(
        "SELECT * FROM vmtableau.tickets WHERE last_change >= DATE_SUB(NOW(), INTERVAL 2 DAY);"
    )
    if tickets:
        process_tickets(tickets, org_id_dict)

    # Process Port Scans
    port_scans = fetch_from_redshift(
        "SELECT * FROM vmtableau.port_scans WHERE time >= DATE_SUB(NOW(), INTERVAL 2 DAY);"
    )
    if port_scans:
        process_port_scans(port_scans, org_id_dict)

    print("VS Sync scan completed successfully!")


def fetch_from_redshift(query):
    """Fetch data from Redshift and log execution time."""
    try:
        start_time = datetime.datetime.now()
        result = query_redshift(query)
        end_time = datetime.datetime.now()
        duration_seconds = (end_time - start_time).total_seconds()
        print(f"[Redshift] [{duration_seconds}s] [{len(result)} records] {query}")
        return result
    except Exception as e:
        print(f"Error fetching data from Redshift: {e}")
        return []


def process_organizations_and_relations():
    """Fetch organizations and sync with the external API."""
    try:
        shaped_orgs = fetch_orgs_and_relations()
        if not shaped_orgs:
            return

        print("Shaped orgs exist, chunking and processing")
        chunks = chunk_list_by_bytes(shaped_orgs, 4194304)

        for idx, chunk_info in enumerate(chunks):
            chunk = chunk_info["chunk"]
            bounds = chunk_info["bounds"]
            csv_data = convert_to_csv(chunk)
            send_csv_to_sync(csv_data, bounds)
    except Exception as e:
        print(f"Error processing organization data: {e}")


def send_csv_to_sync(csv_data, bounds):
    """Send CSV data to /sync API."""
    body = {"data": csv_data}
    try:
        checksum = create_checksum(csv_data)
    except Exception as e:
        print(f"Error creating checksum: {e}")
        return

    headers = {
        "x-checksum": checksum,
        "x-cursor": f"{bounds['start']}-{bounds['end']}",
        "Content-Type": "application/json",
        "Authorization": os.environ.get("DMZ_API_KEY"),
    }

    response = requests.post(
        os.environ.get("DMZ_SYNC_ENDPOINT"), json=body, headers=headers, timeout=60
    )
    if response.status_code == 200:
        print("CSV successfully sent to /sync")


def process_vulnerability_scans(vuln_scans, org_id_dict):
    """Process and save vulnerability scans."""
    for vuln in vuln_scans:
        try:
            owner_id = org_id_dict.get(vuln.get("owner"))
            ip_id = (
                save_ip_to_datalake(
                    {
                        "ip": vuln["ip"],
                        "ip_hash": hash_ip(vuln["ip"]),
                        "organization": {"id": owner_id},
                    }
                )
                if vuln.get("ip")
                else None
            )
            cve_id = (
                save_cve_to_datalake({"name": vuln["cve"]}) if vuln.get("cve") else None
            )

            vuln_scan_dict = build_vuln_scan_dict(vuln, owner_id, ip_id, cve_id)
            save_vuln_scan(vuln_scan_dict)
        except Exception as e:
            print(f"Error processing vulnerability scan: {e}")


def build_vuln_scan_dict(vuln, owner_id, ip_id, cve_id):
    """Construct a vulnerability scan dictionary."""
    return {
        "id": vuln.get("_id"),
        "organization_id": owner_id,
        "ip_id": ip_id.ip_hash if ip_id else None,
        "cve_id": cve_id if cve_id else None,
        "cve_string": vuln.get("cve"),
        "severity": vuln.get("severity"),
        "vuln_detection_timestamp": vuln.get("time"),
        "other_findings": vuln,
    }


def process_host_scans(host_scans, org_id_dict):
    """Process and save host scans."""
    for host in host_scans:
        try:
            owner_id = org_id_dict.get(host.get("owner"))
            ip_id = (
                save_ip_to_datalake(
                    {
                        "ip": host["ip"],
                        "ip_hash": hash_ip(host["ip"]),
                        "organization": {"id": owner_id},
                    }
                )
                if host.get("ip")
                else None
            )

            host_dict = {
                "id": host.get("_id"),
                "organization_id": owner_id,
                "ip_id": ip_id.ip_hash if ip_id else None,
                "status": host.get("status"),
                "updated_timestamp": host.get("last_change"),
            }
            save_host(host_dict)
        except Exception as e:
            print(f"Error processing host scan: {e}")


def process_tickets(tickets, org_id_dict):
    """Process and save ticket data."""
    for ticket in tickets:
        try:
            details = json.loads(ticket.get("details", "{}"))
            # loc = json.loads(ticket.get("loc", "[]"))
            ip_id = (
                save_ip_to_datalake(
                    {
                        "ip": ticket["ip"],
                        "ip_hash": hash_ip(ticket["ip"]),
                        "organization": {"id": org_id_dict.get(ticket["owner"])},
                    }
                )
                if ticket.get("ip")
                else None
            )
            cve_id = (
                save_cve_to_datalake({"name": details.get("cve")})
                if details.get("cve")
                else None
            )

            ticket_dict = {
                "id": ticket["_id"].replace("ObjectId('", "").replace("')", ""),
                "organization_id": org_id_dict[ticket["owner"]],
                "ip_id": ip_id,
                "cve_id": cve_id,
                "updated_timestamp": ticket["last_change"],
            }
            save_ticket_to_datalake(ticket_dict)
        except Exception as e:
            print(f"Error processing ticket data: {e}")


def process_port_scans(port_scans, org_id_dict):
    """Process and save port scan data."""
    for port_scan in port_scans:
        try:
            owner_id = org_id_dict.get(port_scan.get("Owner"))
            if not owner_id:
                print(
                    f"{port_scan.get('Owner')} is not a recognized organization, skipping host"
                )
                continue

            ip_id = (
                save_ip_to_datalake(
                    {
                        "ip": port_scan.get("ip"),
                        "ip_hash": hash_ip(port_scan.get("ip")),
                        "organization": {"id": owner_id},
                    }
                )
                if port_scan.get("ip")
                else None
            )

            port_scan_dict = {
                "id": port_scan["_id"].replace("ObjectId('", "").replace("')", ""),
                "organization_id": owner_id,
                "ip_id": ip_id,
                "port": port_scan.get("port"),
                "protocol": port_scan.get("protocol"),
            }
            save_port_scan_to_datalake(port_scan_dict)
        except Exception as e:
            print(f"Error processing port scan data: {e}")


def process_orgs(request_list, org_id_dict):
    """Process organization data, save to MDL and return org ID dict for linking."""
    sector_child_dict = {}
    parent_child_dict = {}

    # Process the request data
    if request_list and isinstance(request_list, list):
        process_request(request_list, sector_child_dict, parent_child_dict, org_id_dict)

        # Link parent-child organizations
        link_parent_child_organizations(parent_child_dict, org_id_dict)

        # Assign organizations to sectors
        assign_organizations_to_sectors(sector_child_dict, org_id_dict)

    return org_id_dict


def link_parent_child_organizations(parent_child_dict, org_id_dict):
    """Link child organizations to their respective parent organizations."""
    for parent_acronym, child_acronyms in parent_child_dict.items():
        parent_id = org_id_dict.get(parent_acronym)
        if not parent_id:
            print(f"Parent acronym {parent_acronym} not found in org_id_dict")
            continue

        try:
            parent_org = Organization.objects.get(id=parent_id)
        except Organization.DoesNotExist:
            print(f"Parent organization {parent_id} does not exist")
            continue

        # Collect child organization IDs
        children_ids = [
            org_id_dict.get(acronym)
            for acronym in child_acronyms
            if acronym in org_id_dict
        ]

        # Update parent field for child organizations
        if children_ids:
            Organization.objects.filter(id__in=children_ids).update(
                parent=parent_org.id
            )
            print(
                f"Successfully linked {len(children_ids)} children to parent {parent_acronym}"
            )


def assign_organizations_to_sectors(sector_child_dict, org_id_dict):
    """Assign organizations to sectors based on sector-child relationships."""
    for sector_id, child_acronyms in sector_child_dict.items():
        try:
            sector = Sector.objects.get(id=sector_id)
        except Sector.DoesNotExist:
            print(f"Sector {sector_id} does not exist")
            continue

        organization_ids = [
            org_id_dict.get(acronym)
            for acronym in child_acronyms
            if acronym in org_id_dict
        ]

        if organization_ids:
            sector.organizations.add(
                *Organization.objects.filter(id__in=organization_ids)
            )
            print(
                f"Successfully added {len(organization_ids)} organizations to sector {sector_id}"
            )


def process_request(request_list, sector_child_dict, parent_child_dict, org_id_dict):
    """Process requests and build dictionaries for linking later."""
    non_sector_list = {
        "CRITICAL_INFRASTRUCTURE",
        "FEDERAL",
        "ROOT",
        "SLTT",
        "CATEGORIES",
        "INTERNATIONAL",
        "THIRD_PARTY",
    }

    for request in request_list:
        request = parse_request_data(request)

        # Skip non-sector records
        if "type" not in request["agency"]:
            if request["_id"] in non_sector_list:
                print("Record missing ID, skipping to next")
                continue

            process_sector(request, sector_child_dict)
            continue

        # Process parent-child relationships
        if request.get("children"):
            parent_child_dict[request["_id"]] = request["children"]

        # Process networks
        network_list = process_networks(request.get("networks", []))

        # Process location
        location_dict = process_location(request.get("agency", {}).get("location"))

        # Process organization
        process_organization(request, network_list, location_dict, org_id_dict)


def parse_request_data(request):
    """Parse JSON fields in the request."""
    json_fields = ["agency", "networks", "report_types", "scan_types", "children"]
    for field in json_fields:
        if field in request:
            request[field] = json.loads(request[field]) if request[field] else []
    return request


def process_sector(request, sector_child_dict):
    """Process sector data and update sector_child_dict."""
    if request.get("children"):
        sector_data = {
            "name": request["agency"]["name"],
            "acronym": request["_id"],
            "retired": bool(request["retired"]),
        }
        try:
            sector_obj, created = Sector.objects.update_or_create(
                acronym=sector_data["acronym"],
                defaults={
                    "name": sector_data["name"],
                    "retired": sector_data["retired"],
                },
            )
            print(f"{'Created' if created else 'Updated'} sector {sector_obj.id}")
            sector_child_dict[sector_obj.id] = request["children"]
        except Exception as e:
            print("Error occurred creating sector", e)


def process_networks(networks):
    """Process network CIDR entries and return a list of network objects."""
    network_list = []
    for cidr in networks:
        try:
            address = IPv6Network(cidr) if ":" in cidr else IPv4Network(cidr)
            network_list.append(
                {"network": cidr, "start_ip": address[0], "end_ip": address[-1]}
            )
        except Exception as e:
            print("Invalid CIDR Format", e)
    return network_list


def process_location(org_location):
    """Create a dictionary representation of an organization's location."""
    if not org_location:
        return None

    return {
        "name": org_location.get("name"),
        "country_abrv": org_location.get("country", ""),
        "country": org_location.get("country_name"),
        "county": org_location.get("county"),
        "county_fips": org_location.get("county_fips"),
        "gnis_id": org_location.get("gnis_id"),
        "state_abrv": org_location.get("state"),
        "stateFips": org_location.get("state_fips"),
        "state": org_location.get("state_name"),
    }


def process_organization(request, network_list, location_dict, org_id_dict):
    """Save organization data and update org_id_dict."""
    org_data = {
        "name": request["agency"]["name"],
        "acronym": request["_id"],
        "retired": bool(request["retired"]),
        "type": request["agency"]["type"],
        "stakeholder": bool(request["stakeholder"]),
        "enrolled_in_vs_timestamp": request["enrolled"] or datetime.datetime.now(),
        "period_start_vs_timestamp": request.get("period_start"),
        "report_types": json.dumps(request.get("report_types")),
        "scan_types": json.dumps(request.get("scan_types")),
        "is_passive": False,
    }

    org_record = save_organization_to_mdl(org_data, network_list, location_dict)
    org_id_dict[request["_id"]] = org_record.id
