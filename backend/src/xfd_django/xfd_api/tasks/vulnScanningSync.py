import os
# Uncomment the below to run the script standalone
import sys
import django
# Dynamically add the project root to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(PROJECT_ROOT)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'xfd_django.settings')
django.setup()
# Uncomment the above to run the script standalone
import datetime
from ipaddress import IPv4Network, IPv6Network
from django.db.models import Prefetch
import json
from typing import List, Optional, TypedDict
from uuid import uuid4
import psycopg2
from psycopg2.extensions import connection, cursor
from xfd_api.utils.chunk import chunk_list_by_bytes
from xfd_api.utils.csv_utils import convert_to_csv, write_csv_to_file


#  Look into Error creating location 'NoneType' object is not subscriptable

from xfd_mini_dl.models import Sector, Organization, Cidr, Location

async def handler(event):
    try:
        main()
        return {"statusCode": 200, "body": "VS Sync completed successfully"}
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}

def load_test_data():
    file_path = os.path.expanduser("~/Downloads/requests_full_redshift.json")
    with open(file_path) as file:
        data = json.load(file)
    return data


def main():
    print("Starting VS Sync scan")
    request_list = []
    # Need to connect to redshift
    start_time = datetime.datetime.now()
    query = "SELECT * FROM vmtableau.requests;"
    # result = client.query()
    result = []
    end_time = datetime.datetime.now()
    duration_ms = start_time - end_time
    duration_seconds = duration_ms.total_seconds()
    print(
        f"[Redshift] [{duration_ms}ms] [{duration_seconds}s] [{len(result)} records] {query}"
    )
    # request_list = result.row
    request_list = load_test_data()

    mdl_connection = psycopg2.connect(
        user="dmz_mdl",
        password="mini_data_lake",
        host="127.0.0.1",
        port="5432",
        database="mini_data_lake_local",
    )

    mdl_cursor = mdl_connection.cursor()

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
                json.loads(request["children"]) if request["children"] != None else []
            )
            if not "type" in request["agency"]:
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
                            acronym=sector['acronym'],
                            defaults={
                                "name": sector['name'],
                                "retired": sector['retired']
                            }
                        )
                        if created:
                            print('Created sector', sector_obj.id)
                        print('Updated sector', sector_obj.id)
                        sector_child_dict[sector_obj.id] = request["children"]
                    except Exception as e:
                        print('Error occured creating sector', e)
                    try:
                        # TO-DO - Save Sectors to the Data Lake
                        # TO-DO - Add sector and orgs to the sector_child_dict so we can link them after creating orgs
                        print("Result", result)
                    except Exception as e:
                        print("Error connecting to MDL", e)

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
                "is_passive": False
            }

            # TO-DO Save organization to MDL and return org id
            org_record = save_organization_to_mdl(
                org_dict, network_list, location_dict
            )

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
                        print('Org id dict @ acronym did not exist')
                for id in children_ids:
                    try:
                        Organization.objects.filter(id=id).update(parent=org.id)
                        print('Succesfully linked child to parent')
                    except Exception as e:
                        print('Error occured linking child to parent')
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
                        print('Org id dict @ acronym did not exist')
            organizations = Organization.objects.filter(id__in=organization_ids)
            if len(organization_ids) > 0:
                print('Adding orgs to sector')
                print(sector.id)
                print(organization_ids)
                sector.organizations.add(*organizations)
                print("Succesfully added organizations to sector")


            
    shaped_orgs = None
    try:
        shaped_orgs = fetch_orgs_and_relations(mdl_connection)
    except Exception as e:
        print("Error occurred sending Data to /sync", e)
    
    if shaped_orgs:
        # Convert to CSV and save a local copy?
        # Do we need to chunk?
        print('Shaped orgs exist, chunk them and slam')
        chunks: List[List] = chunk_list_by_bytes(shaped_orgs, 4194304)
        for idx, chunk in enumerate(chunks):
            csv_data = convert_to_csv(chunk)
            now = datetime.datetime.now()
            write_csv_to_file(csv_data, f"csv-output_{idx}_{now.day}-{now.month}-{now.year}",)
            print('Succesfully chunked organization CSV data.')
    # To - Do
    # Perform a checksum on each chunk
    # Send the data and checksum to /sync


# Helper and utility functions
def fetch_orgs_and_relations(connection: connection):
    # Prefetch related ManyToMany fields (sectors, cidrs) and reverse ForeignKey (children)
    sectors_prefetch = Prefetch('sectors')
    cidrs_prefetch = Prefetch('cidrs')
    children_prefetch = Prefetch('organization_set')  # Default reverse name for self-referential ForeignKey

    # Fetch organizations with all the necessary relations
    organizations = Organization.objects.select_related(
        'location',   # ForeignKey
        'parent',     # Self-referential ForeignKey for parent organization
        'org_type'    # ForeignKey for organization type
    ).prefetch_related(
        sectors_prefetch,  # ManyToManyField for sectors
        cidrs_prefetch,    # ManyToManyField for CIDRs
        children_prefetch  # Reverse ForeignKey for children organizations
    )

    # Iterate through results and access related fields
    shaped_orgs = []
    for org in organizations:
        shaped_orgs.append(organization_to_dict(org))
    return shaped_orgs
        
    

def organization_to_dict(org):
    """Converts an Organization instance and its relations to a nested dictionary."""
    return {
        "id": str(org.id),
        "name": org.name,
        "acronym": org.acronym,
        "retired": org.retired,
        "created_at": org.created_at,
        "updated_at": org.updated_at,
        "location": {
            "id": str(org.location.id) if org.location else None,
            "name": org.location.name if org.location else None,
        } if org.location else None,
        "parent": {
            "id": str(org.parent.id) if org.parent else None,
            "name": org.parent.name if org.parent else None,
        } if org.parent else None,
        "children": [
            {"id": str(child.id), "name": child.name}
            for child in org.organization_set.all()
        ],
        "sectors": [
            {"id": str(sector.id), "name": sector.name}
            for sector in org.sectors.all()
        ],
        "cidrs": [
            {
                "id": str(cidr.id),
                "network": str(cidr.network),
                "start_ip": str(cidr.start_ip),
                "end_ip": str(cidr.end_ip),
            }
            for cidr in org.cidrs.all()
        ],
    }

# Fetch organizations with their relations
organizations = Organization.objects.select_related(
    'location', 'parent', 'org_type'
).prefetch_related(
    Prefetch('sectors'), Prefetch('cidrs'), Prefetch('organization_set')
)

# Convert organizations to a nested dictionary
org_dicts = [organization_to_dict(org) for org in organizations]

# Print or return the resulting list of dictionaries
print(org_dicts)


def save_organization_to_mdl(org_dict, network_list, location):
    # Creates organization in database
    # Creates location for organization
    # Creates cidrs and links cidrs to organization
    location_obj = None
    try:
        location_obj, created = Location.objects.update_or_create(
        gnis_id=location['gnis_id'],  # Lookup field
        defaults={  # Fields to update or set if creating
            'name': location.get('name', None),
            'country_abrv': location.get('country_abrv', None),
            'country': location.get('country', None),
            'county': location.get('county', None),
            'county_fips': location.get('county_fips', None),
            'state_abrv': location.get('state_abrv', None),
            'state': location.get('state', None),
            }
        )
    except Exception as e:
        print('Error creating location', e)
    org_obj = None
    try:
        organization_obj = Organization.objects.get(acronym=org_dict['acronym'])
        organization_obj.name = org_dict['name']
        organization_obj.retired = org_dict['retired']
        organization_obj.type = org_dict['type']
        organization_obj.stakeholder = org_dict['stakeholder']
        organization_obj.enrolled_in_vs_timestamp = org_dict['enrolled_in_vs_timestamp']
        organization_obj.period_start_vs_timestamp = org_dict['period_start_vs_timestamp']
        organization_obj.report_types = org_dict['report_types']
        organization_obj.scan_types = org_dict['scan_types']
        organization_obj.location = location_obj
        organization_obj.save()
        org_obj = organization_obj
    except Organization.DoesNotExist:
        organization_obj = Organization.objects.create(
                id=str(uuid4()),
                name=org_dict['name'],
                acronym=org_dict['acronym'],
                retired=org_dict['retired'],
                type=org_dict['type'],
                stakeholder=org_dict['stakeholder'],
                enrolled_in_vs_timestamp=org_dict['enrolled_in_vs_timestamp'],
                period_start_vs_timestamp=org_dict['period_start_vs_timestamp'],
                report_types=org_dict['report_types'],
                scan_types=org_dict['scan_types'],
                location=location_obj,
                is_passive=False
            )
        org_obj = organization_obj
    except Exception as e:
        print('Error occured creating org', type(e))

    if org_obj:
        # Create cidrs and link them
        for cidr in network_list:
            save_cidr_to_mdl(cidr, org_obj)
    return org_obj



def save_cidr_to_mdl(cidr_dict: dict, org: Organization):
    # print('Creating or updating CIDR for', org)
    try:
        # Look for an existing object by the unique constraints
        cidr_obj = Cidr.objects.filter(
            network=cidr_dict['network'], 
            start_ip=cidr_dict['start_ip']
        ).first()
        
        if cidr_obj:
            # Update the existing object
            cidr_obj.end_ip = cidr_dict['end_ip']
            cidr_obj.save()
            created = False
        else:
            # Create a new object
            cidr_obj = Cidr.objects.create(
                id=str(uuid4()),
                network=cidr_dict['network'],
                start_ip=cidr_dict['start_ip'],
                end_ip=cidr_dict['end_ip']
            )
            created = True

        # Link the organization to the ManyToManyField
        cidr_obj.organizations.set([org])

        # if created:
        #     print('Created new CIDR and linked:', cidr_obj.id)
        # else:
        #     print('Updated existing CIDR and linked:', cidr_obj.id)

    except Exception as e:
        print('Error occurred while creating or updating CIDR:', e)
 


# def fetch_org_and_children(org_id: str, cursor: cursor):
#     cursor.execute("SELECT * FROM organization WHERE id == %s", [org_id])

import time
start_time = time.time()
main()
end_time = time.time()

runtime = end_time - start_time
print(f"Function runtime: {runtime} seconds")
