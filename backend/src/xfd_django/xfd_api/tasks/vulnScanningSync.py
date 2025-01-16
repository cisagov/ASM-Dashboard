# Standard Python Libraries
import datetime
from ipaddress import IPv4Network, IPv6Network
import json
import os
from typing import List, Optional, TypedDict
from uuid import uuid4

# Third-Party Libraries
import psycopg2
from psycopg2.extensions import connection, cursor


class Sector:
    def __init__(self, name, acronym, retired):
        self.name = name
        self.acronym = acronym
        self.retired = retired

    def __repr__(self):
        return (
            f"Sector(name={self.name}, acronym={self.acronym}, retired={self.retired})"
        )


async def handler(event):
    try:
        main()
        return {"statusCode": 200, "body": "VS Sync completed successfully"}
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}


class Cidr(TypedDict):
    network: str
    start_ip: IPv4Network | IPv6Network
    end_ip: IPv4Network | IPv6Network


class Location(TypedDict):
    name: str
    country_abrv: str
    country: str
    county: str
    county_fips: str
    gnis_id: str
    state_abrv: str
    state_fips: str
    state: str


class Organization:
    def __init__(
        self,
        id: str,
        created_at: datetime.datetime,
        updated_at: datetime.datetime,
        acronym: str,
        retired: bool,
        name: str,
        root_domains: Optional[str],
        ip_blocks: Optional[str],
        is_passive: bool,
        pending_domains: Optional[str],
        date_pe_first_reported: Optional[datetime.datetime],
        country: Optional[str],
        country_name: Optional[str],
        state: Optional[str],
        region_id: Optional[str],
        state_fips: Optional[int],
        state_name: Optional[str],
        county: Optional[str],
        county_fips: Optional[int],
        type: Optional[str],
        pe_report_on: Optional[bool],
        pe_premium: Optional[bool],
        pe_demo: Optional[bool],
        agency_type: Optional[str],
        is_parent: Optional[bool],
        pe_run_scans: Optional[bool],
        stakeholder: Optional[bool],
        election: Optional[bool],
        was_stakeholder: Optional[bool],
        vs_stakeholder: Optional[bool],
        pe_stakeholder: Optional[bool],
        receives_cyhy_report: Optional[bool],
        receives_bod_report: Optional[bool],
        receives_cybex_report: Optional[bool],
        init_stage: Optional[str],
        scheduler: Optional[str],
        enrolled_in_vs_timestamp: Optional[datetime.datetime],
        period_start_vs_timestamp: Optional[datetime.datetime],
        report_types: Optional[List[str]],
        scan_types: Optional[List[str]],
        scan_windows: Optional[str],
        scan_limits: Optional[str],
        password: Optional[str],
        cyhy_period_start: Optional[datetime.datetime],
        created_by_id: Optional[str],
        location_id: Optional[str],
        org_type_id: Optional[str],
        parent_id: Optional[str],
    ):
        self.id = id
        self.created_at = created_at
        self.updated_at = updated_at
        self.acronym = acronym
        self.retired = retired
        self.name = name
        self.root_domains = root_domains
        self.ip_blocks = ip_blocks
        self.is_passive = is_passive
        self.pending_domains = pending_domains
        self.date_pe_first_reported = date_pe_first_reported
        self.country = country
        self.country_name = country_name
        self.state = state
        self.region_id = region_id
        self.state_fips = state_fips
        self.state_name = state_name
        self.county = county
        self.county_fips = county_fips
        self.type = type
        self.pe_report_on = pe_report_on
        self.pe_premium = pe_premium
        self.pe_demo = pe_demo
        self.agency_type = agency_type
        self.is_parent = is_parent
        self.pe_run_scans = pe_run_scans
        self.stakeholder = stakeholder
        self.election = election
        self.was_stakeholder = was_stakeholder
        self.vs_stakeholder = vs_stakeholder
        self.pe_stakeholder = pe_stakeholder
        self.receives_cyhy_report = receives_cyhy_report
        self.receives_bod_report = receives_bod_report
        self.receives_cybex_report = receives_cybex_report
        self.init_stage = init_stage
        self.scheduler = scheduler
        self.enrolled_in_vs_timestamp = enrolled_in_vs_timestamp
        self.period_start_vs_timestamp = period_start_vs_timestamp
        self.report_types = report_types
        self.scan_types = scan_types
        self.scan_windows = scan_windows
        self.scan_limits = scan_limits
        self.password = password
        self.cyhy_period_start = cyhy_period_start
        self.created_by_id = created_by_id
        self.location_id = location_id
        self.org_type_id = org_type_id
        self.parent_id = parent_id
        self.location = Location

    @classmethod
    def from_tuple(cls, data: tuple):
        # Define the parameter order as per the tuple structure
        param_names = [
            "id",
            "created_at",
            "updated_at",
            "acronym",
            "retired",
            "name",
            "root_domains",
            "ip_blocks",
            "is_passive",
            "pending_domains",
            "date_pe_first_reported",
            "country",
            "country_name",
            "state",
            "region_id",
            "state_fips",
            "state_name",
            "county",
            "county_fips",
            "type",
            "pe_report_on",
            "pe_premium",
            "pe_demo",
            "agency_type",
            "is_parent",
            "pe_run_scans",
            "stakeholder",
            "election",
            "was_stakeholder",
            "vs_stakeholder",
            "pe_stakeholder",
            "receives_cyhy_report",
            "receives_bod_report",
            "receives_cybex_report",
            "init_stage",
            "scheduler",
            "enrolled_in_vs_timestamp",
            "period_start_vs_timestamp",
            "report_types",
            "scan_types",
            "scan_windows",
            "scan_limits",
            "password",
            "cyhy_period_start",
            "created_by_id",
            "location_id",
            "org_type_id",
            "parent_id",
        ]

        # Ensure the tuple length matches the number of parameters
        if len(data) != len(param_names):
            raise ValueError(f"Expected {len(param_names)} elements, got {len(data)}")

        # Convert tuple to dictionary using param_names
        input_dict = dict(zip(param_names, data))

        # Call the class constructor with the unpacked dictionary
        return cls(**input_dict)

    def __repr__(self):
        return f"Organization({self.acronym}, {self.name})"


class Location:
    def __init__(
        self,
        id: str,
        name: Optional[str],
        country_abrv: Optional[str],
        country: Optional[str],
        county: Optional[str],
        county_fips: Optional[str],
        gnis_id: Optional[str],
        state_abrv: Optional[str],
        state_fips: Optional[str],
        state: Optional[str],
    ):
        self.id = id
        self.name = name
        self.country_abrv = country_abrv
        self.country = country
        self.county = county
        self.county_fips = county_fips
        self.gnis_id = gnis_id
        self.state_abrv = state_abrv
        self.state_fips = state_fips
        self.state = state

    @classmethod
    def from_tuple(cls, data: tuple):
        # Define the parameter order as per the tuple structure
        param_names = [
            "id",
            "name",
            "country_abrv",
            "country",
            "county",
            "county_fips",
            "gnis_id",
            "state_abrv",
            "state_fips",
            "state",
        ]

        # Ensure the tuple length matches the number of parameters
        if len(data) != len(param_names):
            raise ValueError(f"Expected {len(param_names)} elements, got {len(data)}")

        # Create the object by unpacking the tuple into the constructor
        return cls(*data)

    def __repr__(self):
        return f"Location({self.name}, {self.state}, {self.country})"


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
        user="mdl_local",
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
                    print("Creating sector for request")
                    # In TS we are converting the this to a Sector object via a typeorm models
                    sector = {
                        "name": request["agency"]["name"],
                        "acronym": request["_id"],
                        "retired": True if request["retired"] else False,
                    }
                    try:
                        variables = [
                            str(uuid4()),
                            sector["name"],
                            sector["acronym"],
                            sector["retired"],
                        ]
                        mdl_cursor.execute(
                            """INSERT INTO sector (id, name, acronym, retired)
                                                VALUES (%s, %s, %s, %s)
                                                ON CONFLICT (id)
                                                DO UPDATE
                                                SET name = EXCLUDED.name,
                                                    acronym = EXCLUDED.acronym,
                                                    retired = EXCLUDED.retired;
                                            """,
                            variables,
                        )
                        mdl_connection.commit()
                        print("Created Sector")
                        return
                    except Exception as e:
                        mdl_connection.rollback()
                    except psycopg2.errors.UniqueViolation:
                        mdl_connection.rollback()
                    sector_updated_values = []

                    try:
                        # TO-DO - Save Sectors to the Data Lake
                        # TO-DO - Add sector and orgs to the sector_child_dict so we can link them after creating orgs
                        print("Result", result)
                    except Exception as e:
                        print("Error connecting to MDL", e)

                    print("Sector Updated Values", sector_updated_values)
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
                "enrolledInVsTimestamp": request["enrolled"]
                if request["enrolled"]
                else datetime.datetime.now(),
                "periodStartVsTimestamp": request.get("period_start"),
                "reportTypes": json.dumps(request.get("report_types")),
                "scanTypes": json.dumps(request.get("scan_types")),
            }

            # TO-DO Save organization to MDL and return org id
            org_id = save_organization_to_mdl(
                org_dict, network_list, location_dict, mdl_connection
            )

            org_id_dict[request["_id"]] = org_id

            # For Any org that has child organizations, link them here
            for key in parent_child_dict.keys():
                item = parent_child_dict[key]

    try:
        fetch_orgs_and_relations(mdl_connection)
    except Exception as e:
        print("Error occurre sending Data to /sync", e)


def fetch_orgs_and_relations(connection: connection):
    # To-Do - Fetch and attach sectors, cidrs, parent, children
    orgs = {}
    mdl_cursor = connection.cursor()
    try:
        mdl_cursor.execute("SELECT * FROM organization;")
        org_rows = mdl_cursor.fetchall()
        for row in org_rows:
            org = Organization.from_tuple(row)
            orgs[org.id] = org
    except Exception as e:
        print("Error fetching organization", e)
    location_ids = []
    location_org_dict = {}
    for org in orgs.values():
        location_ids.append(org.location_id)
        # Create a location_org map so we can attach the location to the org after fetching locations
        location_org_dict[org.location_id] = org.id
    try:
        placeholders = ", ".join(["%s"] * len(location_ids))
        mdl_cursor.execute(
            f"SELECT * FROM location WHERE id IN ({placeholders})", location_ids
        )
        location_rows = mdl_cursor.fetchall()
        if len(location_rows) > 0:
            for row in location_rows:
                location = Location.from_tuple(row)
                orgs[location_org_dict[location.id]].location = location
    except Exception as e:
        print("Errror occured while fetching locations", e)


def save_organization_to_mdl(org_dict, network_list, location, connection: connection):
    # Creates organization in database
    # Creates location for organization
    # Creates cidrs and links cidrs to organization
    location_id = save_location_to_mdl(location, connection)
    cursor = connection.cursor()
    org_id = None
    org_insert_query = """INSERT INTO organization
                            (name, acronym, retired, type, stakeholder,
                            enrolled_in_vs_timestamp, period_start_vs_timestamp,
                            report_types, scan_types, id, created_at, updated_at,
                            is_passive, ip_blocks, location_id)
                            VALUES
                            (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (id)
                            DO UPDATE SET
                            name = EXCLUDED.name,
                            acronym = EXCLUDED.acronym,
                            retired = EXCLUDED.retired,
                            type = EXCLUDED.type,
                            stakeholder = EXCLUDED.stakeholder,
                            enrolled_in_vs_timestamp = EXCLUDED.enrolled_in_vs_timestamp,
                            period_start_vs_timestamp = EXCLUDED.period_start_vs_timestamp,
                            report_types = EXCLUDED.report_types,
                            scan_types = EXCLUDED.scan_types,
                            updated_at = EXCLUDED.updated_at,
                            is_passive = EXCLUDED.is_passive,
                            ip_blocks = EXCLUDED.ip_blocks,
                            location_id = EXCLUDED.location_id
                            RETURNING id;"""
    try:
        variables = list(org_dict.values())
        extra_vars = [
            str(uuid4()),
            datetime.datetime.now(),
            datetime.datetime.now(),
            False,
            "[]",
            location_id,
        ]
        variables.extend(extra_vars)

        cursor.execute(org_insert_query, variables)
        connection.commit()
        org_id = cursor.fetchone()[0]
    except psycopg2.errors.UniqueViolation:
        connection.rollback()
        get_org_by_acronym_query = """SELECT id FROM organization WHERE acronym = %s"""
        acronym = org_dict["acronym"]
        cursor.execute(get_org_by_acronym_query, [acronym])
        org_id = cursor.fetchone()[0]
    except Exception as e:
        print(type(e))
        connection.rollback()
        print("Error occured saving org to MDL", e)

    if org_id:
        # Create cidrs and link them
        for cidr in network_list:
            save_cidr_to_mdl(cidr, connection, org_id)
    return org_id


def save_location_to_mdl(location: Location, connection: connection):
    insert_location_query = """INSERT INTO location
                               (id, name, country_abrv, country, county, county_fips, gnis_id, state_abrv, state_fips, state)
                               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                               RETURNING id;
                               """
    if not location:
        return None
    variables = list(location.values())
    variables.insert(0, str(uuid4()))
    try:
        mdl_cursor = connection.cursor()
        mdl_cursor.execute(insert_location_query, variables)
        connection.commit()
        return mdl_cursor.fetchone()[0]
    except psycopg2.errors.UniqueViolation:
        connection.rollback()
        get_location_by_gnis_id_query = (
            """SELECT id FROM location WHERE gnis_id = %s;"""
        )
        mdl_cursor.execute(get_location_by_gnis_id_query, [str(location["gnis_id"])])
        return mdl_cursor.fetchone()[0]


def save_cidr_to_mdl(cidr: Cidr, connection: connection, org_id: str):
    cidr_id = None
    mdl_cursor = connection.cursor()
    upsert_cidr_query = """ INSERT INTO cidr (id, network, start_ip, end_ip, created_date, updated_at)
                            VALUES (%s, %s, %s, %s, %s, %s)
                            ON CONFLICT (id)
                            DO UPDATE SET
                                start_ip = EXCLUDED.start_ip,
                                end_ip = EXCLUDED.end_ip,
                                updated_at = EXCLUDED.updated_at
                            RETURNING id; """
    try:
        variables = [
            str(uuid4()),
            cidr["network"],
            str(cidr["start_ip"]),
            str(cidr["end_ip"]),
            datetime.datetime.now(),
            datetime.datetime.now(),
        ]
        mdl_cursor.execute(upsert_cidr_query, variables)
        connection.commit()
        cidr_id = mdl_cursor.fetchone()[0]
    except psycopg2.errors.UniqueViolation:
        connection.rollback()
        get_cidr_by_network_query = """SELECT id FROM cidr WHERE network = %s"""
        mdl_cursor.execute(get_cidr_by_network_query, [str(cidr["network"])])
        cidr_id = mdl_cursor.fetchone()[0]

    except Exception as e:
        connection.rollback()
        print("Error occured saving cidr to MDL", e)

    try:
        create_cidr_org_link_query = """INSERT INTO cidr_organizations
                                        (cidr_id, organization_id)
                                        VALUES (%s, %s );"""
        variables = [cidr_id, org_id]
        mdl_cursor.execute(create_cidr_org_link_query, variables)
        connection.commit()
        # print(f"Created cidr and linked for {cidr['network']}")
    except psycopg2.errors.UniqueViolation as e:
        # Do something?
        connection.rollback()


# def fetch_org_and_children(org_id: str, cursor: cursor):
#     cursor.execute("SELECT * FROM organization WHERE id == %s", [org_id])


main()
