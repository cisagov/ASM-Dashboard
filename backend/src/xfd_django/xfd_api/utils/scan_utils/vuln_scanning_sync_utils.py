"""Utility functions for vulnerability scanning synchronization.

This module provides functions to save and fetch vulnerability scan data,
including organizations, hosts, IPs, CVEs, tickets, and port scans. It supports
data synchronization by interfacing with the data lake and database models.
"""

# Standard Python Libraries
from typing import Dict
from uuid import uuid4
import datetime

# Third-Party Libraries
from django.db import transaction
from django.db.models import Exists, OuterRef, Prefetch
from django.db.utils import IntegrityError
from xfd_mini_dl.models import (
    Cidr,
    CidrOrgs,
    Cve,
    Host,
    Ip,
    Location,
    Organization,
    PortScan,
    Ticket,
    VulnScan,
)


def save_port_scan_to_datalake(port_scan_obj):
    """
    Save a PortScan record to the datalake, performing an upsert if necessary.

    Args:
        port_scan_obj (dict): A dictionary containing PortScan record data.

    Returns:
        str or None: The ID of the inserted/updated record.
    """
    # print(
    #     f"Starting to save port scan {port_scan_obj.get('ipString')} {port_scan_obj.get('port')} to datalake"
    # )

    # Map fields to match Django model expectations
    field_mapping = {"organization": "organization_id", "ip": "ip_id"}

    # Determine fields to update, excluding 'id'
    port_scan_updated_values = {
        field_mapping.get(key, key): value
        for key, value in port_scan_obj.items()
        if key != "id" and value is not None
    }

    try:
        with transaction.atomic(using="mini_data_lake"):
            if port_scan_updated_values:
                # Upsert: Insert or update if a conflict occurs
                port_scan_record, created = PortScan.objects.update_or_create(
                    id=port_scan_obj.get(
                        "id", str(uuid4())
                    ),  # Generate UUID if not provided
                    defaults=port_scan_updated_values,
                )
                print("Updated PortScan" if not created else "Created PortScan")
                return str(port_scan_record.id)
            else:
                # Insert but ignore if the record already exists
                obj, created = PortScan.objects.get_or_create(
                    id=port_scan_obj.get("id", str(uuid4())), defaults=port_scan_obj
                )
                if not created:
                    print(f"Found existing PortScan: {obj.id}")
                return str(obj.id) if obj else None
    except Exception as e:
        print("Error saving PortScan to Datalake", e)
        return None


def save_ticket_to_datalake(ticket_obj):
    """
    Save a Ticket record to the datalake, performing an upsert if necessary.

    Args:
        ticket_obj (dict): A dictionary containing Ticket record data.

    Returns:
        str or None: The ID of the inserted/updated record.
    """
    # print("Starting to save Ticket to datalake")

    # Map fields to match Django model expectations
    field_mapping = {"organization": "organization_id", "ip": "ip_id", "cve": "cve_id"}

    # Determine fields to update, excluding 'id'
    ticket_updated_values = {
        field_mapping.get(key, key): value
        for key, value in ticket_obj.items()
        if key != "id" and value is not None
    }

    try:
        with transaction.atomic(using="mini_data_lake"):
            if ticket_updated_values:
                # Upsert: Insert or update if a conflict occurs
                ticket_record, created = Ticket.objects.update_or_create(
                    id=ticket_obj.get(
                        "id", str(uuid4())
                    ),  # Generate UUID if not provided
                    defaults=ticket_updated_values,
                )
                print("Updated Ticket" if not created else "Created Ticket")
                return str(ticket_record.id)
            else:
                # Insert but ignore if the record already exists
                obj, created = Ticket.objects.get_or_create(
                    id=ticket_obj.get("id", str(uuid4())), defaults=ticket_obj
                )
                if not created:
                    print(f"Found existing Ticket: {obj.id}")
                return str(obj.id) if obj else None
    except Exception as e:
        print("Error saving Ticket to Datalake", e)
        return None


def save_host(host_data: Dict) -> str:
    """Save a Host record to the data lake.

    Args:
        host_data (dict): A dictionary containing Host record data.

    Returns:
        str: The ID of the inserted/updated record.
    """
    excluded_keys = {"id"}
    key_mapping = {"organization": "organizationId", "ip": "ip_id"}

    host_updated_values = [
        key_mapping.get(key, key)
        for key in host_data.keys()
        if key not in excluded_keys and host_data[key] is not None
    ]

    with transaction.atomic(using="mini_data_lake"):
        host, created = Host.objects.update_or_create(
            id=host_data.get("id"),
            defaults={key: host_data[key] for key in host_updated_values},
        )

    return str(host.id)


def save_vuln_scan(vuln_scan: Dict) -> str:
    """Save a Vulnerability Scan record to the data lake.

    Args:
        vuln_scan (dict): A dictionary containing vulnerability scan data.

    Returns:
        str: The ID of the inserted/updated record.
    """
    vuln_scan_updated_values = [
        "organizationId"
        if key == "organization"
        else "ipId"
        if key == "ip"
        else "cveId"
        if key == "cve"
        else key
        if vuln_scan[key] is not None and key != "id"
        else ""
        for key in vuln_scan.keys()
    ]

    # Filter out empty values
    vuln_scan_updated_values = [key for key in vuln_scan_updated_values if key]

    # Upsert into the database
    vuln_scan_obj, created = VulnScan.objects.update_or_create(
        id=vuln_scan.get("id"),
        defaults={key: vuln_scan[key] for key in vuln_scan_updated_values},
    )

    return str(vuln_scan_obj.id)


def save_cve_to_datalake(cve_obj):
    """
    Save a CVE record to the datalake, performing an upsert if necessary.

    Args:
        cve_obj (dict): A dictionary containing CVE record data.

    Returns:
        str or None: The ID of the inserted/updated record.
    """
    cve_name = cve_obj.get("name")

    print(f"Starting to save CVE to datalake: {cve_name}")

    # Determine fields to update, excluding 'name'
    cve_updated_values = [
        key
        for key in cve_obj.keys()
        if key not in ["name"] and cve_obj[key] is not None
    ]

    try:
        with transaction.atomic(using="mini_data_lake"):
            if cve_updated_values:
                # Upsert: Insert or update if a conflict occurs
                cve_record, created = Cve.objects.update_or_create(
                    name=cve_name,
                    defaults={key: cve_obj[key] for key in cve_updated_values}
                    | {"id": str(uuid4())},
                )
                print("Updated CVE" if not created else "Created CVE")
                return str(cve_record.id)
            else:
                # Insert but ignore if the record already exists
                obj, created = Cve.objects.get_or_create(
                    name=cve_name, defaults=cve_obj | {"id": str(uuid4())}
                )
                if not created:
                    print(f"Found existing CVE: {obj.id}")
                return str(obj.id) if obj else None
    except Exception as e:
        print("Error saving CVE to Datalake", e)
        return None


def save_ip_to_datalake(ip_obj):
    """
    Save an IP record to the datalake, performing an upsert if necessary.

    Args:
        ip_obj (dict): A dictionary containing IP record data.

    Returns:
        str or None: The ID of the inserted/updated record.
    """
    ip_address = ip_obj.get("ip")
    organization = ip_obj.get("organization")

    print(f"Starting to save IP to datalake: {ip_address}")
    print(organization["id"])

    # Determine fields to update
    ip_updated_values = [
        key
        for key in ip_obj.keys()
        if key not in ["ip", "organization"] and ip_obj[key] is not None
    ]
    try:
        org_record = Organization.objects.get(id=str(organization["id"]))
        with transaction.atomic(using="mini_data_lake"):
            if ip_updated_values:
                # Upsert: Insert or update if a conflict occurs
                ip_record, created = Ip.objects.update_or_create(
                    ip=ip_address,
                    organization=org_record or None,
                    defaults={key: ip_obj[key] for key in ip_updated_values},
                )
                print("Updated IP")
                return ip_record
            else:
                # Insert but ignore if the record already exists
                obj, created = Ip.objects.get_or_create(
                    ip=ip_address,
                    organization=org_record or None,
                    defaults={
                        "ip": ip_address,
                        "organization": org_record,
                        "ip_hash": ip_obj["ip_hash"],
                    },
                )
                print("Created ip")
                return obj
    except Exception as e:
        print("Error saving IP to Datalake", e)
    except IntegrityError:
        pass


# Helper and utility functions
def fetch_orgs_and_relations():
    """Fetch organizations along with related sectors, CIDRs, and child organizations.

    Returns:
        list: A list of dictionaries representing organizations and their relations.
    """
    sectors_prefetch = Prefetch("sectors")
    cidrs_prefetch = Prefetch("cidrs")
    children_prefetch = Prefetch(
        "organization_set"  # Default reverse name for self-referential ForeignKey
    )

    # Annotate organizations to identify if their id exists in another record's parent_id
    organizations = (
        Organization.objects.annotate(
            is_p=Exists(Organization.objects.filter(parent_id=OuterRef("id")))
        )
        .select_related(
            "location",  # ForeignKey
            "parent",  # Self-referential ForeignKey for parent organization
            "org_type",  # ForeignKey for organization type
        )
        .prefetch_related(
            sectors_prefetch,  # ManyToManyField for sectors
            cidrs_prefetch,  # ManyToManyField for CIDRs
            children_prefetch,  # Reverse ForeignKey for children organizations
        )
        .order_by(
            "-is_p"  # Order by `is_parent` descending, so parent organizations come first
        )
    )

    # Iterate through results and access related fields
    shaped_orgs = []
    for org in organizations:
        shaped_orgs.append(organization_to_dict(org))
    return shaped_orgs


def organization_to_dict(org):
    """Convert an Organization instance and its relations to a nested dictionary.

    Args:
        org (Organization): The organization instance to convert.

    Returns:
        dict: A dictionary representation of the organization and its related data.
    """
    return {
        "id": str(org.id),
        "name": org.name,
        "acronym": org.acronym,
        "retired": org.retired,
        "created_at": org.created_at,
        "updated_at": org.updated_at,
        "type": org.type,
        "stakeholder": org.stakeholder,
        "enrolled_in_vs_timestamp": org.enrolled_in_vs_timestamp,
        "period_start_vs_timestamp": org.period_start_vs_timestamp,
        "report_types": org.report_types,
        "scan_types": org.scan_types,
        "location": {
            "name": org.location.name,
            "country": org.location.country,
            "county": org.location.county,
            "country_abrv": org.location.country_abrv,
            "county_fips": org.location.county_fips,
            "gnis_id": org.location.gnis_id,
            "state_abrv": org.location.state_abrv,
            "stateFips": org.location.state_fips,
            "state": org.location.state,
        }
        if org.location
        else None,
        "parent": {
            "id": str(org.parent.id) if org.parent else None,
            "name": org.parent.name if org.parent else None,
            "acronym": org.parent.acronym if org.parent else None,
        }
        if org.parent
        else None,
        "children": [
            {"id": str(child.id), "name": child.name}
            for child in org.organization_set.all()
        ],
        "sectors": [
            {"id": str(sector.id), "name": sector.name, "acronym": sector.acronym}
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


def save_organization_to_mdl(
    org_dict, network_list, location, db_name="mini_data_lake"
) -> Organization:
    """Save or update an organization in the specified database.

    This function handles creating or updating an organization record,
    managing its location, and linking CIDRs to the organization.

    Args:
        org_dict (dict): A dictionary containing organization details,
            including name, acronym, type, and enrollment timestamps.
        network_list (list): A list of CIDR dictionaries representing
            the organization's associated networks.
        location (dict or None): A dictionary containing location details
            (e.g., GNIS ID, country, state, etc.), or None if no location is provided.
        db_name (str, optional): The name of the database to use.
            Defaults to "mini_data_lake".

    Returns:
        Organization: The created or updated organization instance.
    """
    location_obj = None
    if location:
        try:
            location_obj, created = Location.objects.using(db_name).update_or_create(
                gnis_id=location["gnis_id"],  # Lookup field
                defaults={  # Fields to update or set if creating
                    "name": location.get("name", None),
                    "country_abrv": location.get("country_abrv", None),
                    "country": location.get("country", None),
                    "county": location.get("county", None),
                    "county_fips": location.get("county_fips", None),
                    "state_abrv": location.get("state_abrv", None),
                    "state": location.get("state", None),
                },
            )
        except Exception as e:
            print("Error creating location", e)

    org_obj = None
    try:
        organization_obj = Organization.objects.using(db_name).get(
            acronym=org_dict["acronym"]
        )
        organization_obj.name = org_dict["name"]
        organization_obj.retired = org_dict["retired"]
        organization_obj.type = org_dict["type"]
        organization_obj.stakeholder = org_dict["stakeholder"]
        organization_obj.enrolled_in_vs_timestamp = org_dict["enrolled_in_vs_timestamp"]
        organization_obj.period_start_vs_timestamp = org_dict[
            "period_start_vs_timestamp"
        ]
        organization_obj.report_types = org_dict["report_types"]
        organization_obj.scan_types = org_dict["scan_types"]
        organization_obj.location = location_obj
        organization_obj.save()
        org_obj = organization_obj
    except Organization.DoesNotExist:
        organization_obj = Organization.objects.using(db_name).create(
            id=str(uuid4()),
            name=org_dict["name"],
            acronym=org_dict["acronym"],
            retired=org_dict["retired"],
            type=org_dict["type"],
            stakeholder=org_dict["stakeholder"],
            enrolled_in_vs_timestamp=org_dict["enrolled_in_vs_timestamp"],
            period_start_vs_timestamp=org_dict["period_start_vs_timestamp"],
            report_types=org_dict["report_types"],
            scan_types=org_dict["scan_types"],
            location=location_obj,
            is_passive=False,
        )
        org_obj = organization_obj
    except IntegrityError:
        organization_obj = Organization.objects.using(db_name).get(
            acronym=org_dict["acronym"]
        )
        if organization_obj:
            org_obj = organization_obj
        pass
    except Exception as e:
        print("Error occurred creating org", e)

    if org_obj:
        # Create CIDRs and link them
        for cidr in network_list:
            save_cidr_to_mdl(cidr, org_obj, db_name)

    return org_obj


def save_cidr_to_mdl(cidr_dict: dict, org: Organization, db_name="mini_data_lake"):
    """
    Create or update a CIDR record in the specified database, linking it to the provided organization.

    Args:
        cidr_dict (dict): Dictionary containing CIDR details (network, start_ip, end_ip).
        org (Organization): Organization to associate with the CIDR.
        db_name (str): Name of the database to use. Defaults to "mini_data_lake".
    """
    try:
        with transaction.atomic(using=db_name):
            # Fetch or create the CIDR object
            cidr_obj = (
                Cidr.objects.using(db_name).filter(network=cidr_dict["network"]).first()
            )
            if cidr_obj:
                cidr_obj.start_ip = cidr_dict["start_ip"]
                cidr_obj.end_ip = cidr_dict["end_ip"]
                cidr_obj.last_seen = datetime.datetime.today().date()
                cidr_obj.save(using=db_name)  # Save updates

            else:
                cidr_obj = Cidr.objects.using(db_name).create(
                    id=str(uuid4()),
                    network=cidr_dict["network"],
                    start_ip=cidr_dict["start_ip"],
                    end_ip=cidr_dict["end_ip"],
                    first_seen = datetime.datetime.today().date(),
                    last_seen = datetime.datetime.today().date()
                )
            # cidr_obj.organizations.add(org, through_defaults={})
            cidr_obj.save(using=db_name)
            CidrOrgs.objects.update_or_create(
                organization=org,
                cidr=cidr_obj,
                defaults={
                    "last_seen":datetime.datetime.today().date(),
                    "current":True
                }
            )
    except IntegrityError as e:
        print("IntegrityError:", e)
    except Exception as e:
        print(type(e))
        print("Error occurred while creating or updating CIDR:", e)
