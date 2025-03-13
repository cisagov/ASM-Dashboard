"""
Module for handling synchronization of organization data to the data lake.

This module provides the `sync_post` function for ingesting and persisting
organization data, along with helper functions for linking organizations
to parents and sectors.
"""

# Standard Python Libraries
from datetime import datetime
import json
from uuid import uuid4

# Third-Party Libraries
from django.db import transaction
from fastapi import HTTPException, Request
from xfd_api.tasks.vulnScanningSync import save_organization_to_mdl
from xfd_mini_dl.models import Organization, Sector

from ..helpers.s3_client import S3Client
from ..utils.csv_utils import create_checksum


async def sync_post(sync_body, request: Request):
    """Ingest and persist organization data to the data lake."""
    try:
        headers = request.headers
        request_checksum = headers.get("x-checksum")

        if not request_checksum or not sync_body.data:
            raise HTTPException(status_code=500, detail="Missing checksum")

        if request_checksum != create_checksum(sync_body.data):
            raise HTTPException(status_code=500, detail="Missing checksum")

        # Use MinIO client to save CSV data to S3
        s3_client = S3Client()
        start_bound, end_bound = parse_cursor(headers.get("x-cursor"))
        file_name = generate_s3_filename(start_bound, end_bound)

        s3_url = s3_client.save_csv(sync_body.data, file_name)
        if not s3_url:
            return {"status": 500}

        parsed_data = json.loads(sync_body.data)

        for item in parsed_data:
            try:
                org = save_organization_to_mdl(
                    org_dict=item,
                    network_list=item["cidrs"],
                    location=item["location"],
                    db_name="mini_data_lake",
                )

                if org:
                    link_parent_organization(
                        org, item.get("parent"), db_name="mini_data_lake"
                    )
                    link_sectors_to_organization(
                        org, item.get("sectors", []), db_name="mini_data_lake"
                    )

            except Exception as e:
                pass
                print("Error processing item:", e)

        return {"status": 200}
    except Exception as e:
        print("Error in sync endpoint", e)


def parse_cursor(cursor_header):
    """Extract start and end bounds from cursor header."""
    if cursor_header:
        bounds = cursor_header.split("-")
        if len(bounds) >= 2:
            return bounds[0], bounds[1]
    return -1, -2


def generate_s3_filename(start_bound, end_bound):
    """Generate file name for S3 storage."""
    now = datetime.now()
    return f"lz_org_sync/{now.month}-{now.day}-{now.year}/{start_bound}-{end_bound}.csv"


def link_parent_organization(org, parent_data, db_name="mini_data_lake_lz"):
    """Link an organization to its parent if applicable."""
    if not isinstance(parent_data, dict):
        return

    parent_acronym = parent_data.get("acronym")
    if not parent_acronym:
        return

    try:
        parent_org = Organization.objects.using(db_name).get(acronym=parent_acronym)
        org.parent = parent_org
        org.save()
    except Organization.DoesNotExist:
        print(f"Parent organization with acronym {parent_acronym} not found.")
    except Exception as e:
        print("Error while linking parent org to child org:", e)


def link_sectors_to_organization(org, sectors, db_name="mini_data_lake_lz"):
    """Associate sectors with the organization."""
    if not isinstance(sectors, list):
        return

    for sector in sectors:
        sector_acronym = sector.get("acronym")
        if not sector_acronym:
            continue

        try:
            with transaction.atomic():
                sector_obj, created = Sector.objects.using(db_name).get_or_create(
                    acronym=sector_acronym,
                    defaults={"id": str(uuid4()), "name": sector.get("name")},
                )

                # Ensure the organization is linked to the sector
                if not sector_obj.organizations.filter(id=org.id).exists():
                    sector_obj.organizations.add(org)

        except Exception as e:
            print(f"Error linking sector {sector_acronym} to organization:", e)
