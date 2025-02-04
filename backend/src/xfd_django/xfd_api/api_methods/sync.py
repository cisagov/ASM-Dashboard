"""Split a list into chunks based on a byte size limit.

Each chunk will have a total byte size that does not exceed the specified
maximum. Chunks are stored as dictionaries containing the chunked items
and their bounds.
"""

# Standard Python Libraries

# Standard Python Libraries
from datetime import datetime
from uuid import uuid4

# Third-Party Libraries
from django.db import transaction
from fastapi import Request
from xfd_api.tasks.vulnScanningSync import save_organization_to_mdl
from xfd_mini_dl.models import Organization, Sector

from ..helpers.s3_client import S3Client
from ..utils.csv_utils import convert_csv_to_json, create_checksum


# Helper function
async def sync_post(sync_body, request: Request):
    """Ingest and persist organization data to the data lake."""
    headers = request.headers
    request_checksum = headers.get("x-checksum")

    try:
        if not request_checksum:
            # Checksum missing in request headers, return 500
            return {"status": 500}

        generated_checksum = create_checksum(sync_body.data)
        if request_checksum != generated_checksum:
            # Checksums don't match, return 500
            return {"status": 500}

        # Use MinIO client to save CSV data to S3
        s3_client = S3Client()
        cursor_header = headers.get("x-cursor")
        start_bound, end_bound = -1, -2

        if cursor_header:
            bounds = cursor_header.split("-")
            if len(bounds) >= 2:
                start_bound, end_bound = bounds[0], bounds[1]

        now = datetime.now()
        file_name = f"lz_org_sync/{now.month}-{now.day}-{now.year}/{start_bound}-{end_bound}.csv"

        if not sync_body.data:
            # Sync body missing
            return {"status": 500}

        s3_url = s3_client.save_csv(sync_body.data, file_name)
        if not s3_url:
            return {"status": 500}

        parsed_data = convert_csv_to_json(sync_body.data)
        for item in parsed_data:
            try:
                org = save_organization_to_mdl(
                    org_dict=item,
                    network_list=item["cidrs"],
                    location=item["location"],
                    db_name="mini_data_lake_integration",
                )

                parent_acronym = (
                    item.get("parent", {}).get("acronym", None)
                    if isinstance(item.get("parent"), dict)
                    else None
                )
                sectors = item.get("sectors", [])  # Now an array

                # Handle if the organization has a parent
                if org:
                    if parent_acronym:
                        print("Parent acronym exists, attempting to link")
                        try:
                            parent_org = Organization.objects.using(
                                "mini_data_lake_integration"
                            ).get(acronym=parent_acronym)
                            org.parent = parent_org
                            org.save()
                        except Organization.DoesNotExist:
                            print(
                                f"Parent organization with acronym {parent_acronym} not found."
                            )
                        except Exception as e:
                            print("Error while linking parent org to child org:", e)

                    # Handle sector association (now multiple)
                    if isinstance(sectors, list):
                        for sector in sectors:
                            sector_acronym = sector.get("acronym")
                            if sector_acronym:
                                print(
                                    f"Sector acronym {sector_acronym} exists, attempting to link or create sector then link"
                                )
                                try:
                                    with transaction.atomic():
                                        sector_obj = Sector.objects.using(
                                            "mini_data_lake_integration"
                                        ).get(acronym=sector_acronym)
                                        # Update the existing sector
                                        sector_obj.name = sector.get("name", None)
                                        sector_obj.save()
                                except Sector.DoesNotExist:
                                    # Create a new sector if it doesn't exist
                                    sector_obj = Sector.objects.using(
                                        "mini_data_lake_integration"
                                    ).create(
                                        id=str(uuid4()),
                                        name=sector.get("name", None),
                                        acronym=sector_acronym,
                                    )

                                # Ensure the organization is linked to the sector
                                if not sector_obj.organizations.filter(
                                    id=org.id
                                ).exists():
                                    sector_obj.organizations.add(org)

            except Exception as e:
                print("Error processing item:", e)

            except Exception as e:
                print("Error creating Org in integration MDL", e)

        return {"status": 200}

    except Exception as e:
        print("Error:", e)
        return {"status": 500}
