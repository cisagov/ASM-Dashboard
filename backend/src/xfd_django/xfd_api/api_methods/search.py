# api_methods/search.py
# Standard Python Libraries
import csv
from io import StringIO
from typing import Any, Dict, List, Optional
from uuid import UUID

# Third-Party Libraries
import boto3
from elasticsearch import Elasticsearch
from fastapi import HTTPException
from pydantic import BaseModel
from xfd_api.auth import (
    get_org_memberships,
    get_tag_organizations,
    is_global_view_admin,
)
from xfd_api.helpers.elastic_search import build_elasticsearch_query, es

from ..schema_models.search import SearchBody


# TODO: Determine if new search method works with indexes, if so:
# remove the commented out original search methods
def get_options(search_body: SearchBody, event) -> Dict[str, Any]:
    """Determine options for filtering based on organization ID or tag ID."""
    if search_body.organization_id and (
        search_body.organization_id in get_org_memberships(event)
        or is_global_view_admin(event)
    ):
        options = {
            "organizationIds": [search_body.organization_id],
            "matchAllOrganizations": False,
        }
    elif search_body.tag_id:
        options = {
            "organizationIds": get_tag_organizations(event, str(search_body.tag_id)),
            "matchAllOrganizations": False,
        }
    else:
        options = {
            "organizationIds": get_org_memberships(event),
            "matchAllOrganizations": is_global_view_admin(event),
        }
    return options


def fetch_all_results(
    filters: Dict[str, Any], options: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Fetch all search results from Elasticsearch."""
    client = Elasticsearch()
    results = []
    current = 1
    while True:
        # Define the request as an empty dictionary for now
        request: Dict[str, Any] = {}
        current += 1
        try:
            search_results = client.search(index="domains", body=request)
        except Exception as e:
            print(f"Elasticsearch search error: {e}")
            continue
        if len(search_results["hits"]["hits"]) == 0:
            break
        results.extend([res["_source"] for res in search_results["hits"]["hits"]])
    return results


def search(search_body: SearchBody, event) -> Dict[str, Any]:
    """Perform a search on Elasticsearch and return results."""
    request: Dict[str, Any] = {}

    client = Elasticsearch()
    try:
        search_results = client.search(index="domains", body=request)
    except Exception as e:
        print(f"Elasticsearch search error: {e}")
        raise HTTPException(status_code=500, detail="Elasticsearch query failed")

    return search_results["hits"]


def search_post(request_input):
    """Handle Elastic Search request"""
    
    es_query = build_elasticsearch_query(request_input)

    # Perform search in Elasticsearch TODO: Confirm index name and format
    response = es.search(index="domains-5", body=es_query)

    # Format response to match the required structure
    result = {
        "took": response["took"],
        "timed_out": response["timed_out"],
        "_shards": response["_shards"],
        "hits": {
            "total": response["hits"]["total"],
            "max_score": response["hits"].get("max_score", None),
            "hits": [
                {
                    "_index": hit["_index"],
                    "_type": hit["_type"],
                    "_id": hit["_id"],
                    "_score": hit["_score"],
                    "_source": hit["_source"],
                    "sort": hit.get("sort", []),
                    "inner_hits": hit.get("inner_hits", {}),
                }
                for hit in response["hits"]["hits"]
            ],
        },
    }

    return result


def export(search_body: SearchBody, event) -> Dict[str, Any]:
    """Export the search results into a CSV and upload to S3."""
    options = get_options(search_body, event)
    print(f"Export Options: {options}")
    results = fetch_all_results(search_body.dict(), options)
    print(f"Export results: {results}")

    # Process results for CSV
    for res in results:
        res["organization"] = res.get("organization", {}).get("name", "")
        res["ports"] = ", ".join(
            [str(service["port"]) for service in res.get("services", [])]
        )
        products = {}
        for service in res.get("services", []):
            for product in service.get("products", []):
                if product.get("name"):
                    products[product["name"].lower()] = product["name"] + (
                        f" {product['version']}" if product.get("version") else ""
                    )
        res["products"] = ", ".join(products.values())

    # Create CSV
    csv_buffer = StringIO()
    fieldnames = [
        "name",
        "ip",
        "id",
        "ports",
        "products",
        "createdAt",
        "updatedAt",
        "organization",
    ]
    writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(results)

    # TODO: Replace with helper s3 logic
    # Save to S3
    # s3 = boto3.client("s3")
    # bucket_name = "export-bucket-name"
    # csv_key = "domains.csv"
    # s3.put_object(Bucket=bucket_name, Key=csv_key, Body=csv_buffer.getvalue())

    # # Generate a presigned URL to access the CSV
    # url = s3.generate_presigned_url(
    #     "get_object", Params={"Bucket": bucket_name, "Key": csv_key}, ExpiresIn=3600
    # )

    # return {"url": url}
    # TODO: Modify return once s3 logic is confirmed.
    return {"data": results}
