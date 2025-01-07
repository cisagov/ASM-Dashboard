"""Search methods."""
# Standard Python Libraries
import csv
import io
from typing import Any, Dict, List

# Third-Party Libraries
from fastapi import HTTPException
from xfd_api.auth import (
    get_org_memberships,
    get_tag_organizations,
    is_global_view_admin,
)
from xfd_api.helpers.elastic_search import build_request
from xfd_api.helpers.s3_client import S3Client
from xfd_api.tasks.es_client import ESClient

from ..schema_models.search import DomainSearchBody


async def get_options(search_body, user) -> Dict[str, Any]:
    """Get Elastic Search options."""
    if search_body.organization_id and (
        search_body.organization_id in get_org_memberships(user)
        or is_global_view_admin(user)
    ):
        return {
            "organization_ids": [search_body.organization_id],
            "match_all_organizations": False,
        }
    if search_body.tag_id:
        return {
            "organization_ids": get_tag_organizations(user, search_body.tag_id),
            "match_all_organizations": False,
        }

    return {
        "organization_ids": get_org_memberships(user),
        "match_all_organizations": is_global_view_admin(user),
    }


async def fetch_all_results(
    search_body: DomainSearchBody,
    options: Dict[str, Any],
    client: ESClient,
) -> List[Dict[str, Any]]:
    """Fetch all results from Elasticsearch."""
    results: List[Any] = []
    current = 1
    RESULTS_PER_PAGE = 1000

    while True:
        request = build_request(
            DomainSearchBody(
                **{
                    "current": current,
                    "resultsPerPage": RESULTS_PER_PAGE,
                    "filters": search_body.filters,
                    "searchTerm": search_body.searchTerm,
                    "sortDirection": search_body.sortDirection,
                    "sortField": search_body.sortField,
                }
            ),
            options,
        )
        try:
            response = client.search_domains(request)
        except Exception as e:
            print(f"Elasticsearch error: {e}")
            raise HTTPException(status_code=500, detail="Error querying Elasticsearch.")

        hits = response.get("hits", {}).get("hits", [])
        if not hits:
            break

        results.extend(hit["_source"] for hit in hits)
        current += 1

    return results


def process_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Process Elasticsearch results into the desired format."""
    processed_results = []
    for res in results:
        res["organization"] = (
            res["organization"]["name"] if "organization" in res else None
        )
        res["ports"] = ", ".join(
            str(service["port"]) for service in res.get("services", [])
        )

        products = {}
        for service in res.get("services", []):
            for product in service.get("products", []):
                if "name" in product:
                    product_name = product["name"].lower()
                    product_version = product.get("version", "")
                    products[
                        product_name
                    ] = f"{product['name']} {product_version}".strip()

        res["products"] = ", ".join(products.values())
        processed_results.append(res)

    return processed_results


def generate_csv(results: List[Dict[str, Any]], fields: List[str]) -> str:
    """Generate a CSV from the processed results."""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(results)
    return output.getvalue()


# POST: /search
async def search_post(search_body: DomainSearchBody, current_user):
    """Handle Elastic Search request."""
    options = await get_options(search_body, current_user)
    es_query = build_request(search_body, options)

    client = ESClient()

    # Perform search in Elasticsearch
    response = client.search_domains(body=es_query)

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


# POST: /search/export
async def search_export(search_body: DomainSearchBody, current_user) -> Dict[str, Any]:
    """Export the search results into a CSV and upload to S3."""
    # Get Elasticsearch options
    options = await get_options(search_body, current_user)

    # Fetch results from Elasticsearch
    client = ESClient()
    results = await fetch_all_results(search_body, options, client)

    # Process results for CSV
    processed_results = process_results(results)

    # Define CSV fields
    csv_fields = [
        "name",
        "ip",
        "id",
        "ports",
        "products",
        "createdAt",
        "updatedAt",
        "organization",
        "screenshot",
        "censysCertificatesResults",
        "ipOnly",
        "vulnerabilities",
        "cloudHosted",
        "reverseName",
        "subdomainSource",
        "country",
        "ssl",
        "parent_join",
        "discoveredBy",
        "fromCidr",
        "fromRootDomain",
        "trustymailResults",
        "asn",
        "syncedAt",
        "isFceb",
        "services",
        "suggest",
    ]
    # Generate CSV content
    csv_content = generate_csv(processed_results, csv_fields)

    # Upload CSV to S3
    s3_client = S3Client()
    try:
        csv_url = s3_client.save_csv(csv_content, "domains")
    except Exception as e:
        print(f"S3 upload error: {e}")
        raise HTTPException(status_code=500, detail="Error uploading CSV to S3.")

    return {"url": csv_url}
