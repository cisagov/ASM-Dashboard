# Standard Python Libraries
import os
from typing import Any, Dict, List, Optional

# Third-Party Libraries
from django.conf import settings
from elasticsearch import AsyncElasticsearch

from ..schema_models.search import SearchRequest

# Elasticsearch client
es = AsyncElasticsearch(
    hosts=[settings.ELASTICSEARCH_ENDPOINT],
    headers={"Content-Type": "application/json"},  # Set correct Content-Type header
)


# Elasticsearch Query Builder
def build_elasticsearch_query(request: SearchRequest) -> dict:
    # Define the query type explicitly
    query: Dict[str, Any] = {"bool": {"must": [], "filter": []}}

    # Add search term
    if request.searchTerm:
        query["bool"]["must"].append(
            {
                "multi_match": {
                    "query": request.searchTerm,
                    "fields": ["name^3", "organization.name", "organization.acronym"],
                }
            }
        )

    # Add filters
    for filter in request.filters:
        if filter.type == "any":
            query["bool"]["filter"].append({"terms": {filter.field: filter.values}})

    # Return the query with sorting
    return {
        "query": query,
        "sort": [{request.sortField: {"order": request.sortDirection}}],
        "from": (request.current - 1) * request.resultsPerPage,
        "size": request.resultsPerPage,
    }
