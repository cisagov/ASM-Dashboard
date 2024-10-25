# Standard Python Libraries
from typing import Any, List, Optional
from uuid import UUID

# Third-Party Libraries
from pydantic import BaseModel


# Input request schema
class Filter(BaseModel):
    field: str
    values: List[str]
    type: str


# TODO this is based on current payload Ajust as needed
class SearchRequest(BaseModel):
    current: int
    filters: List[Filter]
    resultsPerPage: int
    searchTerm: Optional[str] = ""
    sortDirection: str = "asc"
    sortField: str = "name"


# Response schema (based on your example)
class SearchResponse(BaseModel):
    took: int
    timed_out: bool
    _shards: Any
    hits: Any


class SearchBody(BaseModel):
    current: int
    results_per_page: int
    search_term: str
    sort_direction: str
    sort_field: str
    filters: List[Filter]
    organization_ids: Optional[List[UUID]] = None
    organization_id: Optional[UUID] = None
    tag_id: Optional[UUID] = None
