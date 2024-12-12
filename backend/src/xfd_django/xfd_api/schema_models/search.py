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


class DomainSearchBody(BaseModel):
    """Elastic search domain model."""

    current: Optional[int] = 1
    filters: Optional[List[dict]] = []
    resultsPerPage: Optional[int] = 15
    searchTerm: Optional[str] = ""
    sortDirection: Optional[str] = "asc"
    sortField: Optional[str] = "name"
    organization_id: Optional[List[str]] = None
    tag_id: Optional[str] = None
