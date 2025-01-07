"""Search schemas."""
# Standard Python Libraries
from typing import Any, List, Optional

# Third-Party Libraries
from pydantic import BaseModel


# Input request schema
class Filter(BaseModel):
    """Filter."""

    field: str
    values: List[str]
    type: str


# TODO this is based on current payload just as needed
class SearchRequest(BaseModel):
    """Search request."""

    current: int
    filters: List[Filter]
    resultsPerPage: int
    searchTerm: Optional[str] = ""
    sortDirection: str = "asc"
    sortField: str = "name"


# Response schema (based on your example)
class SearchResponse(BaseModel):
    """Search response."""

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
