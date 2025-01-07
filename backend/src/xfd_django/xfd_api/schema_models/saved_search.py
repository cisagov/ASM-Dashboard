"""Saved Search schemas."""
# Standard Python Libraries
from datetime import datetime
from typing import Any, List, Optional
from uuid import UUID

# Third-Party Libraries
from pydantic import BaseModel


class SavedSearchFilters(BaseModel):
    """SavedSearchFilters schema."""

    type: Optional[str]
    field: str
    values: List[Any]


class SavedSearchCreate(BaseModel):
    """Saved search create."""

    name: str
    searchTerm: str
    sortDirection: str
    sortField: str
    count: int
    filters: List[SavedSearchFilters]
    searchPath: str


class SavedSearchUpdate(BaseModel):
    """Saved search update."""

    name: str
    searchTerm: str
    sortDirection: str
    sortField: str
    count: int
    filters: List[SavedSearchFilters]
    searchPath: str


class SavedSearch(BaseModel):
    """SavedSearch schema."""

    id: UUID
    createdAt: datetime
    updatedAt: datetime
    name: str
    searchTerm: str
    sortDirection: str
    sortField: str
    count: int
    filters: List[SavedSearchFilters]
    searchPath: str
    createdById: UUID


class SavedSearchList(BaseModel):
    """SavedSearchList schema."""

    result: List[SavedSearch]
    count: int
