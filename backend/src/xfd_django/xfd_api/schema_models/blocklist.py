"""Blocklist Schemas."""
# Third-Party Libraries
from pydantic import BaseModel


class BlocklistCheckResponse(BaseModel):
    """BlocklistCheckResponse schema."""

    status: str
