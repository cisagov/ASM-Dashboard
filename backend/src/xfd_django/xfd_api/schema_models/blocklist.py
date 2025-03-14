"""Blocklist Schemas."""
# Third-Party Libraries
from pydanti import BaseModel


class BlocklistCheckResponse(BaseModel):
    """BlocklistCheckResponse schema."""

    status: str
