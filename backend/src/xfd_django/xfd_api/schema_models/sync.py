# Standard Python Libraries
from typing import Any

# Third-Party Libraries
from pydantic import BaseModel


class SyncResponse(BaseModel):
    status: int


class SyncBody(BaseModel):
    data: Any
