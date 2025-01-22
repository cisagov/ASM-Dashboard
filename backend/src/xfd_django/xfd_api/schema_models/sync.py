
from pydantic import BaseModel

class SyncResponse(BaseModel):
    status: int


class SyncBody(BaseModel):
    data: str