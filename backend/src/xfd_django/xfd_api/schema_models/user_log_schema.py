"""User event log schema."""

from typing import Optional, Any, List
from pydantic import BaseModel, validator

class Filter(BaseModel):
    value: str
    operator: Optional[str] = 'contains'

    @validator('operator')
    def validate_operator(cls, v):
        allowed = ['contains', 'exact', 'iexact', 'startswith', 'istartswith', 'endswith', 'iendswith']
        if v and v not in allowed:
            raise ValueError(f'Operator must be one of {allowed}')
        return v

class DateFilter(BaseModel):
    value: str
    operator: str

    @validator('operator')
    def validate_operator(cls, v):
        allowed = ['is', 'not', 'after', 'onOrAfter', 'before', 'onOrBefore', 'empty', 'notEmpty']
        if v not in allowed:
            raise ValueError(f'Operator must be one of {allowed}')
        return v

class LogSearch(BaseModel):
    eventType: Optional[Filter] = None
    result: Optional[Filter] = None
    timestamp: Optional[DateFilter] = None
    payload: Optional[str] = None 

    @validator('payload')
    def validate_payload(cls, v):
        if v:
            if not isinstance(v, str):
                raise ValueError('Payload must be a string')
        return v
    
class LogSearchResponse(BaseModel):
    """Log search response model."""
    result: List[Any]
    count: int

