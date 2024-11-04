"""Pydantic models used by FastAPI."""
# Standard Python Libraries
from collections import UserDict
from datetime import date, datetime
from decimal import Decimal

# from pydantic.types import UUID1, UUID
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

# Third-Party Libraries
from matplotlib.text import OffsetFrom
from pydantic import UUID4, BaseModel, ConfigDict, EmailStr, Field

# from pygments.lexers.configs import UnixConfigLexer

"""
Developer Note: If there comes an instance as in class Cidrs where there are
foreign keys. The data type will not be what is stated in the database. What is
happening is the data base is making a query back to the foreign key table and
returning it as the column in its entirety i.e. select * from <table>, so it
will error and not be able to report on its data type. In these scenario's use
the data type "Any" to see what the return is.
"""


class SeverityCountSchema(BaseModel):
    id: str
    value: int

    class Config:
        from_attributes = True
