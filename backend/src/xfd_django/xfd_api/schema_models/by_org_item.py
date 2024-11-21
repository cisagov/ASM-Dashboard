"""Pydantic models used by FastAPI."""

# Third-Party Libraries
from pydantic import BaseModel

# from pygments.lexers.configs import UnixConfigLexer

"""
Developer Note: If there comes an instance as in class Cidrs where there are
foreign keys. The data type will not be what is stated in the database. What is
happening is the data base is making a query back to the foreign key table and
returning it as the column in its entirety i.e. select * from <table>, so it
will error and not be able to report on its data type. In these scenario's use
the data type "Any" to see what the return is.
"""


class ByOrgItem(BaseModel):
    id: str
    orgId: str
    value: int
    label: str

    class Config:
        from_attributes = True
