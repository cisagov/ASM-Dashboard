"""Pydantic models used by FastAPI."""

from pydantic import BaseModel

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
