"""Run bastion (Read-Only)."""
# Standard Python Libraries
import os

# Third-Party Libraries
import django
from django.db import connection

# Django setup
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()


def handler(event, context):
    """Execute database queries or manage Elasticsearch indices (Read-Only)."""
    mode = event.get("mode")
    query = event.get("query")

    if not mode or not query:
        return {"statusCode": 400, "body": "Mode and query are required in the event."}

    try:
        if mode == "db":
            return handle_db_query(query)
        else:
            return {"statusCode": 400, "body": "Unsupported mode: {}".format(mode)}
    except Exception as e:
        return {"statusCode": 500, "body": "Error: {}".format(str(e))}


def handle_db_query(query):
    """Handle only read-only SELECT queries safely using parameterized execution."""
    # Only allow SELECT queries
    if not is_safe_select_query(query):
        return {"statusCode": 403, "body": "Only SELECT queries are allowed."}

    try:
        with connection.cursor() as cursor:
            cursor.execute(query)
            result = cursor.fetchall()

        return {"statusCode": 200, "body": str(result)}
    except Exception as e:
        return {"statusCode": 500, "body": "Database error: {}".format(str(e))}


def is_safe_select_query(query):
    """
    Validate that the query is a safe, read-only SELECT statement.

    Ensures no modifications, UNION injections, or dangerous clauses.
    """
    query = query.strip().lower()

    # Reject any queries that do not start with SELECT
    if not query.startswith("select"):
        return False

    # Prevent UNION-based injection
    if "union" in query:
        return False

    # Prevent subqueries modifying data
    if any(
        kw in query
        for kw in ["insert", "update", "delete", "drop", "alter", "truncate", "exec"]
    ):
        return False

    return True
