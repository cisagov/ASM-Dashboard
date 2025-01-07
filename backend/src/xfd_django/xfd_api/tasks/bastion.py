"""Run bastion."""
# Standard Python Libraries
import os

# Third-Party Libraries
import django
from django.db import connection
from xfd_api.tasks.es_client import ESClient

# Django setup
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()


def handler(event, context):
    """Execute database queries or managing Elasticsearch indices."""
    mode = event.get("mode")
    query = event.get("query")

    if not mode or not query:
        return {"statusCode": 400, "body": "Mode and query are required in the event."}

    try:
        if mode == "db":
            return handle_db_query(query)
        elif mode == "es":
            return handle_es_query(query)
        else:
            return {"statusCode": 400, "body": f"Unsupported mode: {mode}"}
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}


def handle_db_query(query):
    """Handle the 'db' mode: executes a raw SQL query on the database."""
    with connection.cursor() as cursor:
        cursor.execute(query)
        result = cursor.fetchall()

    print(str(result))
    return {"statusCode": 200, "body": str(result)}


def handle_es_query(query):
    """Handle the 'es' mode: interacts with Elasticsearch."""
    client = ESClient()

    if query == "delete":
        client.delete_all()
        return {"statusCode": 200, "body": "Index successfully deleted."}
    else:
        return {"statusCode": 400, "body": f"Unsupported Elasticsearch query: {query}"}
