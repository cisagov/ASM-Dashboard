# Standard Python Libraries
import os

# Third-Party Libraries
import django
from django.core.management import call_command
from xfd_api.management.commands.syncdb import (
    populate_sample_data,
    manage_elasticsearch_indices,
)


def handler(event, context):
    """
    Lambda handler to trigger syncdb.
    """
    # Set the Django settings module
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
    os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"

    # Initialize Django
    django.setup()

    # Parse arguments from the event
    dangerouslyforce = event.get("dangerouslyforce", False)
    populate = event.get("populate", False)

    try:
        # Step 1: Database Reset and Migration
        if dangerouslyforce:
            print("Dropping and recreating the database...")
            call_command("flush", "--noinput")
            call_command("migrate")  # Apply migrations
        else:
            print("Applying migrations...")
            call_command("migrate")  # Apply migrations

        # Step 2: Elasticsearch Index Management
        manage_elasticsearch_indices(dangerouslyforce)

        # Step 3: Populate Sample Data
        if populate:
            print("Populating the database with sample data...")
            populate_sample_data()
            print("Sample data population complete.")

        return {
            "statusCode": 200,
            "body": "Database synchronization completed successfully.",
        }
    except Exception as e:
        print(f"Error during syncdb: {str(e)}")
        return {
            "statusCode": 500,
            "body": f"Database synchronization failed: {str(e)}",
        }
