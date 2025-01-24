"""Run syncdb."""
# Standard Python Libraries
import os

# Third-Party Libraries
import django

# Set the Django settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"

# Initialize Django
django.setup()

# Third-Party Libraries
from xfd_api.tasks.syncdb_helpers import (
    drop_all_tables,
    manage_elasticsearch_indices,
    populate_sample_data,
    sync_es_organizations,
    synchronize,
)


def handler(event, context):
    """Trigger syncdb."""
    dangerouslyforce = event.get("dangerouslyforce", False)
    populate = event.get("populate", False)

    try:
        # Drop and recreate the database if dangerouslyforce is true
        if dangerouslyforce:
            print("Dropping and recreating the database...")
            drop_all_tables()

        # Generate and apply migrations dynamically
        print("Applying migrations dynamically...")
        synchronize()

        # Elasticsearch Index Management
        manage_elasticsearch_indices(dangerouslyforce)

        # Populate Sample Data
        if populate:
            print("Populating the database with sample data...")
            populate_sample_data()
            print("Sample data population complete.")

        # Step 4: Sync organizations in ES

        sync_es_organizations()

        return {
            "statusCode": 200,
            "body": "Database synchronization completed successfully.",
        }
    except Exception as e:
        print("Error during syncdb: {}".format(str(e)))
        return {
            "statusCode": 500,
            "body": "Database synchronization failed: {}".format(str(e)),
        }
