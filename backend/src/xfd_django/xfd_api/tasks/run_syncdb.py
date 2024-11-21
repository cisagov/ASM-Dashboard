# Standard Python Libraries
import os

# Third-Party Libraries
import django

# Set the Django settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"

# Initialize Django
django.setup()

from xfd_api.tasks.syncdb_helpers import manage_elasticsearch_indices, populate_sample_data, drop_all_tables, synchronize, sync_es_organizations


def handler(event, context):
    """
    Lambda handler to trigger syncdb.
    """
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
        print(f"Error during syncdb: {str(e)}")
        return {
            "statusCode": 500,
            "body": f"Database synchronization failed: {str(e)}",
        }
