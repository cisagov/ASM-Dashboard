# Standard Python Libraries
import os

# Third-Party Libraries
import django
from django.core.management import call_command
from django.db import migrations, connection
from django.db.migrations.executor import MigrationExecutor

# Set the Django settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"

# Initialize Django
django.setup()

from xfd_api.tasks.syndb_helpers import manage_elasticsearch_indices, populate_sample_data


def handler(event, context):
    """
    Lambda handler to trigger syncdb.
    """

    # Parse arguments from the event
    dangerouslyforce = event.get("dangerouslyforce", False)
    populate = event.get("populate", False)

    try:
        # Drop and recreate the database if dangerouslyforce is true
        if dangerouslyforce:
            print("Dropping and recreating the database...")
            call_command("flush", "--noinput")

        # Generate and apply migrations dynamically
        print("Applying migrations dynamically...")
        apply_dynamic_migrations()

        # Elasticsearch Index Management
        manage_elasticsearch_indices(dangerouslyforce)

        # Populate Sample Data
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


def apply_dynamic_migrations():
    """
    Dynamically detect, create, and apply migrations without writing migration files.
    """
    connection.prepare_database()  # Ensure the database is initialized
    executor = MigrationExecutor(connection)

    # Get the current project state
    current_state = executor.loader.project_state()

    # Generate migration plans
    migration_plan = []
    for app_label in current_state.apps:
        app_models = current_state.apps.get_models(app_label=app_label)
        for model in app_models:
            # Generate migrations for each model in memory
            migration = migrations.CreateModel(
                name=model.__name__,
                fields=model._meta.fields,
                options=model._meta.options,
                bases=model._meta.parents,
            )
            migration_plan.append(migration)

    # Apply each migration dynamically
    for migration in migration_plan:
        print(f"Applying migration for model: {migration.name}")
        executor.apply_migration(migration)
        print(f"Migration applied: {migration.name}")

    print("Migrations applied successfully.")
