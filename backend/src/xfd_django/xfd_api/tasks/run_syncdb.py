# Standard Python Libraries
import os

# Third-Party Libraries
import django
from django.core.management import call_command
from django.db import connection
from django.apps import apps
from django.db.backends.base.schema import BaseDatabaseSchemaEditor


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
        synchronize()

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

def get_ordered_models(apps):
    """
    Get models in dependency order to ensure foreign key constraints are respected.
    Handles circular dependencies gracefully by breaking cycles.
    """
    from collections import defaultdict, deque

    # Build dependency graph
    dependencies = defaultdict(set)
    dependents = defaultdict(set)
    models = list(apps.get_models())

    for model in models:
        for field in model._meta.get_fields():
            if field.is_relation and field.related_model:
                dependencies[model].add(field.related_model)
                dependents[field.related_model].add(model)

    # Resolve dependencies using Kahn's Algorithm
    ordered = []
    independent_models = deque(model for model in models if not dependencies[model])

    while independent_models:
        model = independent_models.popleft()
        ordered.append(model)
        for dependent in list(dependents[model]):
            dependencies[dependent].remove(model)
            dependents[model].remove(dependent)
            if not dependencies[dependent]:
                independent_models.append(dependent)

    # Handle circular dependencies
    if any(dependencies.values()):
        print("Circular dependencies detected. Breaking cycles arbitrarily.")
        for model, deps in dependencies.items():
            if deps:
                print(f"Breaking dependency for model: {model.__name__}")
                dependencies[model] = set()

        ordered.extend(dependencies.keys())

    return ordered


def synchronize():
    """
    Synchronize the database schema with Django models.
    Handles creation, update, and removal of tables and fields dynamically.
    """
    print("Synchronizing database schema with models...")
    with connection.cursor() as cursor:
        with connection.schema_editor() as schema_editor:
            # Step 1: Process models in dependency order
            ordered_models = get_ordered_models(apps)
            for model in ordered_models:
                print(f"Processing model: {model.__name__}")
                process_model(schema_editor, cursor, model)

            # Step 2: Cleanup stale tables
            cleanup_stale_tables(cursor)
    print("Database synchronization complete.")


def process_model(schema_editor: BaseDatabaseSchemaEditor, cursor, model):
    """
    Process a single model: create or update its table.
    """
    table_name = model._meta.db_table

    # Check if the table exists
    cursor.execute(f"SELECT to_regclass('{table_name}');")
    table_exists = cursor.fetchone()[0] is not None

    if table_exists:
        print(f"Updating table for model: {model.__name__}")
        update_table(schema_editor, model)
    else:
        print(f"Creating table for model: {model.__name__}")
        schema_editor.create_model(model)


def update_table(schema_editor: BaseDatabaseSchemaEditor, model):
    """
    Update an existing table for the given model. Ensure columns match fields.
    """
    table_name = model._meta.db_table
    db_fields = {field.column for field in model._meta.fields}

    with connection.cursor() as cursor:
        # Get existing columns
        cursor.execute(
            f"SELECT column_name FROM information_schema.columns WHERE table_name = '{table_name}';"
        )
        existing_columns = {row[0] for row in cursor.fetchall()}

        # Add missing columns
        missing_columns = db_fields - existing_columns
        for field in model._meta.fields:
            if field.column in missing_columns:
                print(f"Adding column '{field.column}' to table '{table_name}'")
                schema_editor.add_field(model, field)

        # Remove extra columns
        extra_columns = existing_columns - db_fields
        for column in extra_columns:
            print(f"Removing extra column '{column}' from table '{table_name}'")
            try:
                cursor.execute(f"ALTER TABLE {table_name} DROP COLUMN IF EXISTS {column};")
            except Exception as e:
                print(f"Error dropping column '{column}' from table '{table_name}': {e}")


def cleanup_stale_tables(cursor):
    """
    Remove tables that no longer correspond to any Django model.
    """
    print("Checking for stale tables...")
    model_tables = {model._meta.db_table for model in apps.get_models()}
    cursor.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public';")
    existing_tables = {row[0] for row in cursor.fetchall()}

    stale_tables = existing_tables - model_tables
    for table in stale_tables:
        print(f"Removing stale table: {table}")
        cursor.execute(f"DROP TABLE {table} CASCADE;")
