"""Syncdb helpers."""
# File: xfd_api/utils/db_utils.py
# Standard Python Libraries
from datetime import datetime
import hashlib
from itertools import islice
import json
import os
import random
import secrets

# Third-Party Libraries
from django.apps import apps
from django.conf import settings
from django.db import connection, transaction
from django.db.backends.base.schema import BaseDatabaseSchemaEditor
from xfd_api.models import (
    ApiKey,
    Domain,
    Organization,
    OrganizationTag,
    Service,
    User,
    UserType,
    Vulnerability,
)
from xfd_api.tasks.es_client import ESClient

# Constants for sample data generation
SAMPLE_TAG_NAME = "Sample Data"
NUM_SAMPLE_ORGS = 10
NUM_SAMPLE_DOMAINS = 10
PROB_SAMPLE_SERVICES = 0.5
PROB_SAMPLE_VULNERABILITIES = 0.5
SAMPLE_STATES = ["Virginia", "California", "Colorado"]
SAMPLE_REGION_IDS = ["1", "2", "3"]
ORGANIZATION_CHUNK_SIZE = 50

# Load sample data files
SAMPLE_DATA_DIR = os.path.join(settings.BASE_DIR, "xfd_api", "tasks", "sample_data")
services = json.load(open(os.path.join(SAMPLE_DATA_DIR, "services.json")))
cpes = json.load(open(os.path.join(SAMPLE_DATA_DIR, "cpes.json")))
vulnerabilities = json.load(open(os.path.join(SAMPLE_DATA_DIR, "vulnerabilities.json")))
cves = json.load(open(os.path.join(SAMPLE_DATA_DIR, "cves.json")))
nouns = json.load(open(os.path.join(SAMPLE_DATA_DIR, "nouns.json")))
adjectives = json.load(open(os.path.join(SAMPLE_DATA_DIR, "adjectives.json")))

# Elasticsearch client
es_client = ESClient()


def manage_elasticsearch_indices(dangerouslyforce):
    """Handle Elasticsearch index setup and teardown."""
    try:
        if dangerouslyforce:
            es_client.delete_all()
        es_client.sync_organizations_index()
        es_client.sync_domains_index()
        print("Elasticsearch indices synchronized.")
    except Exception as e:
        print(f"Error managing Elasticsearch indices: {e}")


def populate_sample_data():
    """Populate sample data into the database."""
    with transaction.atomic():
        tag, _ = OrganizationTag.objects.get_or_create(name=SAMPLE_TAG_NAME)
        for _ in range(NUM_SAMPLE_ORGS):
            # Create organization
            org = Organization.objects.create(
                acronym="".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=5)),
                name=generate_random_name(),
                rootDomains=["crossfeed.local"],
                ipBlocks=[],
                isPassive=False,
                state=random.choice(SAMPLE_STATES),
                regionId=random.choice(SAMPLE_REGION_IDS),
            )
            org.tags.add(tag)

            # Create sample domains, services, and vulnerabilities
            for _ in range(NUM_SAMPLE_DOMAINS):
                domain = create_sample_domain(org)
                create_sample_services_and_vulnerabilities(domain)

        # Create a user for the organization
        user = create_sample_user(org)

        # Create an API key for the user
        create_api_key_for_user(user)


def create_sample_user(organization):
    """Create a sample user linked to an organization."""
    user = User.objects.create(
        firstName="Sample",
        lastName="User",
        email=f"user{random.randint(1, 1000)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        state=random.choice(SAMPLE_STATES),
        regionId=random.choice(SAMPLE_REGION_IDS),
    )
    # Set user as the creator of the organization (optional)
    organization.createdBy = user
    organization.save()
    return user


def create_api_key_for_user(user):
    """Create a sample API key linked to a user."""
    # Generate a random 16-byte API key
    key = secrets.token_hex(16)

    # Hash the API key
    hashed_key = hashlib.sha256(key.encode()).hexdigest()

    # Create the API key record
    ApiKey.objects.create(
        hashedKey=hashed_key,
        lastFour=key[-4:],
        user=user,
        createdAt=datetime.utcnow(),
        updatedAt=datetime.utcnow(),
    )

    # Print the raw key for debugging or manual testing
    print(f"Created API key for user {user.email}: {key}")


def generate_random_name():
    """Generate a random organization name using an adjective and entity noun."""
    adjective = random.choice(adjectives)
    noun = random.choice(nouns)
    entity = random.choice(["City", "County", "Agency", "Department"])
    return f"{adjective.capitalize()} {entity} {noun.capitalize()}"


def create_sample_domain(organization):
    """Create a sample domain linked to an organization."""
    domain_name = (
        f"{random.choice(adjectives)}-{random.choice(nouns)}.crossfeed.local".lower()
    )
    ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
    return Domain.objects.create(
        name=domain_name,
        ip=ip,
        fromRootDomain="crossfeed.local",
        isFceb=True,
        subdomainSource="findomain",
        organization=organization,
    )


def create_sample_services_and_vulnerabilities(domain):
    """Create sample services and vulnerabilities for a domain."""
    # Add random services
    if random.random() < PROB_SAMPLE_SERVICES:
        Service.objects.create(
            domain=domain,
            port=random.choice([80, 443]),
            service="http",
            serviceSource="shodan",
            wappalyzerResults=[
                {"technology": {"cpe": random.choice(cpes)}, "version": ""}
            ],
        )

    # Add random vulnerabilities
    if random.random() < PROB_SAMPLE_VULNERABILITIES:
        Vulnerability.objects.create(
            title="Sample Vulnerability "
            + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=3)),
            domain=domain,
            service=None,
            description="Sample description",
            severity=random.choice(["Low", "Medium", "High"]),
            needsPopulation=True,
            state="open",
            substate="unconfirmed",
            source="sample_source",
            actions=[],
            structuredData={},
        )


def synchronize():
    """
    Synchronize the database schema with Django models.

    Handles creation, update, and removal of tables and fields dynamically,
    including Many-to-Many linking tables.
    """
    print("Synchronizing database schema with models...")
    with connection.cursor() as cursor:
        with connection.schema_editor() as schema_editor:
            # Step 1: Process models in dependency order
            ordered_models = get_ordered_models(apps)
            for model in ordered_models:
                print(f"Processing model: {model.__name__}")
                process_model(schema_editor, cursor, model)

            # Step 2: Handle Many-to-Many tables
            print("Processing Many-to-Many tables...")
            process_m2m_tables(schema_editor, cursor)

            # Step 3: Cleanup stale tables
            cleanup_stale_tables(cursor)
    print("Database synchronization complete.")


def get_ordered_models(apps):
    """
    Get models in dependency order to ensure foreign key constraints are respected.

    Handles circular dependencies gracefully by breaking cycles.
    """
    # Standard Python Libraries
    from collections import defaultdict, deque

    dependencies = defaultdict(set)
    dependents = defaultdict(set)
    models = list(apps.get_models())

    for model in models:
        for field in model._meta.get_fields():
            if field.is_relation and field.related_model:
                dependencies[model].add(field.related_model)
                dependents[field.related_model].add(model)

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


def process_model(schema_editor: BaseDatabaseSchemaEditor, cursor, model):
    """Process a single model: create or update its table."""
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


def process_m2m_tables(schema_editor: BaseDatabaseSchemaEditor, cursor):
    """Handle creation of Many-to-Many linking tables."""
    for model in apps.get_models():
        for field in model._meta.local_many_to_many:
            m2m_table_name = field.m2m_db_table()

            # Check if the M2M table exists
            cursor.execute(f"SELECT to_regclass('{m2m_table_name}');")
            table_exists = cursor.fetchone()[0] is not None

            if not table_exists:
                print(f"Creating Many-to-Many table: {m2m_table_name}")
                schema_editor.create_model(field.remote_field.through)
            else:
                print(f"Many-to-Many table {m2m_table_name} already exists. Skipping.")


def update_table(schema_editor: BaseDatabaseSchemaEditor, model):
    """Update an existing table for the given model. Ensure columns match fields."""
    table_name = model._meta.db_table
    db_fields = {field.column for field in model._meta.fields}

    with connection.cursor() as cursor:
        # Get existing columns
        cursor.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = %s;",
            [table_name],  # Pass the table name as a parameter
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
                cursor.execute(
                    f"ALTER TABLE {table_name} DROP COLUMN IF EXISTS {column};"
                )
            except Exception as e:
                print(
                    f"Error dropping column '{column}' from table '{table_name}': {e}"
                )


def cleanup_stale_tables(cursor):
    """Remove tables that no longer correspond to any Django model or Many-to-Many relationship."""
    print("Checking for stale tables...")
    model_tables = {model._meta.db_table for model in apps.get_models()}
    m2m_tables = {
        field.m2m_db_table()
        for model in apps.get_models()
        for field in model._meta.local_many_to_many
    }
    expected_tables = model_tables.union(m2m_tables)

    cursor.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public';")
    existing_tables = {row[0] for row in cursor.fetchall()}

    stale_tables = existing_tables - expected_tables
    for table in stale_tables:
        print(f"Removing stale table: {table}")
        try:
            cursor.execute(f"DROP TABLE {table} CASCADE;")
        except Exception as e:
            print(f"Error dropping stale table {table}: {e}")


def drop_all_tables():
    """Drop all tables in the database. Used with `dangerouslyforce`."""
    with connection.cursor() as cursor:
        cursor.execute(
            """
            DO $$ DECLARE
                r RECORD;
            BEGIN
                FOR r IN (
                    SELECT tablename
                    FROM pg_tables
                    WHERE schemaname = 'public'
                ) LOOP
                    EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE';
                END LOOP;
            END $$;
            """
        )
    print("All tables dropped successfully.")


def chunked_iterable(iterable, size):
    """Chunk an iterable."""
    iterator = iter(iterable)
    for first in iterator:
        yield list(islice([first] + list(iterator), size - 1))


def update_organization_chunk(es_client, organizations):
    """Update a chunk of organizations."""
    es_client.update_organizations(organizations)


def sync_es_organizations():
    """Sync elastic search organizations."""
    try:
        # Fetch all organization IDs
        organization_ids = list(Organization.objects.values_list("id", flat=True))
        print(f"Found {len(organization_ids)} organizations to sync.")

        if organization_ids:
            # Split IDs into chunks
            for organization_chunk in chunked_iterable(
                organization_ids, ORGANIZATION_CHUNK_SIZE
            ):
                # Fetch full organization data for the current chunk
                organizations = list(
                    Organization.objects.filter(id__in=organization_chunk).values(
                        "id", "name", "country", "state", "regionId", "tags"
                    )
                )
                print(f"Syncing {len(organizations)} organizations...")

                # Attempt to update Elasticsearch
                update_organization_chunk(es_client, organizations)

            print("Organization sync complete.")
        else:
            print("No organizations to sync.")

    except Exception as e:
        print(f"Error syncing organizations: {e}")
        raise e
