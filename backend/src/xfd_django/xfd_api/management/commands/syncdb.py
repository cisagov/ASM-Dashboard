"""Populate command."""
# Third-Party Libraries
from django.core.management.base import BaseCommand
from xfd_api.tasks.searchSync import handler as sync_es_domains
from xfd_api.tasks.syncdb_helpers import (
    create_scan_user,
    drop_all_tables,
    manage_elasticsearch_indices,
    populate_sample_data,
    sync_es_organizations,
    synchronize,
)


class Command(BaseCommand):
    """Syncdb command."""

    help = "Synchronizes and populates the database with optional sample data, and manages Elasticsearch indices."

    def add_arguments(self, parser):
        """Add arguments."""
        parser.add_argument(
            "-d",
            "--dangerouslyforce",
            action="store_true",
            help="Force drop and recreate the database.",
        )
        parser.add_argument(
            "-p",
            "--populate",
            action="store_true",
            help="Populate the database with sample data.",
        )

    def handle(self, *args, **options):
        """Handle method."""
        dangerouslyforce = options["dangerouslyforce"]
        populate = options["populate"]

        # Step 1: Database Reset and Migration
        if dangerouslyforce:
            self.stdout.write("Dropping and recreating the database...")
            drop_all_tables(app_label="xfd_api")
            synchronize(target_app_label="xfd_api")
        else:
            self.stdout.write("Applying migrations...")
            synchronize(target_app_label="xfd_api")

        # Step 2: Elasticsearch Index Management
        manage_elasticsearch_indices(dangerouslyforce)

        # Step 3: Create the scanning user if doesn't exist
        self.stdout.write("Creating and configuring the scanning user...")
        create_scan_user()

        # Step 4: Populate Sample Data
        if populate:
            self.stdout.write("Populating the database with sample data...")
            populate_sample_data()
            self.stdout.write("Sample data population complete.")

            # Step 4: Sync organizations in ES
            sync_es_organizations()

            # Step 5: Sync domains in ES
            sync_es_domains({})
