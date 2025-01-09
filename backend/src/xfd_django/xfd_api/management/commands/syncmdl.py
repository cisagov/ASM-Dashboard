"""Populate command."""
# Standard Python Libraries
import os

# Third-Party Libraries
from django.core.management.base import BaseCommand
from django.db import connections
from xfd_api.tasks.syncdb_helpers import drop_all_tables, synchronize


class Command(BaseCommand):
    """Syncmdl command."""

    help = "Synchronizes the MDL with optional sample data, and manages Elasticsearch indices."

    def add_arguments(self, parser):
        """Add arguments."""
        parser.add_argument(
            "-d",
            "--dangerouslyforce",
            action="store_true",
            help="Force drop and recreate the database.",
        )

    def handle(self, *args, **options):
        """Handle method."""
        dangerouslyforce = options["dangerouslyforce"]

        mdl_username = os.getenv("MDL_USERNAME")
        mdl_password = os.getenv("MDL_PASSWORD")
        mdl_name = os.getenv("MDL_NAME")

        if not (mdl_username and mdl_password and mdl_name):
            self.stderr.write(
                "Error: MDL_USERNAME, MDL_PASSWORD, and MDL_NAME must be set in the environment."
            )
            return

        connection = connections["default"]

        # Step 1: Database User and Database Setup
        self.stdout.write("Setting up the MDL database and user...")

        with connection.cursor() as cursor:
            try:
                cursor.execute(
                    f"CREATE USER {mdl_username} WITH PASSWORD '{mdl_password}';"
                )
            except Exception as e:
                self.stdout.write(f"User creation failed (likely already exists): {e}")

            try:
                cursor.execute(f"GRANT {mdl_username} TO {os.getenv('DB_USERNAME')};")
            except Exception as e:
                self.stdout.write(f"Granting role failed: {e}")

            try:
                cursor.execute(f"CREATE DATABASE {mdl_name} OWNER {mdl_username};")
            except Exception as e:
                self.stdout.write(
                    f"Database creation failed (likely already exists): {e}"
                )

            try:
                cursor.execute(
                    f"GRANT ALL PRIVILEGES ON DATABASE {mdl_name} TO {mdl_username};"
                )
            except Exception as e:
                self.stdout.write(f"Granting privileges failed: {e}")

        # Step 2: Synchronize or Reset the Database
        self.stdout.write("Synchronizing the MDL database schema...")
        if dangerouslyforce:
            self.stdout.write("Dropping and recreating the database...")
            drop_all_tables(app_label="xfd_mini_dl")
        synchronize(target_app_label="xfd_mini_dl")

        self.stdout.write("Database synchronization complete.")
