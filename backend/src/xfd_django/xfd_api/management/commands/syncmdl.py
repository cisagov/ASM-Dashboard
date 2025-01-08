"""Populate command."""
# Third-Party Libraries
from django.core.management.base import BaseCommand
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

        # Step 1: Database Reset and Migration
        if dangerouslyforce:
            self.stdout.write("Dropping and recreating the database...")
            drop_all_tables(app_label="xfd_mini_dl")
            synchronize(target_app_label="xfd_mini_dl")
        # else:
        self.stdout.write("Applying migrations...")
        synchronize(target_app_label="xfd_mini_dl")
