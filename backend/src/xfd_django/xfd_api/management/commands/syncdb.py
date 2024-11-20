# Standard Python Libraries
import json
import os
import random

# Third-Party Libraries
from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand
from xfd_api.tasks.es_client import ESClient
from xfd_api.tasks.syndb_helpers import manage_elasticsearch_indices, populate_sample_data

# Sample data and helper data for random generation
SAMPLE_TAG_NAME = "Sample Data"
NUM_SAMPLE_ORGS = 10
NUM_SAMPLE_DOMAINS = 10
PROB_SAMPLE_SERVICES = 0.5
PROB_SAMPLE_VULNERABILITIES = 0.5
SAMPLE_STATES = ["VA", "CA", "CO"]
SAMPLE_REGION_IDS = ["1", "2", "3"]

SAMPLE_DATA_DIR = os.path.join(settings.BASE_DIR, "xfd_api", "tasks", "sample_data")
services = json.load(open(os.path.join(SAMPLE_DATA_DIR, "services.json")))
cpes = json.load(open(os.path.join(SAMPLE_DATA_DIR, "cpes.json")))
vulnerabilities = json.load(open(os.path.join(SAMPLE_DATA_DIR, "vulnerabilities.json")))
cves = json.load(open(os.path.join(SAMPLE_DATA_DIR, "cves.json")))
nouns = json.load(open(os.path.join(SAMPLE_DATA_DIR, "nouns.json")))
adjectives = json.load(open(os.path.join(SAMPLE_DATA_DIR, "adjectives.json")))

# Initialize Elasticsearch client
es_client = ESClient()


class Command(BaseCommand):
    help = "Synchronizes and populates the database with optional sample data, and manages Elasticsearch indices."

    def add_arguments(self, parser):
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
        dangerouslyforce = options["dangerouslyforce"]
        populate = options["populate"]

        # Step 1: Database Reset and Migration
        if dangerouslyforce:
            self.stdout.write("Dropping and recreating the database...")
            call_command("flush", "--noinput")
            call_command("makemigrations")
            call_command("migrate")
        else:
            self.stdout.write("Applying migrations...")
            call_command("makemigrations")
            call_command("migrate")

        # Step 2: Elasticsearch Index Management
        manage_elasticsearch_indices(dangerouslyforce)

        # Step 3: Populate Sample Data
        if populate:
            self.stdout.write("Populating the database with sample data...")
            populate_sample_data()
            self.stdout.write("Sample data population complete.")
