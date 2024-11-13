import os
import json
import random
from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.conf import settings
from django.db import transaction
from xfd_api.models import Organization, Domain, Service, Vulnerability, OrganizationTag
from xfd_api.tasks.es_client import ESClient

# Sample data and helper data for random generation
SAMPLE_TAG_NAME = 'Sample Data'
NUM_SAMPLE_ORGS = 10
NUM_SAMPLE_DOMAINS = 10
PROB_SAMPLE_SERVICES = 0.5
PROB_SAMPLE_VULNERABILITIES = 0.5
SAMPLE_STATES = ['VA', 'CA', 'CO']
SAMPLE_REGION_IDS = ['1', '2', '3']

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
        parser.add_argument('-d', '--dangerouslyforce', action='store_true', help='Force drop and recreate the database.')
        parser.add_argument('-p', '--populate', action='store_true', help='Populate the database with sample data.')

    def handle(self, *args, **options):
        dangerouslyforce = options['dangerouslyforce']
        populate = options['populate']

        # Step 1: Database Reset and Migration
        if dangerouslyforce:
            self.stdout.write("Dropping and recreating the database...")
            call_command('flush', '--noinput')
            call_command('makemigrations')
            call_command('migrate')
        else:
            self.stdout.write("Applying migrations...")
            call_command('makemigrations')
            call_command('migrate')

        # Step 2: Elasticsearch Index Management
        self.manage_elasticsearch_indices(dangerouslyforce)

        # Step 3: Populate Sample Data
        if populate:
            self.stdout.write("Populating the database with sample data...")
            self.populate_sample_data()
            self.stdout.write("Sample data population complete.")

    def manage_elasticsearch_indices(self, dangerouslyforce):
        """Handle Elasticsearch index setup and teardown."""
        try:
            if dangerouslyforce:
                es_client.delete_all()
            es_client.sync_organizations_index()
            es_client.sync_domains_index()
            self.stdout.write("Elasticsearch indices synchronized.")
        except Exception as e:
            self.stdout.write(f"Error managing Elasticsearch indices: {e}")

    def populate_sample_data(self):
        """Populate sample data into the database."""
        with transaction.atomic():
            tag, _ = OrganizationTag.objects.get_or_create(name=SAMPLE_TAG_NAME)
            for _ in range(NUM_SAMPLE_ORGS):
                org = Organization.objects.create(
                    acronym=''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=5)),
                    name=self.generate_random_name(),
                    rootDomains=["crossfeed.local"],
                    ipBlocks=[],
                    isPassive=False,
                    state=random.choice(SAMPLE_STATES),
                    regionId=random.choice(SAMPLE_REGION_IDS),
                )
                org.tags.add(tag)

                for _ in range(NUM_SAMPLE_DOMAINS):
                    domain = self.create_sample_domain(org)
                    self.create_sample_services_and_vulnerabilities(domain)

    def generate_random_name(self):
        """Generate a random organization name using an adjective and entity noun."""
        adjective = random.choice(adjectives)
        noun = random.choice(nouns)
        entity = random.choice(["City", "County", "Agency", "Department"])
        return f"{adjective.capitalize()} {entity} {noun.capitalize()}"

    def create_sample_domain(self, organization):
        """Create a sample domain linked to an organization."""
        domain_name = f"{random.choice(adjectives)}-{random.choice(nouns)}.crossfeed.local".lower()
        ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        return Domain.objects.create(
            name=domain_name,
            ip=ip,
            fromRootDomain="crossfeed.local",
            isFceb=True,
            subdomainSource="findomain",
            organization=organization
        )

    def create_sample_services_and_vulnerabilities(self, domain):
        """Create sample services and vulnerabilities for a domain."""
        # Add random services
        if random.random() < PROB_SAMPLE_SERVICES:
            Service.objects.create(
                domain=domain,
                port=random.choice([80, 443]),
                service="http",
                serviceSource="shodan",
                wappalyzerResults=[{
                    "technology": {"cpe": random.choice(cpes)},
                    "version": ""
                }]
            )

        # Add random vulnerabilities
        if random.random() < PROB_SAMPLE_VULNERABILITIES:
            Vulnerability.objects.create(
                title="Sample Vulnerability",
                domain=domain,
                service=None,
                description="Sample description",
                severity=random.choice(['Low', 'Medium', 'High']),
                needsPopulation=True,  # Ensuring required fields are populated
                state="open",
                substate="unconfirmed",
                source="sample_source",
                actions=[],
                structuredData={}
            )