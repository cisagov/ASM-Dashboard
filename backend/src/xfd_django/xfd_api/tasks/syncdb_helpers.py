# File: xfd_api/utils/db_utils.py
import json
import os
import random
import hashlib
import secrets
from django.conf import settings
from django.db import transaction
from xfd_api.models import ApiKey, Domain, Organization, OrganizationTag, Service, Vulnerability, UserType, User
from xfd_api.tasks.es_client import ESClient
from datetime import datetime, timezone

# Constants for sample data generation
SAMPLE_TAG_NAME = "Sample Data"
NUM_SAMPLE_ORGS = 10
NUM_SAMPLE_DOMAINS = 10
PROB_SAMPLE_SERVICES = 0.5
PROB_SAMPLE_VULNERABILITIES = 0.5
SAMPLE_STATES = ["Virginia", "California", "Colorado"]
SAMPLE_REGION_IDS = ["1", "2", "3"]

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
        userId=user,
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
    domain_name = f"{random.choice(adjectives)}-{random.choice(nouns)}.crossfeed.local".lower()
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
            title="Sample Vulnerability",
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
