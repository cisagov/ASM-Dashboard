# Standard Python Libraries
import json
import os

# Third-Party Libraries
import django
from django.conf import settings
from django.db.models import CharField, Count, F, Value
from django.db.models.functions import Concat
import redis

# Set the Django settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"

# Initialize Django
django.setup()

# Third-Party Libraries
from xfd_api.helpers.stats_helpers import populate_stats_cache
from xfd_api.models import Service, Vulnerability


def populate_services_cache():
    return populate_stats_cache(
        model=Service,
        group_by_field="domain__organization_id",
        redis_key_prefix="services_stats",
        annotate_field="service",
        filters={
            "service__isnull": False,
            "domain__isnull": False,
            "domain__organization__isnull": False,
        },
    )


def populate_ports_cache():
    return populate_stats_cache(
        model=Service,
        group_by_field="domain__organization_id",
        redis_key_prefix="ports_stats",
        annotate_field="port",
        filters={
            "port__isnull": False,
            "domain__isnull": False,
            "domain__organization__isnull": False,
        },
    )


def populate_num_vulns_cache():
    return populate_stats_cache(
        model=Vulnerability,
        group_by_field="domain__organization_id",
        redis_key_prefix="vulnerabilities_stats",
        annotate_field="severity",
        custom_id=Concat(
            F("domain__name"),
            Value("|"),
            F("severity"),
            output_field=CharField(),
        ),
        filters={
            "state": "open",  # Include only open vulnerabilities
            "domain__isnull": False,
            "domain__organization__isnull": False,
        },
    )


def populate_latest_vulns_cache(max_results=100):
    """
    Populate Redis with the latest vulnerabilities for each organization.
    """
    try:
        # Connect to Redis
        redis_client = redis.StrictRedis(
            host=settings.ELASTICACHE_ENDPOINT,
            port=6379,
            db=0,
            decode_responses=True,
        )

        # Fetch and organize the latest vulnerabilities
        vulnerabilities = (
            Vulnerability.objects.filter(
                state="open",  # Only open vulnerabilities
                domain__isnull=False,
                domain__organization__isnull=False,
            )
            .select_related("domain", "domain__organization")
            .order_by("createdAt")[:max_results]
        )

        # Organize vulnerabilities by organization
        vulnerabilities_by_org = {}
        for vuln in vulnerabilities:
            org_id = str(vuln.domain.organization.id)  # Organization ID
            vuln_data = {
                "id": str(vuln.id),
                "createdAt": vuln.createdAt.isoformat(),
                "updatedAt": vuln.updatedAt.isoformat(),
                "lastSeen": vuln.lastSeen.isoformat() if vuln.lastSeen else None,
                "title": vuln.title,
                "cve": vuln.cve,
                "cwe": vuln.cwe,
                "cpe": vuln.cpe,
                "description": vuln.description,
                "references": vuln.references,
                "cvss": str(vuln.cvss) if vuln.cvss else None,
                "severity": vuln.severity,
                "needsPopulation": vuln.needsPopulation,
                "state": vuln.state,
                "substate": vuln.substate,
                "source": vuln.source,
                "notes": vuln.notes,
                "actions": vuln.actions,
                "structuredData": vuln.structuredData,
                "isKev": vuln.isKev,
                "kevResults": vuln.kevResults,
                "domain": {
                    "id": str(vuln.domain.id),
                    "createdAt": vuln.domain.createdAt.isoformat(),
                    "updatedAt": vuln.domain.updatedAt.isoformat(),
                    "syncedAt": vuln.domain.syncedAt.isoformat()
                    if vuln.domain.syncedAt
                    else None,
                    "ip": vuln.domain.ip,
                    "fromRootDomain": vuln.domain.fromRootDomain,
                    "subdomainSource": vuln.domain.subdomainSource,
                    "ipOnly": vuln.domain.ipOnly,
                    "reverseName": vuln.domain.reverseName,
                    "name": vuln.domain.name,
                    "screenshot": vuln.domain.screenshot,
                    "country": vuln.domain.country,
                    "asn": vuln.domain.asn,
                    "cloudHosted": vuln.domain.cloudHosted,
                    "fromCidr": vuln.domain.fromCidr,
                    "isFceb": vuln.domain.isFceb,
                    "ssl": vuln.domain.ssl,
                    "censysCertificatesResults": vuln.domain.censysCertificatesResults,
                    "trustymailResults": vuln.domain.trustymailResults,
                },
            }
            if org_id not in vulnerabilities_by_org:
                vulnerabilities_by_org[org_id] = []
            vulnerabilities_by_org[org_id].append(vuln_data)

        # Store each organization's vulnerabilities in Redis
        for org_id, data in vulnerabilities_by_org.items():
            redis_key = f"latest_vulnerabilities:{org_id}"
            redis_client.set(redis_key, json.dumps(data))

        return {
            "status": "success",
            "message": "Cache populated with the latest vulnerabilities successfully.",
        }

    except Exception as e:
        return {
            "status": "error",
            "message": f"An unexpected error occurred while populating the cache: {e}",
        }


def populate_most_common_vulns_cache(max_results=100):
    """
    Populate Redis with the most common vulnerabilities grouped by title, description, and severity.
    """
    try:
        # Connect to Redis
        redis_client = redis.StrictRedis(
            host=settings.ELASTICACHE_ENDPOINT,
            port=6379,
            db=0,
            decode_responses=True,
        )

        # Fetch and aggregate vulnerabilities
        vulnerabilities = (
            Vulnerability.objects.filter(
                state="open",  # Only open vulnerabilities
                domain__isnull=False,
                domain__organization__isnull=False,
            )
            .values("title", "description", "severity", "domain__organization_id")
            .annotate(count=Count("id"))
            .order_by("-count")[:max_results]
        )

        # Organize vulnerabilities by organization
        vulnerabilities_by_org = {}
        for vuln in vulnerabilities:
            org_id = str(vuln["domain__organization_id"])
            vuln_data = {
                "title": vuln["title"],
                "description": vuln["description"],
                "severity": vuln["severity"],
                "count": vuln["count"],
            }
            if org_id not in vulnerabilities_by_org:
                vulnerabilities_by_org[org_id] = []
            vulnerabilities_by_org[org_id].append(vuln_data)

        # Store each organization's vulnerabilities in Redis
        for org_id, data in vulnerabilities_by_org.items():
            redis_key = f"most_common_vulnerabilities:{org_id}"
            redis_client.set(redis_key, json.dumps(data))

        return {
            "status": "success",
            "message": "Cache populated with the most common vulnerabilities successfully.",
        }

    except Exception as e:
        return {
            "status": "error",
            "message": f"An unexpected error occurred while populating the cache: {e}",
        }


def populate_severity_cache():
    """
    Populate Redis with severity statistics for vulnerabilities.
    """
    return populate_stats_cache(
        model=Vulnerability,
        group_by_field="domain__organization_id",  # Group by severity
        redis_key_prefix="severity_stats",
        annotate_field="severity",  # Default field for counting occurrences
        filters={
            "state": "open",  # Include only open vulnerabilities
            "domain__isnull": False,
            "domain__organization__isnull": False,
        },
    )


def populate_by_org_cache():
    """
    Populate Redis with the count of open vulnerabilities grouped by organization.
    Each organization's data is stored under its own Redis key.
    """
    try:
        # Connect to Redis
        redis_client = redis.StrictRedis(
            host=settings.ELASTICACHE_ENDPOINT,
            port=6379,
            db=0,
            decode_responses=True,
        )

        # Fetch and aggregate vulnerabilities grouped by organization
        vulnerabilities = (
            Vulnerability.objects.filter(
                state="open",
                domain__isnull=False,
                domain__organization__isnull=False,
            )
            .values("domain__organization__id", "domain__organization__name")
            .annotate(value=Count("id"))
            .order_by("-value")
        )

        # Organize data and store in Redis
        for vuln in vulnerabilities:
            org_id = str(vuln["domain__organization__id"])
            org_name = vuln["domain__organization__name"]
            redis_key = f"by_org_stats:{org_id}"
            data = {
                "id": org_name,  # Organization name as "id"
                "orgId": org_id,  # Organization ID
                "value": vuln["value"],  # Count of vulnerabilities
                "label": org_name,  # Organization name as "label"
            }
            redis_client.set(redis_key, json.dumps(data))

        return {
            "status": "success",
            "message": "Cache populated for byOrg successfully.",
        }

    except Exception as e:
        return {
            "status": "error",
            "message": f"An unexpected error occurred while populating the cache: {e}",
        }
