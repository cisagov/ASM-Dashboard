# Standard Python Libraries
import json

# Third-Party Libraries
import django
from django.conf import settings
from django.db.models import CharField, Count, F, Value
from django.db.models.functions import Concat
import redis

from .models import Service, Vulnerability


def populate_ServicesStatscache():
    try:
        # Connect to Redis ElastiCache
        redis_client = redis.StrictRedis(
            host=settings.ELASTICACHE_ENDPOINT,
            port=6379,
            db=0,
            decode_responses=True,  # Ensures data returned as string, not bytes
        )

        # Fetch and aggregate data from Django models
        services = (
            Service.objects.filter(service__isnull=False)
            .exclude(service="")
            .filter(domainId__isnull=False)
            .filter(domainId__organizationId__isnull=False)
            .values("service")
            .annotate(value=Count("id"))
            .order_by("-value")
        )

        services_list = list(services)

        # **Debugging statements**
        print(f"Number of services retrieved: {len(services_list)}")
        if services_list:
            print(f"First service entry: {services_list[0]}")

        # Adjust the data to have 'id' and 'value' keys
        services_data = [
            {"id": item["service"], "value": item["value"]} for item in services_list
        ]

        # Serialize the data to JSON
        services_json = json.dumps(services_data)

        # Store the data under a single key in Redis
        redis_client.set("services_stats", services_json)

        return {
            "status": "success",
            "message": "Cache populated services successfully.",
        }

    except Exception as e:
        print(f"An error occurred: {e}")
        return {
            "status": "error",
            "message": f"An unexpected error occurred while populating the cache: {e}",
        }


def populate_PortsStatscache():
    # Connect to Redis Elasticache
    try:
        # Connect to Redis Elasticache
        redis_client = redis.StrictRedis(
            host=settings.ELASTICACHE_ENDPOINT,
            port=6379,
            db=0,
            decode_responses=True,  # Ensures data returned as string, not bytes
        )

        # Fetch data from Django models
        ports = (
            Service.objects.filter(domainId__organizationId__isnull=False)
            .values("port")
            .annotate(value=Count("id"))
            .order_by("-value")
        )

        # Convert queryset to list
        ports_list = list(ports)

        # Serialize the data to JSON
        ports_json = json.dumps(ports_list)

        # Store the data under a single key in Redis
        redis_client.set("ports_stats", ports_json)

        return {"status": "success", "message": "Cache populated ports successfully."}

    except redis.RedisError as redis_error:
        return {
            "status": "error",
            "message": f"Failed to populate cache due to Redis error: {redis_error}",
        }

    except django.db.DatabaseError as db_error:
        return {
            "status": "error",
            "message": f"Failed to populate cache due to database error: {db_error}",
        }

    except Exception as e:
        return {
            "status": "error",
            "message": f"An unexpected error occurred while populating the cache: {e}",
        }


def populate_NumVulnerabilitiesStatscache(event=None, context=None):
    # Connect to Redis ElastiCache
    redis_client = redis.StrictRedis(
        host=settings.ELASTICACHE_ENDPOINT,
        port=6379,
        db=0,
        decode_responses=True,  # Automatically decode responses as UTF-8 strings
    )

    try:
        # Fetch data from Django models
        MAX_RESULTS = 100  # Replace with your desired maximum number of results

        num_vulnerabilities = (
            Vulnerability.objects.filter(
                state="open",
                domainId__isnull=False,  # Ensures the vulnerability is linked to a domain
            )
            .annotate(
                composite_id=Concat(
                    F("domainId__name"),
                    Value("|"),
                    F("severity"),
                    output_field=CharField(),
                )
            )
            .values("composite_id")
            .annotate(value=Count("id"))
            .order_by("-value")[:MAX_RESULTS]
        )

        # Prepare data for Redis
        vulnerabilities_stats = {
            item["composite_id"]: str(item["value"]) for item in num_vulnerabilities
        }

        # Use a Redis hash to store all vulnerability stats under a single key
        redis_client.hset("num_vulnerabilities_stats", mapping=vulnerabilities_stats)

        return {"status": "success", "message": "Cache populated successfully."}

    except Exception as e:
        # Handle exceptions gracefully
        return {"status": "error", "message": f"An error occurred: {e}"}


def populate_LatestVulnerabilitiesCache():
    # Connect to Redis ElastiCache
    redis_client = redis.StrictRedis(
        host=settings.ELASTICACHE_ENDPOINT, port=6379, db=0, decode_responses=True
    )

    try:
        MAX_RESULTS = 100  # Adjust as needed

        latest_vulnerabilities = (
            Vulnerability.objects.filter(state="open")
            .select_related("domainId__organizationId")
            .order_by("createdAt")[:MAX_RESULTS]
        )

        # Prepare data for Redis
        vulnerabilities_data = []
        for vuln in latest_vulnerabilities:
            vulnerabilities_data.append(
                {
                    "id": str(vuln.id),
                    "title": vuln.title,
                    "state": vuln.state,
                    "createdAt": vuln.createdAt.isoformat(),
                    "domain": vuln.domainId.name if vuln.domainId else None,
                    "organizationId": str(vuln.domainId.organizationId.id)
                    if vuln.domainId and vuln.domainId.organizationId
                    else None,
                    # Include other fields as needed
                }
            )

        # Serialize data to JSON
        vulnerabilities_json = json.dumps(vulnerabilities_data)

        # Store data in Redis
        redis_client.set("latest_vulnerabilities", vulnerabilities_json)

        return {"status": "success", "message": "Cache populated successfully."}

    except Exception as e:
        # Handle exceptions gracefully
        return {"status": "error", "message": f"An error occurred: {e}"}


def populate_MostCommonVulnerabilitiesCache():
    redis_client = redis.StrictRedis(
        host=settings.ELASTICACHE_ENDPOINT, port=6379, db=0, decode_responses=True
    )

    try:
        MAX_RESULTS = 100  # Adjust as needed

        # Retrieve vulnerabilities with related domain and organization information
        most_common_vulnerabilities = (
            Vulnerability.objects.filter(state="open")
            .select_related("domainId__organizationId")
            .values(
                "title",
                "description",
                "severity",
                "domainId__name",
                "domainId__organizationId__id",
            )
            .annotate(count=Count("id"))
            .order_by("-count")[:MAX_RESULTS]
        )

        # Convert QuerySet to a list
        vulnerabilities_data = list(most_common_vulnerabilities)

        # Rename fields for consistency and clarity
        for vuln in vulnerabilities_data:
            vuln["domain"] = vuln.pop("domainId__name", None)
            vuln["organizationId"] = str(vuln.pop("domainId__organizationId__id", None))

        # Serialize data to JSON
        vulnerabilities_json = json.dumps(vulnerabilities_data)

        # Store data in Redis
        redis_client.set("most_common_vulnerabilities", vulnerabilities_json)

        return {"status": "success", "message": "Cache populated successfully."}
    except Exception as e:
        return {"status": "error", "message": f"An error occurred: {e}"}


def populate_SeverityCountsCache():
    """
    Fetches the count of open vulnerabilities grouped by severity and stores the data in Redis.
    """
    # Connect to Redis ElastiCache
    redis_client = redis.StrictRedis(
        host=settings.ELASTICACHE_ENDPOINT,
        port=6379,
        db=0,
        decode_responses=True,  # Automatically decode responses as UTF-8 strings
    )

    try:
        vulnerabilities = (
            Vulnerability.objects.filter(state="open")
            .select_related("domainId__organizationId")
            .values("id", "severity", "domainId__organizationId__id")
        )

        # Transform the QuerySet to a list of dictionaries
        data = [
            {
                "id": str(item["id"]),
                "severity": item["severity"],
                "organizationId": str(item["domainId__organizationId__id"]),
            }
            for item in vulnerabilities
        ]

        # Serialize data to JSON
        vulnerabilities_json = json.dumps(data)

        # Store data in Redis under the key 'vulnerabilities_data'
        redis_client.set("vulnerabilities_data", vulnerabilities_json)

        return {
            "status": "success",
            "message": "Vulnerabilities cache populated successfully.",
        }
    except Exception as e:
        return {"status": "error", "message": f"An error occurred: {e}"}


def populate_VulnerabilitiesByOrgCache():
    """
    Fetches open vulnerabilities with organization information and stores them in Redis.
    """
    redis_client = redis.StrictRedis(
        host=settings.ELASTICACHE_ENDPOINT, port=6379, db=0, decode_responses=True
    )

    try:
        # Fetch vulnerabilities with related organization data
        vulnerabilities = (
            Vulnerability.objects.filter(state="open")
            .select_related("domainId__organizationId")
            .values(
                "id",
                "domainId__organizationId__id",
                "domainId__organizationId__name",
            )
        )

        # Convert QuerySet to list of dictionaries
        data = [
            {
                "vulnerabilityId": str(item["id"]),
                "orgId": str(item["domainId__organizationId__id"]),
                "orgName": item["domainId__organizationId__name"],
            }
            for item in vulnerabilities
        ]

        # Serialize data to JSON
        json_data = json.dumps(data)

        # Store data in Redis under the key 'vulnerabilities_by_org'
        redis_client.set("vulnerabilities_by_org", json_data)

        return {"status": "success", "message": "Cache populated successfully."}
    except Exception as e:
        return {"status": "error", "message": f"An error occurred: {e}"}

    # '''I need to create filterQuery to apply to the few endpoints that require it'''


def populate_ByOrgCache():
    """
    Fetches the count of open vulnerabilities grouped by organization and stores the data in Redis.
    """
    # Connect to Redis ElastiCache
    redis_client = redis.StrictRedis(
        host=settings.ELASTICACHE_ENDPOINT,
        port=6379,
        db=0,
        decode_responses=True,  # To automatically decode responses as UTF-8 strings
    )

    try:
        # Execute the Django ORM query
        by_org = (
            Vulnerability.objects.filter(state="open")
            .values(
                id=F("domainId__organizationId__name"),
                orgId=F("domainId__organizationId__id"),
            )
            .annotate(
                value=Count("id"),
            )
            .order_by("-value")
        )

        # Convert QuerySet to a list of dictionaries
        data = list(by_org)

        # Add 'label' field (same as 'id') and ensure data types
        for item in data:
            item["id"] = str(item["id"])
            item["orgId"] = str(item["orgId"])
            item["value"] = int(item["value"])
            item["label"] = item["id"]

        # Serialize data to JSON
        json_data = json.dumps(data)

        # Store data in Redis under the key 'by_org'
        redis_client.set("by_org", json_data)

        return {"status": "success", "message": "ByOrg cache populated successfully."}
    except Exception as e:
        # Handle exceptions gracefully
        return {"status": "error", "message": f"An error occurred: {e}"}
