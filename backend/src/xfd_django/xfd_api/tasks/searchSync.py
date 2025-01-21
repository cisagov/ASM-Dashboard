"""Search sync."""
# Standard Python Libraries
from itertools import islice
import os

# Third-Party Libraries
from django.db.models import F, Q
from django.utils.timezone import now
from xfd_api.models import Domain

from .es_client import ESClient

# Constants
DOMAIN_CHUNK_SIZE = int(os.getenv("DOMAIN_CHUNK_SIZE", "50"))  # Adjust if needed


def chunked_queryset(queryset, chunk_size):
    """Chunk a queryset into smaller pieces."""
    it = iter(queryset.values_list("id", flat=True))  # Extract only IDs
    for first in it:
        yield [first] + list(islice(it, chunk_size - 1))


def handler(command_options):
    """Handle the synchronization of domains with Elasticsearch."""
    organization_id = command_options.get("organizationId")
    domain_id = command_options.get("domainId")

    print("Running searchSync...")
    client = ESClient()

    # Query to find domains that need to be synced
    domain_queryset = Domain.objects.annotate(
        should_sync=(
            Q(syncedAt__isnull=True)
            | Q(updatedAt__gt=F("syncedAt"))
            | Q(organization__updatedAt__gt=F("syncedAt"))
            | Q(vulnerabilities__updatedAt__gt=F("syncedAt"))
            | Q(services__updatedAt__gt=F("syncedAt"))
        )
    ).filter(should_sync=True, isFceb=True)

    # Additional filters for testing
    if organization_id:
        domain_queryset = domain_queryset.filter(organization_id=organization_id)
    if domain_id:
        domain_queryset = domain_queryset.filter(id=domain_id)

    print("Found {} domains to sync.".format(domain_queryset.count()))

    # Chunk domains for processing
    for domain_chunk in chunked_queryset(domain_queryset, DOMAIN_CHUNK_SIZE):
        domains = list(
            Domain.objects.filter(id__in=domain_chunk)
            .select_related("organization")
            .prefetch_related("vulnerabilities", "services")
        )
        print("Syncing {} domains...".format(len(domains)))

        # Update Elasticsearch
        try:
            client.update_domains(
                [
                    {
                        "id": str(domain.id),
                        "createdAt": domain.createdAt,
                        "updatedAt": domain.updatedAt,
                        "name": domain.name,
                        "reverseName": domain.reverseName,
                        "ip": domain.ip,
                        "fromRootDomain": domain.fromRootDomain,
                        "subdomainSource": domain.subdomainSource,
                        "ipOnly": domain.ipOnly,
                        "screenshot": domain.screenshot,
                        "country": domain.country,
                        "asn": domain.asn,
                        "cloudHosted": domain.cloudHosted,
                        "fromCidr": domain.fromCidr,
                        "isFceb": domain.isFceb,
                        "syncedAt": domain.syncedAt.isoformat()
                        if domain.syncedAt
                        else None,
                        "ssl": domain.ssl,
                        "censysCertificatesResults": domain.censysCertificatesResults,
                        "trustymailResults": domain.trustymailResults,
                        "organization": {
                            "id": str(domain.organization.id),
                            "name": domain.organization.name,
                            "acronym": domain.organization.acronym,
                            "rootDomains": domain.organization.rootDomains,
                            "ipBlocks": domain.organization.ipBlocks,
                            "isPassive": domain.organization.isPassive,
                            "country": domain.organization.country,
                            "state": domain.organization.state,
                            "regionId": domain.organization.regionId,
                            "stateFips": domain.organization.stateFips,
                            "stateName": domain.organization.stateName,
                            "county": domain.organization.county,
                            "countyFips": domain.organization.countyFips,
                            "type": domain.organization.type,
                            "parent": {
                                "id": str(domain.organization.parent.id)
                                if domain.organization.parent
                                else None,
                                "name": domain.organization.parent.name
                                if domain.organization.parent
                                else None,
                            }
                            if domain.organization.parent
                            else None,
                        },
                        "discoveredBy": {
                            "id": str(domain.discoveredBy.id)
                            if domain.discoveredBy
                            else None,
                            "name": domain.discoveredBy.name
                            if domain.discoveredBy
                            else None,
                            "arguments": domain.discoveredBy.arguments
                            if domain.discoveredBy
                            else None,
                        }
                        if domain.discoveredBy
                        else None,
                        "services": [
                            {
                                "id": str(service.id),
                                "port": service.port,
                                "service": service.service,
                                "lastSeen": service.lastSeen.isoformat()
                                if service.lastSeen
                                else None,
                                "products": service.products,
                                "censysMetadata": service.censysMetadata,
                            }
                            for service in domain.services.all()
                        ],
                        "vulnerabilities": [
                            {
                                "id": str(vulnerability.id),
                                "title": vulnerability.title,
                                "cvss": vulnerability.cvss,
                                "severity": vulnerability.severity,
                                "state": vulnerability.state,
                                "substate": vulnerability.substate,
                                "description": vulnerability.description,
                                "lastSeen": vulnerability.lastSeen.isoformat()
                                if vulnerability.lastSeen
                                else None,
                                "references": vulnerability.references,
                            }
                            for vulnerability in domain.vulnerabilities.all()
                        ],
                    }
                    for domain in domains
                ]
            )
        except Exception as e:
            print("Error syncing domains to Elasticsearch: {}".format(e))
            continue

        # Mark domains as synced
        Domain.objects.filter(id__in=[domain.id for domain in domains]).update(
            syncedAt=now()
        )

    print("Domain sync complete.")
