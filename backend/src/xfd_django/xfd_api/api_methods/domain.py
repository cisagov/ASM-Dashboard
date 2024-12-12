"""
Domain API.

"""

# Standard Python Libraries
import csv

# Third-Party Libraries
from django.core.exceptions import ObjectDoesNotExist
from django.core.paginator import Paginator
from django.db.models import Prefetch, Q
from django.http import Http404
from fastapi import HTTPException

from ..auth import get_org_memberships, get_user_organization_ids, is_global_view_admin
from ..helpers.filter_helpers import filter_domains, sort_direction
from ..models import Domain, Service
from ..schema_models.domain import DomainFilters, DomainSearch


def get_domain_by_id(domain_id: str):
    """
    Get domain by id.
    Returns:
        object: a single Domain object.
    """
    try:
        domain = (
            Domain.objects.select_related("organization")
            .prefetch_related(
                "vulnerabilities",
                Prefetch(
                    "services",
                    queryset=Service.objects.only(
                        "id", "port", "service", "lastSeen", "products"
                    ),
                ),
            )
            .filter(id=domain_id)
            .first()
        )
        # The Domain model includes related fields (e.g., organization, vulnerabilities, services)
        # which are Django ORM objects themselves and cannot be directly serialized into JSON.
        # Serialize domain object and its relations
        domain_data = {
            "id": domain.id,
            "name": domain.name,
            "ip": domain.ip,
            "createdAt": domain.createdAt,
            "updatedAt": domain.updatedAt,
            "country": domain.country,
            "cloudHosted": domain.cloudHosted,
            "organization": {
                "id": domain.organization.id,
                "name": domain.organization.name,
            }
            if domain.organization
            else None,
            "vulnerabilities": [
                {
                    "id": vulnerability.id,
                    "title": vulnerability.title,
                    "severity": vulnerability.severity,
                    "description": vulnerability.description,
                    "state": vulnerability.state,
                    "createdAt": vulnerability.createdAt,
                }
                for vulnerability in domain.vulnerabilities.all()
            ],
            "services": [
                {
                    "id": service.id,
                    "port": service.port,
                    "lastSeen": service.lastSeen,
                    "products": service.products,
                }
                for service in domain.services.all()
            ],
            "webpages": [
                {
                    "url": webpage.url,
                    "status": webpage.status,
                    "responseSize": webpage.responseSize,
                }
                for webpage in domain.webpages.all()
            ],
        }
        return domain_data
    except Domain.DoesNotExist:
        raise HTTPException(status_code=404, detail="Domain not found.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def search_domains(domain_search: DomainSearch, current_user):
    """
    List domains by search filter
    Arguments:
        domain_search: A DomainSearch object to filter by.
    Returns:
        object: A paginated list of Domain objects
    """
    try:
        domains = Domain.objects.all().order_by(
            sort_direction(domain_search.sort, domain_search.order)
        )

        # Apply global filters based on user permissions
        if not is_global_view_admin(current_user):
            orgs = get_org_memberships(current_user)
            if not orgs:
                # No organization memberships, return empty result
                return [], 0
            domains = domains.filter(organization__id__in=orgs)

        # Add a filter to restrict based on FCEB and CIDR criteria
        domains = domains.filter(Q(isFceb=True) | Q(isFceb=False, fromCidr=True))

        if domain_search.filters:
            domains = filter_domains(domains, domain_search.filters)
        paginator = Paginator(domains, domain_search.pageSize)

        return paginator.get_page(domain_search.page)
    except Domain.DoesNotExist as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def export_domains(domain_filters: DomainFilters):
    try:
        domains = Domain.objects.all()

        if domain_filters:
            domains = filter_domains(domains, domain_filters)

        # TODO: Integrate methods to generate CSV from queryset and save to S3 bucket
        return domains
    except Domain.DoesNotExist as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
