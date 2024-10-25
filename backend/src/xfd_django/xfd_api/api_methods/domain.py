"""
Domain API.

"""

# Standard Python Libraries
import csv

# Third-Party Libraries
from django.core.paginator import Paginator
from django.db.models import Q
from fastapi import HTTPException

from ..helpers.filter_helpers import filter_domains, sort_direction
from ..models import Domain
from ..schema_models.domain import DomainFilters, DomainSearch
from ..auth import is_global_view_admin, get_org_memberships


def get_domain_by_id(domain_id: str):
    """
    Get domain by id.
    Returns:
        object: a single Domain object.
    """
    try:
        domain = Domain.objects.get(id=domain_id)
        return domain
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

        print(domains)
        return paginator.get_page(domain_search.page)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def export_domains(domain_filters: DomainFilters):
    try:
        domains = Domain.objects.all()

        if domain_filters:
            domains = filter_domains(domains, domain_filters)

        # TODO: Integrate methods to generate CSV from queryset and save to S3 bucket
        return domains
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
