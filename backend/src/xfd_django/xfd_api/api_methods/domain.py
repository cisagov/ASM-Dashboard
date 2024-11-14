"""
Domain API.

"""

# Standard Python Libraries
import csv

# Third-Party Libraries
from django.core.exceptions import ObjectDoesNotExist
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import Http404
from fastapi import HTTPException

from ..auth import get_org_memberships, is_global_view_admin
from ..helpers.filter_helpers import filter_domains, sort_direction
from ..models import Domain
from ..schema_models.domain import DomainFilters, DomainSearch


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
