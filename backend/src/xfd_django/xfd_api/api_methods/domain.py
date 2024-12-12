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

from ..auth import get_org_memberships, get_user_organization_ids, is_global_view_admin
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


async def stats_total_domains(organization, tag, current_user):
    """
    Get total number of domains
    Returns:
        int: total number of domains
    """
    try:
        # Base QuerySet
        queryset = Domain.objects.all()

        # Apply filtering logic at the endpoint
        # Check if the user is a global admin
        is_admin = is_global_view_admin(current_user)

        # Get user's accessible organizations
        if not is_admin:
            user_org_ids = await get_user_organization_ids(current_user)
            if not user_org_ids:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User does not belong to any organizations.",
                )
            queryset = queryset.filter(organizationId__id__in=user_org_ids)
        else:
            user_org_ids = None  # Admin has access to all organizations

        # Apply organization filter
        if organization:
            if user_org_ids is not None and organization not in user_org_ids:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User does not have access to the specified organization.",
                )
            queryset = queryset.filter(organizationId__id=organization)

        # Apply tag filter
        if tag:
            tag_org_ids = get_tag_organization_ids(tag)
            if user_org_ids is not None:
                accessible_org_ids = set(user_org_ids).intersection(tag_org_ids)
                if not accessible_org_ids:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="No accessible organizations found for the specified tag.",
                    )
                queryset = queryset.filter(organizationId__id__in=accessible_org_ids)
            else:
                queryset = queryset.filter(organizationId__id__in=tag_org_ids)

        # Get total count
        total_domains = await sync_to_async(queryset.count)()

        # Return the count in the expected schema
        return {"value": total_domains}

    except HTTPException as http_exc:
        raise http_exc
