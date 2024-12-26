# Third-Party Libraries
from django.core.exceptions import ObjectDoesNotExist
from django.db.models.query import Q, QuerySet
from django.http import Http404
from fastapi import HTTPException

from ..models import Domain, Organization, Service, Vulnerability
from ..schema_models.domain import DomainFilters
from ..schema_models.vulnerability import VulnerabilityFilters


def sort_direction(sort, order):
    """
    Adds the sort direction modifier.
    If sort =
        ASC - return order field unmodified to sort in ascending order.
        DSC - returns & prepend '-' to the order field to sort in descending order.
    """
    try:
        # Fetch all domains in list
        if sort == "ASC":
            return order
        elif sort == "DSC":
            return "-" + order
        else:
            raise ValueError
    except ValueError as e:
        raise HTTPException(status_code=500, detail="Invalid sort direction supplied")


def apply_domain_filters(domains, filters):
    """
    Apply filters to domains QuerySet directly.
    For partial matches (like ILIKE), we use __icontains.
    """
    q = Q()

    if filters.name:
        q &= Q(name__icontains=filters.name)

    # reverseName partial match
    if filters.reverseName:
        q &= Q(reverseName__icontains=filters.reverseName)

    # name partial match
    if hasattr(filters, "name") and filters.name:
        q &= Q(name__icontains=filters.name)

    # ip partial match
    if filters.ip:
        q &= Q(ip__icontains=filters.ip)

    # Organization exact match
    if filters.organization:
        q &= Q(organization_id=filters.organization)

    # OrganizationName partial match
    if filters.organizationName:
        q &= Q(organization__name__icontains=filters.organizationName)

    # Vulnerabilities partial match by title
    if filters.vulnerabilities:
        q &= Q(vulnerabilities__title__icontains=filters.vulnerabilities)

    # Ports filtering:
    if hasattr(filters, "ports") and filters.ports:
        try:
            port_int = int(filters.ports)
            q &= Q(services__port=port_int)
        except ValueError:
            # If not a valid integer, no match
            q &= Q(pk__in=[])

    # Service partial match in products or service field:
    if filters.service:
        q &= Q(services__products__icontains=filters.service)

    # Finally filter
    return domains.filter(q)


def apply_vuln_filters(
    vulnerabilities: QuerySet, vulnerability_filters: VulnerabilityFilters
) -> QuerySet:
    """
    Filter vulnerabilities using Q objects for partial matches and exact matches.
    """

    q = Q()

    # Exact match on id
    if vulnerability_filters.id:
        q &= Q(id=vulnerability_filters.id)

    # Partial match on title (ILIKE -> __icontains)
    if vulnerability_filters.title:
        q &= Q(title__icontains=vulnerability_filters.title)

    # Partial match on domain name
    if vulnerability_filters.domain:
        q &= Q(domain__name__icontains=vulnerability_filters.domain)

    # Partial match on severity
    if vulnerability_filters.severity:
        q &= Q(severity__icontains=vulnerability_filters.severity)

    # Partial match on cpe
    if vulnerability_filters.cpe:
        q &= Q(cpe__icontains=vulnerability_filters.cpe)

    # Exact match on state
    if vulnerability_filters.state:
        q &= Q(state=vulnerability_filters.state)

    # Exact match on substate
    if hasattr(vulnerability_filters, "substate") and vulnerability_filters.substate:
        q &= Q(substate=vulnerability_filters.substate)

    # Exact match on organization
    if vulnerability_filters.organization:
        q &= Q(domain__organization_id=vulnerability_filters.organization)

    # Exact match on isKev (True/False)
    if vulnerability_filters.isKev is not None:
        q &= Q(isKev=vulnerability_filters.isKev)

    # Apply the final Q object filter
    filtered = vulnerabilities.filter(q)

    # If the queryset is empty, raise a not found exception (404)
    if not filtered.exists():
        raise Vulnerability.DoesNotExist(
            "No Vulnerabilities found with the provided filters."
        )

    return filtered
