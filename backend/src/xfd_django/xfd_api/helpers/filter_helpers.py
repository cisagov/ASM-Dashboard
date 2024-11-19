# Third-Party Libraries
from django.core.exceptions import ObjectDoesNotExist
from django.db.models.query import QuerySet
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


def filter_domains(domains: QuerySet, domain_filters: DomainFilters):
    """
    Filter domains
    Arguments:
        domains: A list of all domains, sorted
        domain_filters: Value to filter the domains table by
    Returns:
        object: a list of Domain objects
    """
    try:
        if domain_filters.port:
            services_by_port = Service.objects.filter(port=domain_filters.port).values(
                "domain"
            )
            if not services_by_port.exists():
                raise ObjectDoesNotExist(
                    "Domain could not be found with provided port."
                )
            domains = domains.filter(id__in=services_by_port)

        if domain_filters.service:
            service_by_id = Service.objects.filter(id=domain_filters.service).values(
                "domain"
            )
            if not service_by_id.exists():
                raise Domain.DoesNotExist("No Domains found with the provided service")
            domains = domains.filter(id__in=service_by_id)

        if domain_filters.reverseName:
            domains_by_reverse_name = Domain.objects.filter(
                reverseName=domain_filters.reverseName
            ).values("id")
            if not domains_by_reverse_name.exists():
                raise Domain.DoesNotExist(
                    "No Domains found with the provided reverse name"
                )
            domains = domains.filter(id__in=domains_by_reverse_name)

        if domain_filters.ip:
            domains_by_ip = Domain.objects.filter(ip=domain_filters.ip).values("id")
            if not domains_by_ip.exists():
                raise Domain.DoesNotExist("Domain could not be found with provided Ip.")
            domains = domains.filter(id__in=domains_by_ip)

        if domain_filters.organization:
            domains_by_org = Domain.objects.filter(
                organization_id=domain_filters.organization
            ).values("id")
            if not domains_by_org.exists():
                raise Domain.DoesNotExist(
                    "No Domains found with the provided organization"
                )
            domains = domains.filter(id__in=domains_by_org)

        if domain_filters.organizationName:
            organization_by_name = Organization.objects.filter(
                name=domain_filters.organizationName
            ).values("id")
            if not organization_by_name.exists():
                raise Domain.DoesNotExist(
                    "No Domains found with the provided organization name"
                )
            domains = domains.filter(organization_id__in=organization_by_name)

        if domain_filters.vulnerabilities:
            vulnerabilities_by_id = Vulnerability.objects.filter(
                id=domain_filters.vulnerabilities
            ).values("domain")
            if not vulnerabilities_by_id.exists():
                raise Domain.DoesNotExist(
                    "No Domains found with the provided vulnerability"
                )
            domains = domains.filter(id__in=vulnerabilities_by_id)
        return domains
    except Domain.DoesNotExist as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def filter_vulnerabilities(
    vulnerabilities: QuerySet, vulnerability_filters: VulnerabilityFilters
):
    """
    Filter vulnerabilities based on given filters.

    Arguments:
        vulnerabilities: A list of all vulnerabilities, sorted.
        vulnerability_filters: Value to filter the vulnerabilities table by.

    Returns:
        QuerySet: A filtered list of Vulnerability objects.
    """
    # Initialize a query that includes all vulnerabilities
    query = vulnerabilities

    # Apply filters based on the provided criteria
    if vulnerability_filters.id:
        query = query.filter(id=vulnerability_filters.id)

    if vulnerability_filters.title:
        query = query.filter(title=vulnerability_filters.title)

    if vulnerability_filters.domain:
        query = query.filter(domain=vulnerability_filters.domain)

    if vulnerability_filters.severity:
        query = query.filter(severity=vulnerability_filters.severity)

    if vulnerability_filters.cpe:
        query = query.filter(cpe=vulnerability_filters.cpe)

    if vulnerability_filters.state:
        query = query.filter(state=vulnerability_filters.state)

    if vulnerability_filters.organization:
        # Fetch domains based on the organization ID
        domains_by_organization = Domain.objects.filter(
            organization_id=vulnerability_filters.organization
        )

        if not domains_by_organization.exists():
            raise Vulnerability.DoesNotExist(
                "No Organization-Domain found with the provided organization ID"
            )

        # Filter vulnerabilities based on the found domains
        query = query.filter(domain__in=domains_by_organization)

    if (
        vulnerability_filters.isKev is not None
    ):  # Check for None to distinguish between True/False
        query = query.filter(isKev=vulnerability_filters.isKev)

    # If the queryset is empty, raise a not found exception (404)
    if not query.exists():
        raise Vulnerability.DoesNotExist(
            "No Vulnerabilities found with the provided filters."
        )

    return query
