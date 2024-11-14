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
    Filter vulnerabilitie
    Arguments:
        vulnerabilities: A list of all vulnerabilities, sorted
        vulnerability_filters: Value to filter the vulnberabilities table by
    Returns:
        object: a list of Vulnerability objects
    """
    try:
        if vulnerability_filters.id:
            vulnerability_by_id = Vulnerability.objects.values("id").get(
                id=vulnerability_filters.id
            )
            if not vulnerability_by_id:
                raise Vulnerability.DoesNotExist(
                    "No Vulnerabilities found with the provided id"
                )
            vulnerabilities = vulnerabilities.filter(id=vulnerability_by_id)

        if vulnerability_filters.title:
            vulnerabilities_by_title = Vulnerability.objects.values("id").filter(
                title=vulnerability_filters.title
            )
            if not vulnerabilities_by_title.exists():
                raise Vulnerability.DoesNotExist(
                    "No Vulnerabilities found with the provided title"
                )
            vulnerabilities = vulnerabilities.filter(id__in=vulnerabilities_by_title)

        if vulnerability_filters.domain:
            vulnerabilities_by_domain = Vulnerability.objects.values("id").filter(
                domain=vulnerability_filters.domain
            )
            if not vulnerabilities_by_domain.exists():
                raise Vulnerability.DoesNotExist(
                    "No Vulnerabilities found with the provided domain"
                )
            vulnerabilities = vulnerabilities.filter(id__in=vulnerabilities_by_domain)

        if vulnerability_filters.severity:
            vulnerabilities_by_severity = Vulnerability.objects.values("id").filter(
                severity=vulnerability_filters.severity
            )
            if not vulnerabilities_by_severity.exists():
                raise Vulnerability.DoesNotExist(
                    "No Vulnerabilities found with the provided severity level"
                )
            vulnerabilities = vulnerabilities.filter(id__in=vulnerabilities_by_severity)

        if vulnerability_filters.cpe:
            vulnerabilities_by_cpe = Vulnerability.objects.values("id").filter(
                cpe=vulnerability_filters.cpe
            )
            if not vulnerabilities_by_cpe.exists():
                raise Vulnerability.DoesNotExist(
                    "No Vulnerabilities found with the provided Cpe"
                )
            vulnerabilities = vulnerabilities.filter(id__in=vulnerabilities_by_cpe)

        if vulnerability_filters.state:
            vulnerabilities_by_state = Vulnerability.objects.values("id").filter(
                state=vulnerability_filters.state
            )
            if not vulnerabilities_by_state.exists():
                raise Vulnerability.DoesNotExist(
                    "No Vulnerabilities found with the provided state"
                )
            vulnerabilities = vulnerabilities.filter(id__in=vulnerabilities_by_state)

        if vulnerability_filters.organization:
            domains = Domain.objects.all()
            domains_by_organization = Domain.objects.values("id").filter(
                organization_id=vulnerability_filters.organization
            )
            if not domains_by_organization.exists():
                raise Vulnerability.DoesNotExist(
                    "No Organization-Domain found with the provided organization ID"
                )
            domains = domains.filter(id__in=domains_by_organization)
            vulnerabilities_by_domain = Vulnerability.objects.values("id").filter(
                id__in=domains
            )
            if not vulnerabilities_by_domain.exists():
                raise Vulnerability.DoesNotExist(
                    "No Vulnerabilities found with the provided organization ID"
                )
            vulnerabilities = vulnerabilities.filter(id__in=vulnerabilities_by_domain)

        if vulnerability_filters.isKev:
            vulnerabilities_by_is_kev = Vulnerability.objects.values("id").filter(
                isKev=vulnerability_filters.isKev
            )
            if not vulnerabilities_by_is_kev.exists():
                raise Vulnerability.DoesNotExist(
                    "No Vulnerabilities found with the provided isKev value"
                )
            vulnerabilities = vulnerabilities.filter(id__in=vulnerabilities_by_is_kev)
        return vulnerabilities
    except Domain.DoesNotExist as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
