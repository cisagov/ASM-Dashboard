"""
Domain API.

"""

# Third-Party Libraries
from fastapi import HTTPException

from ..models import Domain
from ..schemas import DomainFilters, DomainSearch


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


def search_domains(domain_search: DomainSearch):
    """
    List domains by search filter
    Arguments:
        domain_search: A DomainSearch object to filter by.
    Returns:
        object: a list of Domain objects
    """
    try:
        domains = Domain.objects.filter(domain_search)
        return domains
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def export_domains(domain_search: DomainSearch):
    try:
        domains = Domain.objects.filter(domain_search)
        # TODO Continue developing export logic
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
