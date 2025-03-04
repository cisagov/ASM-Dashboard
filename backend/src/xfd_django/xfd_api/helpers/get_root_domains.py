"""Get root domain per organization."""
from xfd_api.models import Organization

def get_root_domains(organization_id):
    """Retrieve the list of root domains for the specified organization."""
    organization = Organization.objects.get(pk=organization_id)
    return organization.rootDomains