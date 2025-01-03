"""Flag floating IPs."""
# Standard Python Libraries

# Third-Party Libraries
from django.db.models import Prefetch
from xfd_api.models import Cidr, Domain, Organization


async def check_ip_in_cidr(ip: str, acronym: str) -> bool:
    """
    Checks if a given IP address is within the CIDRs associated with an organization.
    """
    try:
        # Fetch the organization by acronym with related CIDRs
        organization = (
            Organization.objects.prefetch_related("cidrs")
            .filter(acronym=acronym)
            .first()
        )
        if not organization or not organization.cidrs.exists():
            return False

        # Check if the IP is within any CIDR
        return Cidr.objects.filter(
            network__contains=ip, id__in=organization.cidrs.values_list("id", flat=True)
        ).exists()
    except Exception as e:
        print(f"Error checking IP in CIDR: {e}")
        return False


async def check_org_is_fceb(acronym: str) -> bool:
    """
    Checks if the organization (or its parent organizations) belongs to the EXECUTIVE sector.
    """
    try:

        def is_executive(organization: Organization) -> bool:
            # Check if the current organization belongs to the EXECUTIVE sector
            if organization.sectors.filter(acronym="EXECUTIVE").exists():
                return True
            # If there is a parent organization, check it recursively
            if organization.parent:
                return is_executive(organization.parent)
            return False

        # Fetch the organization by acronym with its sectors and parent
        organization = (
            Organization.objects.prefetch_related("sectors", "parent")
            .filter(acronym=acronym)
            .first()
        )
        if not organization:
            return False

        # Check if the organization or any of its parents belong to the EXECUTIVE sector
        return is_executive(organization)
    except Exception as e:
        print(f"Error checking organization is FCEB: {e}")
        return False


async def handler(command_options):
    """
    Handles flagging floating IPs and updating domains for an organization.
    """
    organization_id = command_options.get("organizationId")
    organization_name = command_options.get("organizationName")

    print(f"Running flagFloatingIps for {organization_name}...")

    try:
        # Fetch organization with related domains
        organizations = (
            Organization.objects.prefetch_related(
                Prefetch("domains", queryset=Domain.objects.all())
            )
            .filter(id=organization_id)
            .all()
        )

        for organization in organizations:
            print(f"Processing organization: {organization_name}...")

            # Check if the organization is executive (isFceb)
            is_executive = await check_org_is_fceb(organization.acronym)

            if is_executive:
                # Mark all domains as isFceb = True
                domains_to_update = organization.domains.all()
                Domain.objects.filter(
                    id__in=[domain.id for domain in domains_to_update]
                ).update(isFceb=True)
                print(f"Marked all domains in {organization_name} as isFceb=True.")
            else:
                # Update domains' fromCidr status
                for domain in organization.domains.all():
                    if domain.ip:
                        from_cidr = await check_ip_in_cidr(
                            domain.ip, organization.acronym
                        )
                        if domain.fromCidr != from_cidr:
                            domain.fromCidr = from_cidr
                            domain.save()  # Save domain only if `fromCidr` changes
                            print(f"Updated domain {domain.name}: fromCidr={from_cidr}")

        print(f"Completed processing for organization: {organization_name}.")

    except Exception as e:
        print(f"Error processing organization {organization_name}: {e}")
