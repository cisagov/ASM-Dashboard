"""Save domains to the database."""
from django.utils.timezone import now
from xfd_api.models import Domain
from uuid import UUID

def save_domains_to_db(domains):
    """Save or update a list of Domain instances in the database."""
    
    for domain in domains:
        updated_values = {}
        for field in domain._meta.fields:
            field_name = field.name
            if field_name in ["name", "fromRootDomain", "discoveredBy_id"]:
                continue
            
            value = getattr(domain, field_name, None)
            if value is not None:
                updated_values[field_name] = value

        # Ensure updatedAt is set
        updated_values["updatedAt"] = now()

        # Convert organization_id explicitly to UUID before querying
        if isinstance(domain.organization_id, str):
            try:
                domain.organization_id = UUID(domain.organization_id)
            except ValueError:
                print("Invalid UUID: {}".format(domain.organization_id))
                continue  # Skip this entry if UUID conversion fails

        # Check if record exists before updating
        try:
            queryset = Domain.objects.filter(
                name=domain.name.lower(), organization_id=domain.organization_id
            )

            if queryset.exists():  # ✅ QuerySet check before accessing first object
                existing_domain = queryset.first()  # ✅ Now this is safe
                print("EXISTING DOMAIN: {}".format(existing_domain))
                
                # Instead of save(), use .update() directly on QuerySet
                queryset.update(**updated_values)  # ✅ Efficient DB update
            else:
                # Create a new domain if it doesn’t exist
                Domain.objects.create(
                    name=domain.name.lower(),
                    organization_id=domain.organization_id,
                    **updated_values
                )

        except Exception as e:
            print("Error saving domain {}: {}".format(domain.name, e))
