"""Domain API."""

# Standard Python Libraries
import csv
import io

# Third-Party Libraries
from django.core.paginator import Paginator
from django.db.models import Prefetch, Q
from fastapi import HTTPException

from ..auth import get_org_memberships, is_global_view_admin
from ..helpers.filter_helpers import apply_domain_filters, sort_direction
from ..helpers.s3_client import S3Client
from ..models import Domain, Service
from ..schema_models.domain import DomainSearch


def get_domain_by_id(domain_id: str):
    """
    Get domain by id.

    Returns:
        object: a single Domain object.
    """
    try:
        domain = (
            Domain.objects.select_related("organization")
            .prefetch_related(
                "vulnerabilities",
                Prefetch(
                    "services",
                    queryset=Service.objects.only(
                        "id", "port", "service", "lastSeen", "products"
                    ),
                ),
            )
            .filter(id=domain_id)
            .first()
        )
    except Exception as e:
        print(e)
        raise HTTPException(status_code=404, detail="Domain not found.")

    try:
        # The Domain model includes related fields (e.g., organization, vulnerabilities, services)
        # which are Django ORM objects themselves and cannot be directly serialized into JSON.
        # Serialize domain object and its relations
        domain_data = {
            "id": domain.id,
            "name": domain.name,
            "ip": domain.ip,
            "createdAt": domain.createdAt,
            "updatedAt": domain.updatedAt,
            "country": domain.country,
            "cloudHosted": domain.cloudHosted,
            "organization": {
                "id": domain.organization.id,
                "name": domain.organization.name,
            }
            if domain.organization
            else None,
            "vulnerabilities": [
                {
                    "id": vulnerability.id,
                    "title": vulnerability.title,
                    "severity": vulnerability.severity,
                    "description": vulnerability.description,
                    "state": vulnerability.state,
                    "createdAt": vulnerability.createdAt,
                }
                for vulnerability in domain.vulnerabilities.all()
            ],
            "services": [
                {
                    "id": service.id,
                    "port": service.port,
                    "lastSeen": service.lastSeen,
                    "products": service.products,
                }
                for service in domain.services.all()
            ],
            "webpages": [
                {
                    "url": webpage.url,
                    "status": webpage.status,
                    "responseSize": webpage.responseSize,
                }
                for webpage in domain.webpages.all()
            ],
        }
        return domain_data

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def search_domains(domain_search: DomainSearch, current_user):
    """List domains by search filter."""
    try:
        domains = (
            Domain.objects.select_related("organization")
            .prefetch_related("services", "vulnerabilities")
            .order_by(sort_direction(domain_search.sort, domain_search.order))
        )

        # Apply global user permission filters
        if not is_global_view_admin(current_user):
            orgs = get_org_memberships(current_user)
            if not orgs:
                # No organization memberships, return empty result
                return [], 0
            domains = domains.filter(organization__id__in=orgs)

        # Apply the isFceb/fromCidr condition:
        domains = domains.filter(Q(isFceb=True) | Q(isFceb=False, fromCidr=True))

        # Apply filters if provided
        if domain_search.filters:
            domains = apply_domain_filters(domains, domain_search.filters)

        # Handle pagination
        page_size = domain_search.pageSize
        # If pageSize == -1, return all results without pagination
        if page_size == -1:
            result = list(domains)
            return result, len(result)

        page_size = page_size or 15  # default page size if none provided
        paginator = Paginator(domains, page_size)
        page_obj = paginator.get_page(domain_search.page)
        return list(page_obj), paginator.count

    except HTTPException as he:
        raise he
    except Domain.DoesNotExist as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def export_domains(domain_search: DomainSearch, current_user):
    """Export domains into a CSV and upload to S3."""
    try:
        # Set pageSize to -1 to fetch all domains without pagination
        domain_search.pageSize = -1

        # Fetch domains using search_domains function
        domains, count = search_domains(domain_search, current_user)

        # If no domains, generate empty CSV
        if not domains:
            csv_content = "name,ip,id,ports,products,createdAt,updatedAt,organization\n"
        else:
            # Process domains to flatten organization name,
            # ports as string, products as unique string
            processed_domains = []
            for domain in domains:
                organization_name = (
                    domain.organization.name if domain.organization else ""
                )
                ports = ", ".join(
                    [str(service.port) for service in domain.services.all()]
                )

                # Collect unique products
                products_set = set()
                for service in domain.services.all():
                    for product in service.products.all():
                        if product.name:
                            product_entry = (
                                "{} {}".format(product.name, product.version)
                                if product.version
                                else product.name
                            )
                            products_set.add(product_entry)
                products = ", ".join(sorted(products_set))

                processed_domains.append(
                    {
                        "name": domain.name,
                        "ip": domain.ip,
                        "id": str(domain.id),
                        "ports": ports,
                        "products": products,
                        "createdAt": domain.createdAt.isoformat()
                        if domain.createdAt
                        else "",
                        "updatedAt": domain.updatedAt.isoformat()
                        if domain.updatedAt
                        else "",
                        "organization": organization_name,
                    }
                )

            # Define CSV fields
            csv_fields = [
                "name",
                "ip",
                "id",
                "ports",
                "products",
                "createdAt",
                "updatedAt",
                "organization",
            ]

            # Generate CSV content using csv module
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=csv_fields)
            writer.writeheader()
            for domain in processed_domains:
                writer.writerow(domain)
            csv_content = output.getvalue()

        # Initialize S3 client
        client = S3Client()

        # Save CSV to S3
        url = client.save_csv(csv_content, "domains")

        return {"url": url}

    except Exception as e:
        # Log the exception for debugging (optional)
        print("Error exporting domains: {}".format(e))
        raise HTTPException(status_code=500, detail=str(e))
