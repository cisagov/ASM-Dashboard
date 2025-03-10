"""Link sub-domains and IPs from sub-domain lookups."""
# Standard Python Libraries
import datetime
import hashlib
import logging
import socket

from django.utils import timezone

from xfd_mini_dl.models import DataSource, SubDomains, Ip, IpsSubs
from xfd_api.helpers.asset_inserts import create_or_update_ip


LOGGER = logging.getLogger(__name__)
DATE = datetime.datetime.now(datetime.timezone.utc)

whois_datasource, created = DataSource.objects.get_or_create(
    name="WhoisXML",
    defaults={
        "description": "Enterprise Grade solution to search for and monitor domain data.",
        "last_run": timezone.now().date(),  # Sets the current date and time
    },
)

def get_ips_and_type(subdomain):
    # Initialize an empty list to store results
    ip_info = []

    try:
        # Get address information for the subdomain
        results = socket.getaddrinfo(subdomain, None)
        
        # Iterate over the results and classify each IP
        for result in results:
            family, socktype, proto, canonname, sockaddr = result
            ip_address = sockaddr[0]
            
            # Check if the address family is AF_INET (IPv4) or AF_INET6 (IPv6)
            if family == socket.AF_INET:
                ip_type = "IPv4"
            elif family == socket.AF_INET6:
                ip_type = "IPv6"
            else:
                continue

            # Append the IP and type as a tuple to the list
            ip_info.append((ip_address, ip_type))

    except socket.gaierror as e:
        LOGGER.warning(f"Error resolving the subdomain {subdomain}: {e}")

    return ip_info


def link_ip_from_domain(sub, org):
    """Link IP from domain."""
    ips = get_ips_and_type(sub.sub_domain)
    if not ips:
        return 0
    for ip, ip_type in ips:
        create_or_update_ip(
            {
                'ip':str(ip),
                'organization': org,
                'ip_version': ip_type,
                'last_seen_timestamp':datetime.datetime.now(datetime.timezone.utc),
                'current': True,
                'from_cidr': False,
            },
            {
                "last_seen_timestamp":datetime.datetime.now(datetime.timezone.utc),
                'current': True,
            },
            sub
        )

            
    return 1

# def save_ip_and_link_to_subdomain(ip, sub_domain):
#     """Save an IP and link to Subdomains"""
#     ip_object, created = Ip.objects.get_or_create(
#         ip_hash=hashlib.sha256(str(ip).encode("utf-8")).hexdigest(),
#         defaults={
#             'ip':str(ip),
#             'last_seen_timestamp':datetime.datetime.now(datetime.timezone.utc),
#             'current': True,
#             'from_cidr': False,
#         }
#     )
#     if not created:
#         ip_object.last_seen_timestamp = datetime.datetime.now(datetime.timezone.utc)
#         ip_object.current = True
#         ip_object.save()
    

#     IpsSubs.objects.update_or_create(
#         ip = ip_object,
#         sub_domain = sub_domain,
#         defaults = {
#             "last_seen":datetime.datetime.now(datetime.timezone.utc),
#             "current":True,
#         }
#     )
            
    


def connect_ips_from_subs(orgs_list = []):
    """For each org, find all ips associated with its sub_domains and link them in the ips_subs table."""
    # Get P&E organizations DataFram
    LOGGER.info('Linking Ips from subdomains')
    num_orgs = len(orgs_list)

    # Loop through orgs
    org_count = 1
    for org in orgs_list:
        # Connect to database
        LOGGER.info(
            "Running on %s, %d/%d",
            org.acronym,
            org_count,
            num_orgs,
        )

        # Query sub-domains
        subdomains = SubDomains.objects.filter(current=True, organization=org)
        LOGGER.info("Number of Sub-domains: %d", len(subdomains))

        for sub_row in subdomains:
            sub_domain = sub_row.sub_domain
            if sub_domain == "Null_Sub":
                continue
            link_ip_from_domain(sub_row, org)

        org_count += 1