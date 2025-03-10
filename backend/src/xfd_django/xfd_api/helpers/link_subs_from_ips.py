"""Link sub-domains and IPs from IP lookups."""
# Standard Python Libraries
import datetime
import hashlib
import ipaddress
import logging
import threading
import time
import os

# Third-Party Libraries
import numpy as np
import requests

from django.utils import timezone

# cisagov Libraries
LOGGER = logging.getLogger(__name__)
WHOIS_KEY = os.getenv('WHOIS_XML_KEY')
DATE = datetime.datetime.today().date()

from xfd_mini_dl.models import DataSource, Organization, Cidr, SubDomains, Ip, IpsSubs
from xfd_api.helpers.asset_inserts import create_or_update_ip

whois_datasource, created = DataSource.objects.get_or_create(
    name="WhoisXML",
    defaults={
        "description": "Enterprise Grade solution to search for and monitor domain data.",
        "last_run": timezone.now().date(),  # Sets the current date and time
    },
)

def reverseLookup(ip_obj, failed_ips, thread):
    """Take an ip and find all associated subdomains."""
    # Query WHOisXML
    url = f"https://dns-history.whoisxmlapi.com/api/v1?apiKey={WHOIS_KEY}&ip={ip_obj.get('ip')}"
    payload = {}
    headers = {}
    response = requests.request("GET", url, headers=headers, data=payload)

    # Retry clause
    retry_count, max_retries, time_delay = 1, 3, 3
    while response.status_code != 200 and retry_count <= max_retries:
        # LOGGER.warning(f"Retrying WhoisXML API endpoint (code {response.status_code}), attempt {retry_count} of {max_retries} (url: {url})")
        time.sleep(time_delay)
        response = requests.request("GET", url, headers=headers, data=payload)
        retry_count += 1
    # If API call still unsuccessful
    if response.status_code != 200:
        bad_ip = ip_obj.get('ip')

        LOGGER.error(f"Max retries reached for {bad_ip}, labeling as failed")
        failed_ips.append(bad_ip)
    response = response.json()

    found_domains = []
    try:
        # If there is a response, save domain
        if response["size"] > 0:
            # Insert or update IP
            save_link_ip_and_subdomain(ip_obj, response["result"])

            result = response["result"]
            for domain in result:
                try:
                    found_domains.append(
                        {
                            "sub_domain": domain["name"],
                            "root": ".".join(domain["name"].rsplit(".")[-2:]),
                        }
                    )
                except KeyError:
                    continue

    except Exception as e:
        LOGGER.error(f"{thread}: Failed to return WHOIsXML response")
        LOGGER.error(f"{thread}: {response}")
        LOGGER.error(f"{thread}: {e}")
    return found_domains, failed_ips


def link_domain_from_ip(ip_obj, failed_ips, thread):
    """From a provided ip find domains and link them in the db."""
    # Lookup domains from IP
    found_domains, failed_ips = reverseLookup(ip_obj, failed_ips, thread)
    if len(found_domains) > 0:
        LOGGER.info(found_domains)
    return found_domains


def run_ip_chunk(ips_list, thread):
    """Run the provided chunk through the linking process."""
    count = 0
    last_chunk = time.time()
    failed_ips = []
    for ip_obj in ips_list:
        # Log progress
        count += 1
        if count % 10000 == 0:
            LOGGER.info(f"{thread}: Running IPs: {count}/{len(ips_list)}, {time.time() - last_chunk} seconds for the last IP chunk")
            last_chunk = time.time()

        # Link domain from IP
        try:
            link_domain_from_ip(ip_obj, failed_ips, thread)
        except requests.exceptions.SSLError as e:
            LOGGER.error(e)
            time.sleep(1)
            continue
    # LOGGER.info(f"{thread} Ips took {time.time() - start_time} to link to subs")


def connect_subs_from_ips(orgs:list[Organization]):
    """For each org find all domains that are associated to an ip and create link in the ip_subs table."""
    LOGGER.info('Linking subs via IPs')
    # Loop through orgs
    org_count = 1
    for org in orgs:
        # Query IPs
        org_uid = org.id
        # ips_df = query_ips(org_uid, conn)
        cidrs = query_cidrs_by_org(org_uid)
        LOGGER.warning(cidrs)
        LOGGER.warning(len(cidrs))
        ips_list = []
        for cidr_row in cidrs:
            for ip in list(ipaddress.IPv4Network(cidr_row.network).hosts()):
                ip_obj = {
                    "ip": str(ip),
                    "origin_cidr": cidr_row,
                    "organization": org
                }
                ips_list.append(ip_obj)
        # ips_df = pd.DataFrame(ips_list)

        LOGGER.info(f"Number of Cidrs: {len(cidrs)}")

        # if no IPS, continue to next org
        if len(ips_list) == 0:
            org_count += 1
            continue

        # Split IPs into 8 threads, then call run_ip_chunk function
        num_chunks = 5
        ips_split = np.array_split(ips_list, num_chunks)
        thread_num = 0
        thread_list = []
        while thread_num < len(ips_split):
            thread_name = f"Thread {thread_num + 1}: "
            LOGGER.info('number of ips:')
            LOGGER.info(len(ips_split[thread_num]))
            # Start thread
            t = threading.Thread(
                target=run_ip_chunk,
                args=(ips_split[thread_num], thread_name),
            )
            t.start()
            thread_list.append(t)
            thread_num += 1

        for thread in thread_list:
            thread.join()

        LOGGER.info("All threads have finished.")

        org_count += 1


def query_cidrs_by_org(org_id):
    """Get CIDRs by org."""
    cidrs = Cidr.objects.filter(
    cidrorgs__organization_id=org_id,  # Filter by the organization ID in the through table
    cidrorgs__current=True  # Filter by the current status
)
    return cidrs


def save_link_ip_and_subdomain(ip_obj, domains):
    """Save an IP and associated Subdomains"""
    LOGGER.info('linking {domains} to {ip}'.format(domains=domains, ip=ip_obj.get('ip')))
    ip_object = create_or_update_ip(
        {
            'ip':ip_obj.get('ip'),
            'organization': ip_obj.get('organization'),
            'origin_cidr':ip_obj.get('origin_cidr'),
            'last_seen_timestamp':datetime.datetime.now(datetime.timezone.utc),
            'last_reverse_lookup':datetime.datetime.now(datetime.timezone.utc),
            'current': True,
            'from_cidr': True,
        },
        {
            'origin_cidr':ip_obj.get('origin_cidr'),
            'last_seen_timestamp':datetime.datetime.now(datetime.timezone.utc),
            'last_reverse_lookup':datetime.datetime.now(datetime.timezone.utc),
            'current':True,
            'from_cidr':True
        }
    )
    # ip_object, created = Ip.objects.get_or_create(
    #     ip_hash=hashlib.sha256(ip_obj.get('ip').encode("utf-8")).hexdigest(),
    #     defaults={
    #         'ip':ip_obj.get('ip'),
    #         'origin_cidr':ip_obj.get('origin_cidr'),
    #         'last_seen_timestamp':datetime.datetime.now(datetime.timezone.utc),
    #         'last_reverse_lookup':datetime.datetime.now(datetime.timezone.utc),
    #         'current': True,
    #         'from_cidr': True,
    #     }
    # )
    # if not created:
    #     ip_object.origin_cidr = ip_obj.get('origin_cidr')
    #     ip_object.last_seen_timestamp = datetime.datetime.now(datetime.timezone.utc)
    #     ip_object.last_reverse_lookup = datetime.datetime.now(datetime.timezone.utc)
    #     ip_object.current = True
    #     ip_object.from_cidr = True
    #     ip_object.save()
    for domain in domains:
        try:
            root_domain, created = SubDomains.objects.get_or_create(
                sub_domain = ".".join(domain["name"].rsplit(".")[-2:]),
                organization = ip_obj.get('organization'),
                defaults = {
                    "data_source": whois_datasource,
                    "enumerate_subs": False,
                    "is_root_domain": True,
                    "current": True,
                    "identified":True,
                    "subdomain_source":"WhoisXML",
                    "first_seen": datetime.datetime.now(datetime.timezone.utc),
                    "last_seen": datetime.datetime.now(datetime.timezone.utc)
                }
            )
            if not created:
                root_domain.last_seen = datetime.datetime.now(datetime.timezone.utc)
                root_domain.current = True
                root_domain.save()


            if domain["name"] != root_domain.sub_domain:
                sub_domain, created = SubDomains.objects.get_or_create(
                sub_domain = domain["name"],
                organization = ip_obj.get('organization'),
                defaults = {
                    "data_source": whois_datasource,
                    "current": True,
                    "identified":True,
                    "subdomain_source":"WhoisXML",
                    "first_seen": datetime.datetime.now(datetime.timezone.utc),
                    "last_seen": datetime.datetime.now(datetime.timezone.utc),
                    "root_domain":root_domain,
                    "from_root_domain":root_domain.sub_domain,
                    "ip_address": ip_obj.get('ip')
                }
            )
            
            if not created:
                sub_domain.last_seen = datetime.datetime.now(datetime.timezone.utc)
                sub_domain.ip_address = ip_obj.get('ip')
                sub_domain.current = True
                sub_domain.save()

            IpsSubs.objects.update_or_create(
                ip = ip_object,
                sub_domain = sub_domain,
                defaults = {
                    "last_seen":datetime.datetime.now(datetime.timezone.utc),
                    "current":True,
                }
            )
                
        except KeyError as ke:
            LOGGER.warning('Key error: {error}'.format(error=ke))
            continue
        except Exception as e:
            LOGGER.warning('Unknown error: {error}'.format(error=e))
            continue