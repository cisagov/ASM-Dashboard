"""Link sub-domains and IPs from IP lookups."""
# Standard Python Libraries
import datetime
import ipaddress
import logging
import os
import threading
import time

# Third-Party Libraries
from django.utils import timezone
import requests

LOGGER = logging.getLogger(__name__)
WHOIS_KEY = os.getenv("WHOIS_XML_KEY")
DATE = datetime.datetime.today().date()
THREAD_COUNT = 5

# Third-Party Libraries
from xfd_api.helpers.asset_inserts import create_or_update_ip
from xfd_mini_dl.models import Cidr, DataSource, IpsSubs, Organization, SubDomains

whois_datasource, created = DataSource.objects.get_or_create(
    name="WhoisXML",
    defaults={
        "description": "Enterprise Grade solution to search for and monitor domain data.",
        "last_run": timezone.now().date(),  # Sets the current date and time
    },
)


def process_ips(thread_id, org, cidr, ip_gen):
    """Process ips through WhoisXML and save them to DB."""
    count = 0
    failed_ips = []
    chunk_start = time.time()
    while True:
        try:
            # Get the next IP from the generator or break if exhausted
            ip = str(next(ip_gen))
            count += 1
            try:
                domain_list, failed_ips = search_whois_for_domains(ip, failed_ips)
            except Exception as e:
                LOGGER.error(
                    "Thread {thread_id}: Error identifying domains: {error}".format(
                        thread_id=thread_id, error=e
                    )
                )
                failed_ips.append(ip)
                continue
            if domain_list:
                LOGGER.warning(
                    "Found {domain_count} domains associated with {ip}".format(
                        domain_count=len(domain_list), ip=ip
                    )
                )
                save_and_link_ip_and_subdomain(ip, cidr, org, domain_list)
            # print(f"Thread {thread_id} processing IP: {ip}")
        except StopIteration:
            # Stop when the generator is exhausted
            LOGGER.warning(
                "Thread {thread_id} has completed. Processed {count} ips in {dur} seconds.".format(
                    thread_id=thread_id,
                    count=count,
                    dur=round(time.time() - chunk_start, 2),
                )
            )
            if len(failed_ips) > 0:
                LOGGER.warning(
                    "{fail_count} IPs failed to process".format(
                        fail_count=len(failed_ips)
                    )
                )
            break


def process_cidr(cidr, org):
    """Process a given cidr."""
    ip_gen = generate_ips(cidr.network)

    threads = []
    for i in range(THREAD_COUNT):
        thread = threading.Thread(target=process_ips, args=(i + 1, org, cidr, ip_gen))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()


def search_whois_for_domains(ip, failed_ips):
    """Lookup domains associated with the ip."""
    url = "https://dns-history.whoisxmlapi.com/api/v1?apiKey={key}&ip={ip}".format(
        key=WHOIS_KEY, ip=ip
    )
    payload = {}
    headers = {}
    response = requests.request("GET", url, headers=headers, data=payload)

    # Retry clause
    retry_count, max_retries, time_delay = 1, 3, 3
    while response.status_code != 200 and retry_count <= max_retries:
        LOGGER.warning(
            f"Retrying WhoisXML API endpoint (code {response.status_code}), attempt {retry_count} of {max_retries} (url: {url})"
        )
        time.sleep(time_delay)
        response = requests.request("GET", url, headers=headers, data=payload)
        retry_count += 1
    # If API call still unsuccessful
    if response.status_code != 200:
        LOGGER.error("Max retries reached for {ip}, labeling as failed".format(ip=ip))
        failed_ips.append(ip)
    response = response.json()
    try:
        # If there is a response, save domain
        if response["size"] > 0:
            return response["result"], failed_ips
        else:
            return [], failed_ips
    except Exception as e:
        LOGGER.error("Failed to return WHOIsXML response")
        LOGGER.error(response)
        LOGGER.error(e)
        response = []
    return response, failed_ips


def generate_ips(cidr_network):
    """Create ip generator based on a cidr."""
    network = ipaddress.IPv4Network(cidr_network)
    yield from network.hosts()


def connect_subs_from_ips(orgs: list[Organization]):
    """For each org find all domains that are associated to an ip and create link in the ip_subs table."""
    for org in orgs:
        # Query IPs
        org_uid = org.id
        # ips_df = query_ips(org_uid, conn)
        cidrs = query_cidrs_by_org(org_uid)
        LOGGER.warning(
            "identified {cidr_count} cidrs for {acronym}".format(
                cidr_count=len(cidrs), acronym=org.acronym
            )
        )
        for cidr_row in cidrs:
            LOGGER.warning("Running {cidr}".format(cidr=cidr_row.network))
            process_cidr(cidr_row, org)


def query_cidrs_by_org(org_id):
    """Get CIDRs by org."""
    cidrs = Cidr.objects.filter(
        cidrorgs__organization_id=org_id,  # Filter by the organization ID in the through table
        cidrorgs__current=True,  # Filter by the current status
    )
    return cidrs


def save_and_link_ip_and_subdomain(ip, cidr, org, domains):
    """Save an IP and associated Subdomains."""
    LOGGER.info("linking {domains} to {ip}".format(domains=domains, ip=ip))
    ip_object = create_or_update_ip(
        {
            "ip": ip,
            "organization": org,
            "origin_cidr": cidr,
            "last_seen_timestamp": datetime.datetime.now(datetime.timezone.utc),
            "last_reverse_lookup": datetime.datetime.now(datetime.timezone.utc),
            "current": True,
            "from_cidr": True,
        },
        {
            "origin_cidr": cidr,
            "last_seen_timestamp": datetime.datetime.now(datetime.timezone.utc),
            "last_reverse_lookup": datetime.datetime.now(datetime.timezone.utc),
            "current": True,
            "from_cidr": True,
        },
    )

    for domain in domains:
        try:
            root_domain, created = SubDomains.objects.get_or_create(
                sub_domain=".".join(domain["name"].rsplit(".")[-2:]),
                organization=org,
                defaults={
                    "data_source": whois_datasource,
                    "enumerate_subs": False,
                    "is_root_domain": True,
                    "current": True,
                    "identified": True,
                    "subdomain_source": "WhoisXML",
                    "first_seen": datetime.datetime.now(datetime.timezone.utc),
                    "last_seen": datetime.datetime.now(datetime.timezone.utc),
                },
            )
            if not created:
                root_domain.last_seen = datetime.datetime.now(datetime.timezone.utc)
                root_domain.current = True
                root_domain.save()

            if domain["name"] != root_domain.sub_domain:
                sub_domain, created = SubDomains.objects.get_or_create(
                    sub_domain=domain["name"],
                    organization=org,
                    defaults={
                        "data_source": whois_datasource,
                        "current": True,
                        "identified": True,
                        "subdomain_source": "WhoisXML",
                        "first_seen": datetime.datetime.now(datetime.timezone.utc),
                        "last_seen": datetime.datetime.now(datetime.timezone.utc),
                        "root_domain": root_domain,
                        "from_root_domain": root_domain.sub_domain,
                        "ip_address": ip,
                    },
                )

            if not created:
                sub_domain.last_seen = datetime.datetime.now(datetime.timezone.utc)
                sub_domain.ip_address = ip
                sub_domain.current = True
                sub_domain.save()

            IpsSubs.objects.update_or_create(
                ip=ip_object,
                sub_domain=sub_domain,
                defaults={
                    "last_seen": datetime.datetime.now(datetime.timezone.utc),
                    "current": True,
                },
            )

        except KeyError as ke:
            LOGGER.warning("Key error: {error}".format(error=ke))
            continue
        except Exception as e:
            LOGGER.warning("Unknown error: {error}".format(error=e))
            continue
