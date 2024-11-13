# Standard Python Libraries
import logging
import os

# Third-Party Libraries
from elasticsearch import Elasticsearch, helpers

# Constants
DOMAINS_INDEX = "domains-5"
ORGANIZATIONS_INDEX = "organizations-1"

# Configure logging
logging.basicConfig(level=logging.INFO)

# Define mappings
organization_mapping = {
    "properties": {"name": {"type": "text"}, "suggest": {"type": "completion"}}
}

domain_mapping = {
    "properties": {
        "services": {"type": "nested"},
        "vulnerabilities": {"type": "nested"},
        "webpage_body": {"type": "text", "term_vector": "yes"},
        "parent_join": {"type": "join", "relations": {"domain": "webpage"}},
        "suggest": {"type": "completion"},
    }
}


class ESClient:
    def __init__(self):
        """Initializes the Elasticsearch client."""
        endpoint = os.getenv("ELASTICSEARCH_ENDPOINT")
        self.client = Elasticsearch(endpoint)

    def sync_organizations_index(self):
        """Creates or updates the organizations index with mappings."""
        try:
            if not self.client.indices.exists(index=ORGANIZATIONS_INDEX):
                logging.info(f"Creating index {ORGANIZATIONS_INDEX}...")
                self.client.indices.create(
                    index=ORGANIZATIONS_INDEX,
                    body={
                        "mappings": organization_mapping,
                        "settings": {"number_of_shards": 2},
                    },
                )
            else:
                logging.info(f"Updating index {ORGANIZATIONS_INDEX}...")
                self.client.indices.put_mapping(
                    index=ORGANIZATIONS_INDEX, body=organization_mapping
                )
        except Exception as e:
            logging.error(f"Error syncing organizations index: {e}")
            raise e

    def sync_domains_index(self):
        """Creates or updates the domains index with mappings."""
        try:
            if not self.client.indices.exists(index=DOMAINS_INDEX):
                logging.info(f"Creating index {DOMAINS_INDEX}...")
                self.client.indices.create(
                    index=DOMAINS_INDEX,
                    body={
                        "mappings": domain_mapping,
                        "settings": {"number_of_shards": 2},
                    },
                )
            else:
                logging.info(f"Updating index {DOMAINS_INDEX}...")
                self.client.indices.put_mapping(
                    index=DOMAINS_INDEX, body=domain_mapping
                )
            # Set refresh interval
            self.client.indices.put_settings(
                index=DOMAINS_INDEX, body={"settings": {"refresh_interval": "1800s"}}
            )
        except Exception as e:
            logging.error(f"Error syncing domains index: {e}")
            raise e

    def update_organizations(self, organizations):
        """Bulk updates or inserts organizations into Elasticsearch."""
        actions = [
            {
                "_op_type": "update",
                "_index": ORGANIZATIONS_INDEX,
                "_id": org["id"],
                "doc": {**org, "suggest": [{"input": org["name"], "weight": 1}]},
                "doc_as_upsert": True,
            }
            for org in organizations
        ]
        self._bulk_update(actions)

    def update_domains(self, domains):
        """Bulk updates or inserts domains into Elasticsearch."""
        actions = [
            {
                "_op_type": "update",
                "_index": DOMAINS_INDEX,
                "_id": domain["id"],
                "doc": {
                    **domain,
                    "suggest": [{"input": domain["name"], "weight": 1}],
                    "parent_join": "domain",
                },
                "doc_as_upsert": True,
            }
            for domain in domains
        ]
        self._bulk_update(actions)

    def update_webpages(self, webpages):
        """Bulk updates or inserts webpages into Elasticsearch."""
        actions = [
            {
                "_op_type": "update",
                "_index": DOMAINS_INDEX,
                "_id": f"webpage_{webpage['webpage_id']}",
                "routing": webpage["webpage_domainId"],
                "doc": {
                    **webpage,
                    "suggest": [{"input": webpage["webpage_url"], "weight": 1}],
                    "parent_join": {
                        "name": "webpage",
                        "parent": webpage["webpage_domainId"],
                    },
                },
                "doc_as_upsert": True,
            }
            for webpage in webpages
        ]
        self._bulk_update(actions)

    def delete_all(self):
        """Deletes all indices in Elasticsearch."""
        try:
            logging.info("Deleting all indices...")
            self.client.indices.delete(index="*")
        except Exception as e:
            logging.error(f"Error deleting all indices: {e}")
            raise e

    def search_domains(self, body):
        """Searches domains index with specified query body."""
        return self.client.search(index=DOMAINS_INDEX, body=body)

    def search_organizations(self, body):
        """Searches organizations index with specified query body."""
        return self.client.search(index=ORGANIZATIONS_INDEX, body=body)

    def _bulk_update(self, actions):
        """Helper function for bulk updates to Elasticsearch."""
        try:
            helpers.bulk(self.client, actions, raise_on_error=True)
            logging.info("Bulk update completed successfully.")
        except Exception as e:
            logging.error(f"Bulk operation error: {e}")
            raise e
