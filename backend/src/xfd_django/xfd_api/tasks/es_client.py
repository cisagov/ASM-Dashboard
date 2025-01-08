"""ES client."""
# Standard Python Libraries
import os

# Third-Party Libraries
from elasticsearch import Elasticsearch, helpers

# Constants
DOMAINS_INDEX = "domains-5"
ORGANIZATIONS_INDEX = "organizations-1"

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
    """ES Client."""

    def __init__(self):
        """Initialize the Elasticsearch client."""
        endpoint = os.getenv("ELASTICSEARCH_ENDPOINT")
        self.client = Elasticsearch(endpoint)

    def sync_organizations_index(self):
        """Create or updates the organizations index with mappings."""
        try:
            if not self.client.indices.exists(index=ORGANIZATIONS_INDEX):
                print(f"Creating index {ORGANIZATIONS_INDEX}...")
                self.client.indices.create(
                    index=ORGANIZATIONS_INDEX,
                    body={
                        "mappings": organization_mapping,
                        "settings": {"number_of_shards": 2},
                    },
                )
            else:
                print(f"Updating index {ORGANIZATIONS_INDEX}...")
                self.client.indices.put_mapping(
                    index=ORGANIZATIONS_INDEX, body=organization_mapping
                )
        except Exception as e:
            print(f"Error syncing organizations index: {e}")
            raise e

    def sync_domains_index(self):
        """Create or updates the domains index with mappings."""
        try:
            if not self.client.indices.exists(index=DOMAINS_INDEX):
                print(f"Creating index {DOMAINS_INDEX}...")
                self.client.indices.create(
                    index=DOMAINS_INDEX,
                    body={
                        "mappings": domain_mapping,
                        "settings": {"number_of_shards": 2},
                    },
                )
            else:
                print(f"Updating index {DOMAINS_INDEX}...")
                self.client.indices.put_mapping(
                    index=DOMAINS_INDEX, body=domain_mapping
                )
            # Set refresh interval
            self.client.indices.put_settings(
                index=DOMAINS_INDEX, body={"settings": {"refresh_interval": "1800s"}}
            )
        except Exception as e:
            print(f"Error syncing domains index: {e}")
            raise e

    def update_organizations(self, organizations):
        """Update or inserts organizations into Elasticsearch."""
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
        """Update or insert domains into Elasticsearch."""
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
        """Update or insert webpages into Elasticsearch."""
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
        """Delete all indices in Elasticsearch."""
        try:
            print("Deleting all indices...")
            self.client.indices.delete(index="*")
        except Exception as e:
            print(f"Error deleting all indices: {e}")
            raise e

    def search_domains(self, body):
        """Search domains index with specified query body."""
        return self.client.search(index=DOMAINS_INDEX, body=body)

    def search_organizations(self, body):
        """Search organizations index with specified query body."""
        return self.client.search(index=ORGANIZATIONS_INDEX, body=body)

    def _bulk_update(self, actions):
        """Update to Elasticsearch."""
        try:
            success_count, response = helpers.bulk(
                self.client, actions, raise_on_error=False
            )
            print(f"Bulk operation success count: {success_count}")

            for idx, item in enumerate(response):
                if "update" in item and item["update"].get("error"):
                    print(f"Error indexing document {idx}: {item['update']['error']}")
                else:
                    print(f"Successfully indexed document {idx}: {item}")

            self.client.indices.refresh(index="domains-5")
        except Exception as e:
            print(f"Bulk operation error: {e}")
            raise e
