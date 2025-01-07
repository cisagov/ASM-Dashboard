"""Populate command."""
# Third-Party Libraries
from django.core.management.base import BaseCommand
from xfd_api.tasks.elasticache_tasks import populate_by_org_cache


class Command(BaseCommand):
    """Command."""

    help = "Populates the vulnerabilities stats cache in AWS Elasticache"

    def handle(self, *args, **options):
        """Handle call."""
        result = populate_by_org_cache({}, {})
        self.stdout.write(self.style.SUCCESS(result["message"]))
