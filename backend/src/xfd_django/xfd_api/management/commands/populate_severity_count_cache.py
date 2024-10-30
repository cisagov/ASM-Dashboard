from django.core.management.base import BaseCommand
from xfd_api.tasks import populate_SeverityCountsCache

class Command(BaseCommand):
    help = 'Populates the vulnerabilities stats cache in AWS Elasticache'

    def handle(self, *args, **options):
        result = populate_SeverityCountsCache()
        self.stdout.write(self.style.SUCCESS(result['message']))