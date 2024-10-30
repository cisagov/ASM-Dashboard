from django.core.management.base import BaseCommand
from xfd_api.tasks import populate_MostCommonVulnerabilitiesCache

class Command(BaseCommand):
    help = 'Populates the vulnerabilities stats cache in AWS Elasticache'

    def handle(self, *args, **options):
        result = populate_MostCommonVulnerabilitiesCache()
        self.stdout.write(self.style.SUCCESS(result['message']))