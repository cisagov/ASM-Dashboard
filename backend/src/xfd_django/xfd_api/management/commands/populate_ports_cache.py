from django.core.management.base import BaseCommand
from xfd_api.tasks import populate_PortsStatscache

class Command(BaseCommand):
    help = ('Populates the vulnerabilities stats cache in AWS Elasticache.'
            ' i.e. python manage.py populate_ServicesStatscache')

    def handle(self, *args, **options):
        result = populate_PortsStatscache()
        self.stdout.write(self.style.SUCCESS(result['message']))