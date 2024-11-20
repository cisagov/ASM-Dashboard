# Third-Party Libraries
from django.core.management.base import BaseCommand
from xfd_api.elasticache_tasks import populate_ServicesStatscache


class Command(BaseCommand):
    help = (
        "Populates the vulnerabilities stats cache in AWS Elasticache."
        " i.e. python manage.py populate_ServicesStatscache"
    )

    def handle(self, *args, **options):
        result = populate_ServicesStatscache()
        self.stdout.write(self.style.SUCCESS(result["message"]))
