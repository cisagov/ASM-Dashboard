from django.core.management.base import BaseCommand
from xfd_api.tasks import populate_ByOrgCache

class Command(BaseCommand):
    help = 'Populates the ByOrg cache in Redis'

    def handle(self, *args, **options):
        result = populate_ByOrgCache()
        if result.get('status') == 'success':
            self.stdout.write(self.style.SUCCESS(result['message']))
        else:
            self.stdout.write(self.style.ERROR(result['message']))