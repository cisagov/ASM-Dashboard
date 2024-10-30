from django.core.management.base import BaseCommand
from xfd_api.models import Role

class Command(BaseCommand):
    help = 'Finds user IDs associated with services having ports.'

    def handle(self, *args, **options):
        # Find user IDs associated with services that have ports
        user_ids_with_ports = Role.objects.filter(
            organizationId__domain__service__port__isnull=False
        ).values_list('userId', flat=True).distinct()

        # Convert the QuerySet to a list for better readability
        user_ids_list = list(user_ids_with_ports)

        # Display the user IDs
        if user_ids_list:
            self.stdout.write(self.style.SUCCESS(
                f"User IDs with ports in service table: {user_ids_list}"
            ))
            # Pick the first user ID for testing
            test_user_id = user_ids_list[0]
            self.stdout.write(f"Using user_id: {test_user_id} for testing")
        else:
            self.stdout.write(self.style.WARNING(
                "No users found with services having ports."
            ))