# xfd_api/management/commands/find_users_with_vulnerabilities.py

# Third-Party Libraries
from django.core.management.base import BaseCommand
from django.db.models import Q
from xfd_api.models import Role


class Command(BaseCommand):
    help = "Finds user IDs associated with vulnerabilities."

    def handle(self, *args, **options):
        """
        This command retrieves and displays user IDs that are associated with
        vulnerabilities through their organizations and domains.
        """
        try:
            # Query to find user_ids associated with vulnerabilities
            user_ids_with_vulnerabilities = (
                Role.objects.filter(organizationId__domain__vulnerability__isnull=False)
                .values_list("userId", flat=True)
                .distinct()
            )

            # Convert the QuerySet to a list for better readability
            user_ids_list = list(user_ids_with_vulnerabilities)

            # Display the user IDs
            if user_ids_list:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"User IDs with vulnerabilities: {user_ids_list}"
                    )
                )
                # Pick the first user ID for testing
                test_user_id = user_ids_list[0]
                self.stdout.write(f"Using user_id: {test_user_id} for testing")
            else:
                self.stdout.write(
                    self.style.WARNING(
                        "No users found with associated vulnerabilities."
                    )
                )
        except Exception as e:
            self.stderr.write(
                self.style.ERROR(f"An error occurred while fetching user IDs: {e}")
            )
            self.exit_code = 1  # Indicate that the command failed
