from django.core.management.base import BaseCommand
from xfd_api.models import User, Role, Domain
from django.db.models import Q

class Command(BaseCommand):
    help = 'Lists user IDs and emails of users who have domains via their organizations.'

    def handle(self, *args, **options):
        # Step 1: Get organization IDs that have domains
        organization_ids_with_domains = Domain.objects.values_list('organizationId', flat=True).distinct()

        # Step 2: Get user IDs that have roles in these organizations
        user_ids_with_domains = Role.objects.filter(
            organizationId__in=organization_ids_with_domains
        ).values_list('userId', flat=True).distinct()

        # Step 3: Get the count of user IDs
        user_count = user_ids_with_domains.count()

        # Output the count
        self.stdout.write(f"Total users with domains: {user_count}")

        # Step 4: Fetch users
        users_with_domains = User.objects.filter(id__in=user_ids_with_domains)

        # Step 5: Output the user IDs and emails
        for user in users_with_domains:
            self.stdout.write(f"User ID: {user.id}, Email: {user.email}")