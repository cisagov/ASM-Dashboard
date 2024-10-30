from django.core.management.base import BaseCommand
from xfd_api.models import Role, Domain, Service, User  # Adjust the import paths as necessary

class Command(BaseCommand):
    help = 'Test get_user_service_ids function for a given user ID'

    def add_arguments(self, parser):
        parser.add_argument(
            'user_id',
            type=str,
            help='User ID to retrieve service IDs for',
        )

    def handle(self, *args, **options):
        user_id = options['user_id']

        # Verify that the user exists
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            self.stderr.write(self.style.ERROR(f'User with ID {user_id} does not exist.'))
            return

        # Call the get_user_service_ids function
        service_ids = self.get_user_service_ids(user_id)

        if service_ids:
            self.stdout.write(self.style.SUCCESS(f'Service IDs for user {user_id}:'))
            for service_id in service_ids:
                self.stdout.write(f'- {service_id}')
        else:
            self.stdout.write(self.style.WARNING(f'No services found for user {user_id}.'))

    def get_user_service_ids(self, user_id):
        """
        Retrieves service IDs associated with the organizations the user belongs to.
        """
        # Get organization IDs the user is a member of
        organization_ids = Role.objects.filter(userId=user_id).values_list('organizationId', flat=True)

        # Debug: Print organization IDs
        self.stdout.write(f'Organization IDs for user {user_id}: {list(organization_ids)}')

        # Get domain IDs associated with these organizations
        domain_ids = Domain.objects.filter(organizationId__in=organization_ids).values_list('id', flat=True)

        # Debug: Print domain IDs
        self.stdout.write(f'Domain IDs for organizations: {list(domain_ids)}')

        # Get service IDs associated with these domains
        service_ids = Service.objects.filter(domainId__in=domain_ids).values_list('id', flat=True)

        # Debug: Print service IDs
        self.stdout.write(f'Service IDs for domains: {list(service_ids)}')

        return list(map(str, service_ids))  # Convert UUIDs to strings if necessary
