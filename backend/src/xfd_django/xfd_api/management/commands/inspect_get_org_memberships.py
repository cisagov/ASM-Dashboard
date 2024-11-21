# Third-Party Libraries
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from xfd_api.auth import get_org_memberships  # Import the function
from xfd_api.models import Organization, Role  # Import your models
from xfd_api.models import User  # Adjust if your User model is in a different app

# TO run the command: python manage.py test_get_org_memberships 090d87fd-a7be-4bdc-b3a9-5c0bbf24dc40


class Command(BaseCommand):
    help = "Test get_org_memberships function for a given user"

    def add_arguments(self, parser):
        parser.add_argument(
            "user_identifier",
            type=str,
            help="User ID or email to identify the user",
        )

    def handle(self, *args, **options):
        user_identifier = options["user_identifier"]

        # Try to retrieve the user by ID or email
        try:
            user = User.objects.get(id=user_identifier)
            user = user.id

        except (User.DoesNotExist, ValueError):
            try:
                user = User.objects.get(email=user_identifier)
            except User.DoesNotExist:
                self.stderr.write(
                    self.style.ERROR(
                        f'User with ID or email "{user_identifier}" does not exist.'
                    )
                )
                return

        # Call the get_org_memberships function
        org_memberships = get_org_memberships(user)

        # Output the results
        if org_memberships:
            self.stdout.write(
                self.style.SUCCESS(
                    f'User "{user}" is a member of organizations: {org_memberships}'
                )
            )
        else:
            self.stdout.write(
                self.style.WARNING(
                    f'User "{user}" is not a member of any organizations.'
                )
            )
