from django.core.management.base import BaseCommand
from xfd_api.auth import get_user_domains  # Adjust the import path as needed
import asyncio

class Command(BaseCommand):
    help = 'Tests the get_user_domains function for a given user_id and prints the output.'

    def add_arguments(self, parser):
        parser.add_argument(
            'user_id',
            type=str,
            help='The ID of the user to retrieve domains for.'
        )

    def handle(self, *args, **options):
        user_id = options['user_id']

        try:
            # Call the synchronous get_user_domains function
            domains = get_user_domains(user_id)

            # Print the result
            if domains:
                self.stdout.write(self.style.SUCCESS(f"Domains for user_id {user_id}:"))
                for domain in domains:
                    self.stdout.write(f"- {domain}")
            else:
                self.stdout.write(self.style.WARNING(f"No domains found for user_id {user_id}."))

        except Exception as e:
            self.stderr.write(self.style.ERROR(f"An error occurred: {e}"))