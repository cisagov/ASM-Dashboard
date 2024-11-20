# Standard Python Libraries
import os

# Third-Party Libraries
import django
from django.core.management import call_command

def handler(event, context):
    """
    Lambda handler to trigger syncdb.
    """
    # Set the Django settings module
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
    os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"

    # Initialize Django
    django.setup()

    # Parse arguments from the event
    dangerouslyforce = event.get("dangerouslyforce", False)
    populate = event.get("populate", False)

    command_args = []
    if dangerouslyforce:
        command_args.append("--dangerouslyforce")
    if populate:
        command_args.append("--populate")

    try:
        # Run the custom syncdb management command
        call_command("syncdb", *command_args)
        return {
            "statusCode": 200,
            "body": "Database synchronization completed successfully.",
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "body": f"Database synchronization failed: {str(e)}",
        }
