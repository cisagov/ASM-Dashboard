"""Run syncmdl."""
# Standard Python Libraries
import os

# Third-Party Libraries
import django
from django.core.management import call_command

# Set the Django settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"

# Initialize Django
django.setup()

def handler(event, context):
    """Trigger syncmdl."""
    dangerouslyforce = event.get("dangerouslyforce", False)

    try:
        call_command("syncmdl", dangerouslyforce=dangerouslyforce)

    except Exception as e:
        print("Error during syncmdl: {}".format(str(e)))
        return {
            "statusCode": 500,
            "body": "Database synchronization failed: {}".format(str(e)),
        }
