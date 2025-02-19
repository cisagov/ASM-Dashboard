"""Run syncdb."""
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
    """Trigger syncdb."""
    dangerouslyforce = event.get("dangerouslyforce", False)
    populate = event.get("populate", False)

    try:
        call_command("syncdb", dangerouslyforce=dangerouslyforce, populate=populate)
        return {
            "statusCode": 200,
            "body": "Database synchronization completed successfully.",
        }
    except Exception as e:
        print("Error during syncmdl: {}".format(str(e)))
        return {
            "statusCode": 500,
            "body": "Database synchronization failed: {}".format(str(e)),
        }
