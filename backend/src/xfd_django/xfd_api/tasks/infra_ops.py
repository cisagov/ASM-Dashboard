"""Run infra ops."""
# Standard Python Libraries
import os

# Third-Party Libraries
import django

# Set the Django settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"

# Initialize Django
django.setup()

# Third-Party Libraries
from xfd_api.helpers.infra_helpers import create_matomo_scan_user, create_scan_user


def handler(event, context):
    """Trigger infra ops."""
    try:
        # Create the XFD db scanning user if doesn't exist
        create_scan_user()

        # Create the Matomo db scanning user if doesn't exist
        create_matomo_scan_user()

        return {
            "statusCode": 200,
            "body": "Database synchronization completed successfully.",
        }
    except Exception as e:
        print("Error during syncdb: {}".format(str(e)))
        return {
            "statusCode": 500,
            "body": "Database synchronization failed: {}".format(str(e)),
        }
