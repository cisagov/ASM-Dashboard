# Standard Python Libraries
import os
import subprocess


def handler(event, context):
    """Lambda handler to trigger the Django syncdb management command."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
    os.environ.setdefault("PYTHONPATH", "/var/task/src/xfd_django")

    dangerouslyforce = event.get("dangerouslyforce", False)
    populate = event.get("populate", False)

    command = ["python3", "src/xfd_django/manage.py", "syncdb"]
    if dangerouslyforce:
        command.append("--dangerouslyforce")
    if populate:
        command.append("--populate")

    try:
        subprocess.run(command, check=True)
        return {
            "statusCode": 200,
            "body": "Database synchronization completed successfully.",
        }
    except subprocess.CalledProcessError as e:
        return {"statusCode": 500, "body": f"Database synchronization failed: {str(e)}"}
