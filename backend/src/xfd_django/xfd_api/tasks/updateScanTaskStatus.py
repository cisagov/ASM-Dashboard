"""Update scan task status."""
# Standard Python Libraries
import os

# Third-Party Libraries
import django
from django.db.utils import OperationalError
from django.utils.timezone import now

# Django setup
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()

# Third-Party Libraries
from xfd_api.models import ScanTask


def handler(event, context):
    """Update the status of a ScanTask based on EventBridge event data."""
    detail = event.get("detail")
    if not detail:
        return {"statusCode": 400, "body": "Event detail is required."}

    task_arn = detail.get("taskArn")
    last_status = detail.get("lastStatus")
    stop_code = detail.get("stopCode")
    stopped_reason = detail.get("stoppedReason")
    containers = detail.get("containers", [])

    if not task_arn or not last_status:
        return {"statusCode": 400, "body": "taskArn and lastStatus are required."}

    try:
        # Retry logic for finding the ScanTask
        scan_task = retry_find_scan_task(task_arn)

        if not scan_task:
            raise ValueError(
                "Couldn't find scan task with taskArn: {}".format(task_arn)
            )

        old_status = scan_task.status

        if last_status == "RUNNING":
            scan_task.status = "started"
        elif last_status == "STOPPED":
            if containers and containers[0].get("exitCode") == 0:
                scan_task.status = "finished"
            else:
                scan_task.status = "failed"
            scan_task.output = "{}: {}".format(stop_code, stopped_reason)
            scan_task.finishedAt = now()
        else:
            # No update needed for other statuses
            return {"statusCode": 204, "body": "No status change required."}

        print(
            "Updating status of ScanTask {} from {} to {}.".format(
                scan_task.id, old_status, scan_task.status
            )
        )
        scan_task.save()

        return {
            "statusCode": 200,
            "body": "ScanTask {} updated successfully.".format(scan_task.id),
        }

    except Exception as e:
        return {"statusCode": 500, "body": str(e)}


def retry_find_scan_task(task_arn, retries=3):
    """Retry logic to find a ScanTask by its Fargate Task ARN."""
    for attempt in range(retries):
        try:
            scan_task = ScanTask.objects.filter(fargateTaskArn=task_arn).first()
            if scan_task:
                return scan_task
        except OperationalError as e:
            print("Database error on attempt {}: {}".format(attempt + 1, e))
        except Exception as e:
            print("Unexpected error on attempt {}: {}".format(attempt + 1, e))
        if attempt < retries - 1:
            continue
    return None
