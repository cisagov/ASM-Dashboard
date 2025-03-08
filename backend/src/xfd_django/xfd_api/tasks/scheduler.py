"""Scheduler method containing AWS Lambda handler."""

# Standard Python Libraries
import os
import time
import json

# Third-Party Libraries
import django
from django.utils import timezone
import boto3

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()

# Import Django models and helper functions
from xfd_api.models import Organization, Scan, ScanTask
from xfd_api.helpers.getScanOrganizations import get_scan_organizations
from xfd_api.schema_models.scan import SCAN_SCHEMA
from xfd_api.tasks.scanExecution import handler as scan_execution_handler


class Scheduler:
    """Scheduler for executing scans by managing ScanTask records and invoking execution."""

    def __init__(self):
        """Initialize."""
        self.scans = []
        self.organizations = []

    def initialize(self, scans, organizations):
        """Initialize the scheduler with scans and organizations."""
        self.scans = scans
        self.organizations = organizations

    def launch_scan_execution(self, scan):
        """Prepare and send scan execution request."""
        queue_name = "{}-{}-queue".format(os.getenv("STAGE"), scan.name)
        base_queue_url = os.getenv("QUEUE_URL").rstrip("/")
        is_local = os.getenv("IS_LOCAL")

        sqs = boto3.client(
            "sqs",
            region_name=os.getenv("AWS_REGION", "us-east-1"),
            endpoint_url=base_queue_url if is_local else None,
        )

        response = sqs.create_queue(
            QueueName=queue_name,
            Attributes={
                "VisibilityTimeout": "18000",
                "MaximumMessageSize": "262144",
                "MessageRetentionPeriod": "604800"
            }
        )

        queue_url = response["QueueUrl"]
        print("Queue URL: {}".format(queue_url))

        # Get relevant organizations
        orgs = get_scan_organizations(scan) if scan.isGranular else self.organizations
        filtered_orgs = [org for org in orgs if self.should_run_scan(scan, org)]

        for org in filtered_orgs:
            message_body = json.dumps({"org": org.name, "id": str(org.id)})
            try:
                resp = sqs.send_message(QueueUrl=queue_url, MessageBody=message_body)
                print("Message sent to queue with MessageId: {}".format(resp.get("MessageId")))
            except Exception as e:
                print("Error sending message for org {}: {}".format(org.name, e))

        # Now pass organizations to scanExecution
        event_payload = {
            "scanId": str(scan.id),
            "scanType": scan.name,
            "desiredCount": scan.concurrentTasks,
            "organizations": list(filtered_orgs),  # Pass orgs to scanExecution
            "isPe": False,
        }

        try:
            response = scan_execution_handler(event_payload, None)
            print("scanExecution handler response: {}".format(response))
        except Exception as e:
            print("Error invoking scanExecution: {}".format(e))

    def should_run_scan(self, scan, organization=None):
        """
        Determine whether the scan should run for a given organization.

        This method uses several criteria:
         1. If manualRunPending is set, always run.
         2. Check if enough time has passed since the scan last ran (using scan.lastRun and frequency).
         3. Check for currently running or recently finished scan tasks.
        """
        scan_schema = SCAN_SCHEMA.get(scan.name, {})
        is_passive = getattr(scan_schema, "isPassive", False)
        global_scan = getattr(scan_schema, "global_scan", False)

        # Don't run non-passive scans on passive organizations.
        if organization and organization.isPassive and not is_passive:
            return False

        # Always run scans that have manualRunPending set to True.
        if scan.manualRunPending:
            return True

        # Check if the scan has run recently based on its lastRun timestamp.
        if scan.lastRun:
            # Assuming scan.frequency is expressed in days, convert to seconds.
            frequency_seconds = scan.frequency * 86400
            if (timezone.now() - scan.lastRun).total_seconds() < frequency_seconds:
                return False

        def filter_scan_tasks(tasks):
            if global_scan:
                return tasks.filter(scan=scan)
            return tasks.filter(scan=scan).filter(organizations=organization) | tasks.filter(organizations__id=organization.id)

        last_running_scan_task = filter_scan_tasks(
            ScanTask.objects.filter(status__in=["created", "queued", "requested", "started"]).order_by("-createdAt")
        ).first()
        if last_running_scan_task:
            return False

        last_finished_scan_task = filter_scan_tasks(
            ScanTask.objects.filter(status__in=["finished", "failed"], finishedAt__isnull=False).order_by("-finishedAt")
        ).first()
        if last_finished_scan_task and last_finished_scan_task.finishedAt:
            frequency_seconds = scan.frequency * 86400
            if timezone.is_naive(last_finished_scan_task.finishedAt):
                last_finished_scan_task.finishedAt = timezone.make_aware(last_finished_scan_task.finishedAt, timezone.get_current_timezone())
            if (timezone.now() - last_finished_scan_task.finishedAt).total_seconds() < frequency_seconds:
                return False

        if last_finished_scan_task and last_finished_scan_task.finishedAt and scan.isSingleScan:
            print("Single scan")
            return False

        return True

    def run(self):
        """Execute scans based on their configurations."""
        for scan in self.scans:
            print("Running on scan")
            print(scan)
            if getattr(scan, "concurrentTasks", 0):
                self.launch_scan_execution(scan)


# -----------------------------------------------------------------------------
# Lambda Handler
# -----------------------------------------------------------------------------
def handler(event, context):
    """Handler for invoking the scheduler to run scans."""
    print("Running scheduler...")

    scan_ids = event.get("scanIds", [])
    if "scanId" in event:
        scan_ids.append(event["scanId"])

    org_ids = event.get("organizationIds", [])

    # Fetch scans based on scan_ids if provided.
    if scan_ids:
        scans = Scan.objects.filter(id__in=scan_ids).prefetch_related("organizations", "tags")
    else:
        scans = Scan.objects.all().prefetch_related("organizations", "tags")

    # Fetch organizations based on org_ids if provided; otherwise, all organizations.
    if org_ids:
        organizations = Organization.objects.filter(id__in=org_ids)
    else:
        organizations = Organization.objects.all()

    scheduler = Scheduler()
    scheduler.initialize(scans, organizations)
    scheduler.run()

    print("Finished running scheduler.")
