"""Scheduler method containing AWS Lambda handler."""

# Standard Python Libraries
import os
import time
import json

# Third-Party Libraries
import django
from django.utils import timezone
import boto3
import pika

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()

# Import Django models and helper functions
from xfd_api.models import Organization, Scan, ScanTask
from xfd_api.helpers.getScanOrganizations import get_scan_organizations
from xfd_api.schema_models.scan import SCAN_SCHEMA
from xfd_api.tasks.scanExecution import handler as scan_execution_handler


# -----------------------------------------------------------------------------
# Scheduler Class
# -----------------------------------------------------------------------------
class Scheduler:
    """
    Scheduler for invoking scanExecution via queue messaging and Lambda.
    Organizations are determined either from scan tags/organizations (if granular)
    or from self.organizations.
    """

    def __init__(self):
        """Initialize."""
        self.scans = []
        self.organizations = []

    def initialize(self, scans, organizations, queued_scan_tasks, orgs_per_scan_task):
        """
        Initialize the scheduler with scans and organizations.
        Note: queued_scan_tasks and orgs_per_scan_task are no longer used.
        """
        self.scans = scans
        self.organizations = organizations

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
            else:
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

    def launch_scan_execution(self, scan):
        """
        Create (or get) a queue, send a message for each organization, and invoke scanExecution handler.
        """

        # Build queue name dynamically
        queue_name = "{}-{}-queue".format(os.getenv("STAGE"), scan.name)
        base_queue_url = os.getenv("QUEUE_URL").rstrip("/")  # Ensure no trailing `/`
        is_local = os.getenv("IS_LOCAL")
        
        # Create SQS client (for both ElasticMQ and AWS SQS)
        sqs = boto3.client(
            "sqs",
            region_name=os.getenv("AWS_REGION", "us-east-1"),
            endpoint_url=base_queue_url if is_local else None  # Use ElasticMQ locally
        )

        response = sqs.create_queue(
            QueueName=queue_name,
            Attributes={
                "VisibilityTimeout": "18000",
                "MaximumMessageSize": "262144",
                "MessageRetentionPeriod": "604800"
            }
        )
        print("CREATE QUEUE RESPONSE")
        print(response)

        queue_url = response["QueueUrl"]

        print("Queue URL: {}".format(queue_url))

        # Get the organizations for the scan
        orgs = get_scan_organizations(scan) if scan.isGranular else self.organizations
        filtered_orgs = [org for org in orgs if self.should_run_scan(scan, org)]
        
        print("Number of organizations: {}".format(len(filtered_orgs)))

        # Send messages to the queue
        for org in filtered_orgs:
            message_body = json.dumps({"org": org.name, "id": str(org.id)})
            try:
                resp = sqs.send_message(QueueUrl=queue_url, MessageBody=message_body)
                print("Message sent to queue with MessageId: {}".format(resp.get("MessageId")))
            except Exception as e:
                print("Error sending message for organization {}: {}".format(org.name, e))
                raise

        event_payload = {
            "scanId": str(scan.id),
            "scanType": scan.name,
            "desiredCount": scan.concurrentTasks,
            "isPe": False,
        }

        try:
            response = scan_execution_handler(event_payload, None)
            print("scanExecution handler response: {}".format(response))
        except Exception as e:
            print("Error invoking scanExecution handler: {}".format(e))
            raise

    def run(self):
        """
        For each scan in self.scans that has a nonzero concurrentTasks field, launch the scanExecution process.
        """
        for scan in self.scans:
            print(scan)
            print(scan.name)
            print(scan.concurrentTasks)
            if getattr(scan, "concurrentTasks", 0):
                self.launch_scan_execution(scan)


# -----------------------------------------------------------------------------
# Lambda Handler
# -----------------------------------------------------------------------------
def handler(event, context):
    """
    Handler for invoking the scheduler to run scans.
    Expects 'scanIds' or 'scanId' in the event.
    """
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
    scheduler.initialize(scans, organizations, None, None)
    scheduler.run()

    print("Finished running scheduler.")
