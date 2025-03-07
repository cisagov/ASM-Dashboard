#!/usr/bin/env python
import os
import sys
import json
import importlib
import time

import django
from xfd_api.schema_models.scan import SCAN_SCHEMA

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()

import boto3

# ElasticMQ/SQS Configuration
QUEUE_URL = os.getenv("QUEUE_URL")

if not QUEUE_URL:
    print("QUEUE_URL environment variable is not set. Exiting.")
    sys.exit(1)

# Detect if using ElasticMQ (local) or AWS SQS (prod)
USE_ELASTICMQ = "elasticmq" in QUEUE_URL or "localhost" in QUEUE_URL

# Set correct SQS client configuration
sqs = boto3.client(
    "sqs",
    region_name=os.getenv("AWS_REGION", "us-east-1"),
    endpoint_url=QUEUE_URL if USE_ELASTICMQ else None
)

def get_message(queue_url):
    """Retrieve a message from the queue (ElasticMQ or AWS SQS)."""
    try:
        response = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        messages = response.get("Messages", [])
        if not messages:
            return None
        return messages[0]
    except Exception as e:
        print("Error retrieving message: {}".format(e))
        return None

def delete_message(queue_url, receipt_handle):
    """Delete a processed message from the queue."""
    try:
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
        print("Deleted processed message.")
    except Exception as e:
        print("Error deleting message: {}".format(e))

def process_message(message_data):
    """Extract and process the message data."""
    try:
        message = json.loads(message_data.get("Body", "{}"))
    except Exception:
        message = {"org": message_data.get("Body")}
    return message

def main():
    """Main worker loop."""
    try:
        command_options = json.loads(os.getenv("CROSSFEED_COMMAND_OPTIONS", "{}"))
    except Exception:
        command_options = {}

    print("Base command options: {}".format(command_options))
    
    scan_name = command_options.get("scanName", "test")
    SERVICE_QUEUE_URL = command_options.get("SERVICE_QUEUE_URL")

    if not SERVICE_QUEUE_URL:
        print("SERVICE_QUEUE_URL not set in command options. Exiting.")
        sys.exit(1)

    # Detect if using ElasticMQ
    is_local = os.getenv("IS_LOCAL")

    if is_local:
        full_queue_path_name = "http://localhost:9324/000000000000/{}-{}-queue".format("dev", scan_name)
    else:
        full_queue_path_name = SERVICE_QUEUE_URL

    print("Polling queue: {}".format(full_queue_path_name))

    # Import scan handler **once** before the loop
    try:
        task_module = importlib.import_module(f"xfd_api.tasks.{scan_name}")
        scan_fn = getattr(task_module, "handler", None)
        if not callable(scan_fn):
            raise ValueError("No handler function found for scan name: {}".format(scan_name))
    except ModuleNotFoundError:
        raise ValueError("No task handler found for scan name: {}".format(scan_name))
    
    scan_schema = SCAN_SCHEMA.get(scan_name)
    if not scan_schema:
        raise ValueError("No schema found for scan name: {}".format(scan_name))

    while True:
        message_data = get_message(full_queue_path_name)
        if not message_data:
            print("No new messages in the queue. Exiting worker loop.")
            break

        message = process_message(message_data)
        org = message.get("org")
        org_id = message.get("id")
        if not org:
            print("No organization found in the message. Skipping.")
            continue

        print("Processing organization: {}".format(org))

        # Ensure `scan_fn` is still valid
        if not callable(scan_fn):
            raise ValueError("scan_fn is no longer callable. Something went wrong.")

        task_options = dict(command_options)
        if not getattr(scan_schema, "global_scan", False):
            task_options.update({
                "organizationName": org,
                "organizationId": org_id,
                "organizations": []
            })

        scan_fn(task_options)  # No more `await`

        receipt_handle = message_data.get("ReceiptHandle")
        if receipt_handle:
            delete_message(full_queue_path_name, receipt_handle)
        else:
            print("No ReceiptHandle found; cannot delete message.")

        time.sleep(1)  # Pause before fetching next message

    print("Worker finished successfully.")

if __name__ == "__main__":
    main()
