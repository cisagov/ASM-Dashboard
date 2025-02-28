"""Scan Execution."""
# Standard Libraries
# Standard Python Libraries
import json
import os
import random
import re

# Third-Party Libraries
import boto3
from botocore.exceptions import ClientError
import django

# Django setup
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()


# Initialize AWS clients

SCAN_LIST = [
    "asmSync",
    "cybersixgill-alerts",
    "cybersixgill-credentials",
    "cybersixgill-mentions",
    "cybersixgill-topcves",
    "dnsmonitor",
    "dnstwist",
    "intelx",
    "qualys",
    "shodan",
    "xpanse",
]
QUEUE_URL = os.getenv("QUEUE_URL")

# Conditionally import Docker if in local environment
docker = None
if os.getenv("IS_LOCAL"):
    # Third-Party Libraries
    from docker import DockerClient

    docker = DockerClient(base_url="unix://var/run/docker.sock")
else:
    ecs_client = boto3.client("ecs")


def to_snake_case(input_string):
    """Convert a string to snake-case."""
    return re.sub(r"\s+", "-", input_string)


def start_desired_tasks(scan_type, desired_count, shodan_api_keys=None):
    """Start the desired number of tasks on AWS ECS or local Docker based on configuration."""
    shodan_api_keys = shodan_api_keys or []
    queue_url = "{}{}-queue".format(QUEUE_URL, scan_type)

    batch_size = 1 if scan_type in ["shodan", "asmSync"] else 10
    remaining_count = desired_count

    while remaining_count > 0:
        current_batch_count = min(remaining_count, batch_size)
        shodan_api_key = shodan_api_keys[remaining_count - 1] if shodan_api_keys else ""

        if os.getenv("IS_LOCAL"):
            # Use local Docker environment
            print("Starting local containers...")
            start_local_containers(
                current_batch_count, scan_type, queue_url, shodan_api_key
            )
        else:
            # Use AWS ECS
            try:
                ecs_client.run_task(
                    cluster=os.getenv("PE_FARGATE_CLUSTER_NAME"),
                    taskDefinition=os.getenv("PE_FARGATE_TASK_DEFINITION_NAME"),
                    networkConfiguration={
                        "awsvpcConfiguration": {
                            "assignPublicIp": "ENABLED",
                            "securityGroups": [os.getenv("FARGATE_SG_ID")],
                            "subnets": [os.getenv("FARGATE_SUBNET_ID")],
                        }
                    },
                    platformVersion="1.4.0",
                    launchType="FARGATE",
                    count=current_batch_count,
                    overrides={
                        "containerOverrides": [
                            {
                                "name": "main",
                                "environment": [
                                    {"name": "SERVICE_TYPE", "value": scan_type},
                                    {"name": "SERVICE_QUEUE_URL", "value": queue_url},
                                    {
                                        "name": "PE_SHODAN_API_KEYS",
                                        "value": shodan_api_key,
                                    },
                                ],
                            }
                        ]
                    },
                )
                print("Tasks started: {}".format(current_batch_count))
            except ClientError as e:
                print("Error starting tasks: {}".format(e))
                raise e

        remaining_count -= current_batch_count


def start_local_containers(count, scan_type, queue_url, shodan_api_key=""):
    """Start the desired number of local Docker containers."""
    for i in range(count):
        try:
            container_name = to_snake_case(
                "crossfeed_worker_{}_{}_{}".format(
                    scan_type, i, random.randint(1, 10_000_000)
                )
            )
            container = docker.containers.create(
                name=container_name,
                image="pe-worker",
                network_mode="xfd_backend",
                mem_limit="4g",
                detach=True,
                environment=[
                    "DB_DIALECT={}".format(os.getenv("DB_DIALECT")),
                    "DB_HOST={}".format(os.getenv("DB_HOST")),
                    "IS_LOCAL=true",
                    "DB_PORT={}".format(os.getenv("DB_PORT")),
                    "DB_NAME={}".format(os.getenv("DB_NAME")),
                    "DB_USERNAME={}".format(os.getenv("DB_USERNAME")),
                    "DB_PASSWORD={}".format(os.getenv("DB_PASSWORD")),
                    "SERVICE_QUEUE_URL={}".format(queue_url),
                    "SERVICE_TYPE={}".format(scan_type),
                    "PE_SHODAN_API_KEYS={}".format(shodan_api_key),
                    "WHOIS_XML_KEY={}".format(os.getenv("WHOIS_XML_KEY")),
                    "QUALYS_USERNAME={}".format(os.getenv("QUALYS_USERNAME")),
                    "QUALYS_PASSWORD={}".format(os.getenv("QUALYS_PASSWORD")),
                ],
            )
            container.start()
            print("Started container: {}".format(container_name))
        except Exception as e:
            print("Error starting container {}: {}".format(i, e))


def handler(event, context):
    """Handle the AWS Lambda event to start tasks on ECS or Docker."""
    try:
        desired_count = event.get("desiredCount", 1)
        scan_type = event.get("scanType")

        if not scan_type:
            print("scanType must be provided.")
            return {"statusCode": 400, "body": "Failed: no scanType provided."}

        if scan_type in ["shodan", "asmSync"]:
            api_key_list = event.get("apiKeyList", "")
            shodan_api_keys = (
                [key.strip() for key in api_key_list.split(",")] if api_key_list else []
            )

            if len(shodan_api_keys) < desired_count:
                print("Not enough API keys provided for Shodan tasks.")
                return {
                    "statusCode": 400,
                    "body": "Failed: insufficient API keys for Shodan.",
                }

            start_desired_tasks(scan_type, desired_count, shodan_api_keys)
        elif scan_type in SCAN_LIST:
            start_desired_tasks(scan_type, desired_count)
        else:
            print("Invalid scanType. Must be one of:", ", ".join(SCAN_LIST))
            return {"statusCode": 400, "body": "Invalid scanType provided."}

        return {"statusCode": 200, "body": "Tasks started successfully."}
    except Exception as e:
        print("Error in handler: {}".format(e))
        return {"statusCode": 500, "body": json.dumps(str(e))}
