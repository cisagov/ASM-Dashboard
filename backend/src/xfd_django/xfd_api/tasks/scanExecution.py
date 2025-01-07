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
    "dnstwist",
    "intelx",
    "cybersixgill",
    "shodan",
    "xpanse",
    "asmSync",
    "qualys",
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
    queue_url = f"{QUEUE_URL}{scan_type}-queue"

    batch_size = 1 if scan_type == "shodan" else 10
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
                print(f"Tasks started: {current_batch_count}")
            except ClientError as e:
                print(f"Error starting tasks: {e}")
                raise e

        remaining_count -= current_batch_count


def start_local_containers(count, scan_type, queue_url, shodan_api_key=""):
    """Start the desired number of local Docker containers."""
    for i in range(count):
        try:
            container_name = to_snake_case(
                f"crossfeed_worker_{scan_type}_{i}_{random.randint(1, 10_000_000)}"
            )
            container = docker.containers.create(
                name=container_name,
                image="pe-worker",
                network_mode="xfd_backend",
                mem_limit="4g",
                detach=True,
                environment=[
                    f"DB_DIALECT={os.getenv('DB_DIALECT')}",
                    f"DB_HOST={os.getenv('DB_HOST')}",
                    "IS_LOCAL=true",
                    f"DB_PORT={os.getenv('DB_PORT')}",
                    f"DB_NAME={os.getenv('DB_NAME')}",
                    f"DB_USERNAME={os.getenv('DB_USERNAME')}",
                    f"DB_PASSWORD={os.getenv('DB_PASSWORD')}",
                    f"SERVICE_QUEUE_URL={queue_url}",
                    f"SERVICE_TYPE={scan_type}",
                    f"PE_SHODAN_API_KEYS={shodan_api_key}",
                    f"WHOIS_XML_KEY={os.getenv('WHOIS_XML_KEY')}",
                    f"QUALYS_USERNAME={os.getenv('QUALYS_USERNAME')}",
                    f"QUALYS_PASSWORD={os.getenv('QUALYS_PASSWORD')}",
                ],
            )
            container.start()
            print(f"Started container: {container_name}")
        except Exception as e:
            print(f"Error starting container {i}: {e}")


def handler(event, context):
    """Handle the AWS Lambda event to start tasks on ECS or Docker."""
    try:
        desired_count = event.get("desiredCount", 1)
        scan_type = event.get("scanType")

        if not scan_type:
            print("scanType must be provided.")
            return {"statusCode": 400, "body": "Failed: no scanType provided."}

        if scan_type == "shodan":
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
        print(f"Error in handler: {e}")
        return {"statusCode": 500, "body": json.dumps(str(e))}
