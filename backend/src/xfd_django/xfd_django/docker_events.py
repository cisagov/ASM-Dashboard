import asyncio
import json
from docker import DockerClient
from docker.errors import DockerException

# Import your updateScanTaskStatus handler
from xfd_api.tasks.updateScanTaskStatus import handler as update_scan_task_status


def listen_for_docker_events():
    """
    Listens for Docker events and converts start/stop events to simulated
    Fargate EventBridge events for local development.
    """
    try:
        client = DockerClient.from_env()
        print("Listening for Docker events...")

        for event in client.events(decode=True):
            try:
                # Extract relevant event details
                status = event.get("status")
                actor = event.get("Actor", {})
                attributes = actor.get("Attributes", {})
                image_name = event.get("from")

                # Only process events related to 'crossfeed-worker'
                if image_name != "crossfeed-worker":
                    continue

                # Prepare the payload based on the event status
                payload = None
                if status == "start":
                    payload = {
                        "detail": {
                            "stopCode": "",
                            "stoppedReason": "",
                            "taskArn": attributes.get("name", ""),
                            "lastStatus": "RUNNING",
                            "containers": [{}],
                        }
                    }
                elif status == "die":
                    payload = {
                        "detail": {
                            "stopCode": "EssentialContainerExited",
                            "stoppedReason": "Essential container in task exited",
                            "taskArn": attributes.get("name", ""),
                            "lastStatus": "STOPPED",
                            "containers": [
                                {
                                    "exitCode": int(attributes.get("exitCode", 1)),
                                }
                            ],
                        }
                    }
                else:
                    continue

                # Log and process the event
                print(f"Processing Docker event: {json.dumps(payload, indent=2)}")
                # Use asyncio to process the event
                asyncio.run(update_scan_task_status(payload, None))
            except Exception as e:
                print(f"Error processing Docker event: {e}")

    except DockerException as e:
        print(f"Error connecting to Docker: {e}")
