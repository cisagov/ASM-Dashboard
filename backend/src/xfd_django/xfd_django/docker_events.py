"""Docker event listener."""
# Standard Python Libraries
import asyncio
import json

# Third-Party Libraries
from django.conf import settings

if settings.IS_LOCAL:
    # Third-Party Libraries
    from docker import DockerClient

# Import your updateScanTaskStatus handler
# Third-Party Libraries
from xfd_api.tasks.updateScanTaskStatus import handler as update_scan_task_status


def listen_for_docker_events():
    """Listen for Docker events."""
    try:
        if not settings.IS_LOCAL:
            client = DockerClient.from_env()
            print("Listening for Docker events...")
        else:
            print("No docker client")
            return

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
                print(
                    "Processing Docker event: {}".format(json.dumps(payload, indent=2))
                )
                # Use asyncio to process the event
                asyncio.run(update_scan_task_status(payload, None))
            except Exception as e:
                print("Error processing Docker event: {}".format(e))

    except Exception as e:
        print("Error connecting to Docker: {}".format(e))
