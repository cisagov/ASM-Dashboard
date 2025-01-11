"""Worker controller."""
# Standard Python Libraries
import importlib
import json
import os

# Third-Party Libraries
import django
from xfd_api.schema_models.scan import SCAN_SCHEMA

# Set up Django environment
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"

# Initialize Django
django.setup()


async def main():
    """Route tasks based on command options."""
    # Parse command options from the environment
    command_options = json.loads(os.getenv("CROSSFEED_COMMAND_OPTIONS", "{}"))
    print("Command options:", command_options)

    # Extract key fields
    scan_name = command_options.get("scanName", "test")
    organizations = command_options.get("organizations", [])

    # Validate the scan name and dynamically load the appropriate handler
    try:
        task_module = importlib.import_module("xfd_api.tasks.{}".format(scan_name))
        scan_fn = task_module.handler
    except ModuleNotFoundError:
        raise ValueError("No task handler found for scan name: {}".format(scan_name))

    # Fetch scan schema
    scan_schema = SCAN_SCHEMA.get(scan_name)
    if not scan_schema:
        raise ValueError("No schema found for scan name: {}".format(scan_name))

    # Execute the task
    if getattr(scan_schema, "global_scan", False):
        await scan_fn(command_options)
    else:
        # Non-global task: execute per organization
        for org in organizations:
            await scan_fn(
                {
                    **command_options,
                    "organizationId": org["id"],
                    "organizationName": org["name"],
                    "organizations": [],
                }
            )

    print("Task execution completed successfully.")


if __name__ == "__main__":
    # Standard Python Libraries
    import asyncio

    asyncio.run(main())
