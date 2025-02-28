"""Validation utilities for syncing operations."""

# Standard Python Libraries
from datetime import datetime, timezone

# Third-Party Libraries
from xfd_mini_dl.models import SyncChecksum


def save_validation_checksum(checksum: str, type: str) -> bool:
    """
    Save a validation checksum to the data lake.

    This function attempts to create a new SyncChecksum record in the database
    with the provided checksum and sync type. If the operation is successful,
    it returns True. If an exception occurs, it logs the error and returns False.

    Args:
        checksum (str): The checksum value to store.
        type (str): The type of sync operation associated with the checksum.

    Returns:
        bool: True if the checksum was successfully saved, False otherwise.
    """
    try:
        SyncChecksum.objects.create(
            checksum=checksum, sync_type=type, sync_date=datetime.now(timezone.utc)
        )
        return True
    except Exception as e:
        # Optionally, log the exception if needed
        print(f"Error saving checksum: {e}")
        return False
