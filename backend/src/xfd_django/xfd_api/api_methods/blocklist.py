"""Blocklist API."""

# Third-Party Libraries
from fastapi import HTTPException
from xfd_mini_dl.models import Blocklist


async def handle_check_ip(ip_address: str):
    """
    Determine if an IP exists in our blocklist table.

    Returns:
        { status: "BLOCKED" or "UNBLOCKED" }
    """
    try:
        Blocklist.objects.get(ip=ip_address)
        return {"status": "BLOCKED"}
    except Blocklist.DoesNotExist:
        return {"status": "UNBLOCKED"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
