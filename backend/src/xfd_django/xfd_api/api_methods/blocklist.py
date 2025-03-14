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
    ip_obj = None
    try:
        ip_obj = Blocklist.objects.get(ip=ip_address)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    if ip_obj:
        return {"status": "BLOCKED"}
    return {"status": "UNBLOCKED"}
