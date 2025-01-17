"""API methods to support Proxy endpoints."""

# Standard Python Libraries
from typing import Optional

# Third-Party Libraries
from fastapi import Request
from fastapi.responses import Response
import httpx


# Helper function to handle cookie manipulation
def manipulate_cookie(request: Request, cookie_name: str):
    """Manipulate cookie."""
    cookies = request.cookies.get(cookie_name)
    if cookies:
        return {cookie_name: cookies}
    return {}


# Helper function to proxy requests
async def proxy_request(
    request: Request,
    target_url: str,
    path: Optional[str] = None,
    cookie_name: Optional[str] = None,
    public_paths: Optional[list] = None,
):
    """
    Proxy the request to the target URL.

    - Handles public paths without authentication.
    - Manipulates cookies for session-based authentication.
    """
    headers = dict(request.headers)

    # Handle public paths
    if public_paths and path in public_paths:
        async with httpx.AsyncClient() as client:
            proxy_response = await client.request(
                method=request.method,
                url=f"{target_url}/{path}",
                headers=headers,
                params=request.query_params,
                content=await request.body(),
            )
        proxy_response_headers = dict(proxy_response.headers)
        proxy_response_headers.pop("transfer-encoding", None)

        return Response(
            content=proxy_response.content,
            status_code=proxy_response.status_code,
            headers=proxy_response_headers,
        )

    # Handle cookies for private paths
    if cookie_name:
        cookies = manipulate_cookie(request, cookie_name)
        if cookies:
            headers["Cookie"] = f"{cookie_name}={cookies[cookie_name]}"

    # Make the request to the target URL
    async with httpx.AsyncClient() as client:
        proxy_response = await client.request(
            method=request.method,
            url=f"{target_url}/{path}",
            headers=headers,
            params=request.query_params,
            content=await request.body(),
        )

    # Remove chunked encoding for API Gateway compatibility
    proxy_response_headers = dict(proxy_response.headers)
    proxy_response_headers.pop("transfer-encoding", None)

    return Response(
        content=proxy_response.content,
        status_code=proxy_response.status_code,
        headers=proxy_response_headers,
    )
