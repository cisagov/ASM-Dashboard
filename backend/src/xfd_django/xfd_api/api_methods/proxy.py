"""API methods to support Proxy endpoints."""

# Standard Python Libraries
from typing import Optional

# Third-Party Libraries
from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse, Response
import httpx
from xfd_api.auth import get_current_active_user
from xfd_api.schema_models.user import User as UserSchema


# Helper function to proxy requests
async def proxy_request(
    request: Request,
    target_url: str,
    path: Optional[str] = None,
    cookie_name: Optional[str] = None,
):
    """Proxy requests to the specified target URL with optional cookie handling."""
    headers = dict(request.headers)

    # Include specified cookie in the headers if present
    if cookie_name:
        cookies = request.cookies.get(cookie_name)
        if cookies:
            headers["Cookie"] = f"{cookie_name}={cookies}"

    # Send the request to the target
    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
        proxy_response = await client.request(
            method=request.method,
            url=f"{target_url}/{path}" if path else target_url,
            headers=headers,
            params=request.query_params,
            content=await request.body(),
        )

    # Adjust response headers
    proxy_response_headers = dict(proxy_response.headers)
    for header in ["content-encoding", "transfer-encoding", "content-length"]:
        proxy_response_headers.pop(header, None)

    return Response(
        content=proxy_response.content,
        status_code=proxy_response.status_code,
        headers=proxy_response_headers,
    )


async def matomo_proxy_handler(
    request: Request,
    path: str,
    current_user: Optional[UserSchema],
    MATOMO_URL: str,
):
    """
    Handles Matomo-specific proxy logic, including public paths, font redirects,
    and authentication for private paths.
    """
    # Redirect font requests to CDN
    font_paths = {
        "/plugins/Morpheus/fonts/matomo.woff2": "https://cdn.jsdelivr.net/gh/matomo-org/matomo@5.2.1/plugins/Morpheus/fonts/matomo.woff2",
        "/plugins/Morpheus/fonts/matomo.woff": "https://cdn.jsdelivr.net/gh/matomo-org/matomo@5.2.1/plugins/Morpheus/fonts/matomo.woff",
        "/plugins/Morpheus/fonts/matomo.ttf": "https://cdn.jsdelivr.net/gh/matomo-org/matomo@5.2.1/plugins/Morpheus/fonts/matomo.ttf",
    }
    if path in font_paths:
        return RedirectResponse(url=font_paths[path])

    # Public paths allowed without authentication
    public_paths = ["matomo.php", "matomo.js", "index.php"]
    if path in public_paths:
        print("THIS IS A PUBLIC PATH")
        return await proxy_request(request, MATOMO_URL, path)

    # Authenticate private paths
    if not current_user:
        current_user = await get_current_active_user(request)
    if current_user is None or current_user.userType != "globalAdmin":
        raise HTTPException(status_code=403, detail="Unauthorized")

    # Proxy private paths
    return await proxy_request(
        request=request,
        target_url=MATOMO_URL,
        path=path,
        cookie_name="MATOMO_SESSID",
    )
