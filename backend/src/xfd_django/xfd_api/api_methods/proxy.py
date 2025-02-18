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

    # Remove /matomo from the path
    if path and path.startswith("matomo"):
        path = path.replace("matomo", "", 1)
    
    # Include specified cookie in the headers if present
    if cookie_name:
        cookies = request.cookies.get(cookie_name)
        if cookies:
            headers["Cookie"] = "{}={}".format(cookie_name, cookies)

    if target_url:
        print("target is : ", target_url)
    else:
        print("target is empty: ", target_url)

    print("This is the path: ", path)
    # Send the request to the target
    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
        proxy_response = await client.request(
            method=request.method,
            url="{}/{}".format(target_url, path),
            headers=headers,
            params=request.query_params,
            content=await request.body(),
        )
    

    # # Capture and forward cookies from Matomo response
    # set_cookie = proxy_response.headers.get("set-cookie")
    # if set_cookie and cookie_name in set_cookie:
    #     # Extract MATOMO_SESSID from set-cookie
    #     from http.cookies import SimpleCookie
    #     cookie = SimpleCookie()
    #     cookie.load(set_cookie)
    #     session_id = cookie[cookie_name].value
        
    #     # Set the cookie in the response header
    #     proxy_response_headers = dict(proxy_response.headers)
    #     proxy_response_headers["set-cookie"] = f"{cookie_name}={session_id}; Path=/; HttpOnly; Secure; SameSite=Lax"
    # else:
    #     proxy_response_headers = dict(proxy_response.headers)

    # Adjust response headers
    proxy_response_headers = dict(proxy_response.headers)
    for header in ["content-encoding", "transfer-encoding", "content-length"]:
        proxy_response_headers.pop(header, None)

    print("Proxy response response: ", proxy_response)
    print("Proxy params: ", request.query_params)
    # print("Proxy response content: ", proxy_response.content)
    print("Proxy response headers: ", proxy_response_headers)

    return Response(
        content=proxy_response.content,
        status_code=proxy_response.status_code,
        headers=proxy_response_headers,
    )


async def matomo_proxy_handler(
    request: Request,
    path: str,
    MATOMO_URL: str,
):
    """
    Handle Matomo-specific proxy logic.

    Includes public paths, font redirects, and authentication for private paths.
    """
    # Redirect font requests to CDN
    font_paths = {
        "/plugins/Morpheus/fonts/matomo.woff2": "https://cdn.jsdelivr.net/gh/matomo-org/matomo@5.2.1/plugins/Morpheus/fonts/matomo.woff2",
        "/plugins/Morpheus/fonts/matomo.woff": "https://cdn.jsdelivr.net/gh/matomo-org/matomo@5.2.1/plugins/Morpheus/fonts/matomo.woff",
        "/plugins/Morpheus/fonts/matomo.ttf": "https://cdn.jsdelivr.net/gh/matomo-org/matomo@5.2.1/plugins/Morpheus/fonts/matomo.ttf",
    }
    if path in font_paths:
        return RedirectResponse(url=font_paths[path])


    # Proxy private paths
    return await proxy_request(
        request=request,
        target_url=MATOMO_URL,
        path=path,
        cookie_name="MATOMO_SESSID",
    )
