"""API methods to support Proxy endpoints."""

# Standard Python Libraries
import os
from typing import List, Optional
import httpx

# Third-Party Libraries
from django.shortcuts import render
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from pydantic import UUID4
from fastapi.responses import RedirectResponse, Response

# Helper function to handle cookie manipulation
def manipulate_cookie(request: Request, cookie_name: str):
    cookies = request.cookies.get(cookie_name)
    if cookies:
        return {cookie_name: cookies}
    return {}


# Helper function to proxy requests
async def proxy_request(request: Request,  target_url: str, path: Optional[str] = None, cookie_name: Optional[str] = None):
    """Proxy the request to the target URL."""
    headers = dict(request.headers)
    
    # Cookie manipulation for specific cookie names
    if cookie_name:
        cookies = manipulate_cookie(request, cookie_name)
        if cookies:
            headers['Cookie'] = f"{cookie_name}={cookies[cookie_name]}"
    
    # Make the request to the target URL
    async with httpx.AsyncClient() as client:
        proxy_response = await client.request(
            method=request.method,
            url=f"{target_url}/{path}",
            headers=headers,
            params=request.query_params,
            content=await request.body()
        )
    
    # Remove chunked encoding for API Gateway compatibility
    proxy_response_headers = dict(proxy_response.headers)
    proxy_response_headers.pop("transfer-encoding", None)
    
    return Response(
        content=proxy_response.content,
        status_code=proxy_response.status_code,
        headers=proxy_response_headers
    )