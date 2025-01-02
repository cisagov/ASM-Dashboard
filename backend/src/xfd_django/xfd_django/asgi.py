"""
ASGI config for xfd_django project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/howto/deployment/asgi/
"""

# Standard Python Libraries
import os

# Third-Party Libraries
import django
from django.apps import apps
from django.conf import settings
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum
from redis import asyncio as aioredis
from asyncio import Semaphore
from xfd_django.middleware.middleware import LoggingMiddleware

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()

# Ensure apps are populated
apps.populate(settings.INSTALLED_APPS)

# Define the CSP policy
CSP_POLICY = {
    "default-src": ["'self'"],
    "connect-src": [
        "'self'",
        os.getenv("COGNITO_URL"),
        os.getenv("BACKEND_DOMAIN"),
        "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui-bundle.js",
    ],
    "frame-src": ["'self'", "https://www.dhs.gov/ntas/"],
    "img-src": [
        "'self'",
        "data:",
        os.getenv("FRONTEND_DOMAIN"),
        "https://www.ssa.gov",
        "https://www.dhs.gov",
        "https://fastapi.tiangolo.com/img/favicon.png",
    ],
    "object-src": ["'none'"],
    "script-src": [
        "'self'",
        os.getenv("BACKEND_DOMAIN"),
        "https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js",
        "https://www.ssa.gov/accessibility/andi/fandi.js",
        "https://www.ssa.gov/accessibility/andi/andi.js",
        "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui-bundle.js",
        "'sha256-QOOQu4W1oxGqd2nbXbxiA1Di6OHQOLQD+o+G9oWL8YY='",
        "https://www.dhs.gov",
    ],
    "style-src": [
        "'self'",
        "'unsafe-inline'",
        "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui.css",
    ],
    "frame-ancestors": ["'none'"],
}


def set_security_headers(response: Response):
    """
    Apply security headers to the HTTP response.
    """
    # Set Content Security Policy
    csp_value = "; ".join(
        [
            f"{key} {' '.join(map(str, value))}"
            for key, value in CSP_POLICY.items()
            if isinstance(value, (list, tuple))
        ]
    )
    response.headers["Content-Security-Policy"] = csp_value
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    response.headers["X-XSS-Protection"] = "0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Access-Control-Allow-Credentials"] = "true"

    return response


def get_application() -> FastAPI:
    """get_application function."""
    # Import views after Django setup
    # Third-Party Libraries
    from xfd_api.views import api_router

    app = FastAPI(title=settings.PROJECT_NAME, debug=settings.DEBUG)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_HOSTS or ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add security headers middleware
    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        response = await call_next(request)
        return set_security_headers(response)

    app.add_middleware(LoggingMiddleware)
    
    app.include_router(api_router)

    @app.on_event("startup")
    async def startup():
        """Start up Redis with ElastiCache."""
        # Initialize Redis with the ElastiCache endpoint using the modern Redis-Py Asyncio
        app.state.redis = await aioredis.from_url(
            f"redis://{settings.ELASTICACHE_ENDPOINT}",
            encoding="utf-8",
            decode_responses=True,
            max_connections=100,
            socket_timeout=5,
        )
        app.state.redis_semaphore = Semaphore(20)

    @app.on_event("shutdown")
    async def redis_shutdown():
        """Shut down Redis connection."""
        await app.state.redis.close()
        await app.state.redis.connection_pool.disconnect()

    return app


app = get_application()
handler = Mangum(app)
