"""
ASGI config for xfd_django project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/howto/deployment/asgi/
"""

# Standard Python Libraries
import asyncio
from asyncio import Semaphore
import os
import threading

# Third-Party Libraries
import django
from django.apps import apps
from django.conf import settings
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum
from redis import asyncio as aioredis
from xfd_api.tasks.scheduler import handler as scheduler_handler
from xfd_django.docker_events import listen_for_docker_events
from xfd_django.middleware.middleware import LoggingMiddleware

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()

# Ensure apps are populated
apps.populate(settings.INSTALLED_APPS)


def set_security_headers(response: Response):
    """Apply security headers to the HTTP response."""
    # Set Content Security Policy (CSP)
    csp_value = "; ".join(
        [
            "{} {}".format(key, " ".join(map(str, value)))
            for key, value in settings.SECURE_CSP_POLICY.items()
            if isinstance(value, (list, tuple))
        ]
    )
    response.headers["Content-Security-Policy"] = csp_value

    # Set Strict-Transport-Security (HSTS)
    hsts_value = f"max-age={settings.SECURE_HSTS_SECONDS}"
    if settings.SECURE_HSTS_PRELOAD:
        hsts_value += "; preload"
    if settings.SECURE_HSTS_INCLUDE_SUBDOMAINS:
        hsts_value += "; includeSubDomains"
    response.headers["Strict-Transport-Security"] = hsts_value

    # Additional security headers
    response.headers["X-XSS-Protection"] = (
        "1; mode=block" if settings.SECURE_BROWSER_XSS_FILTER else "0"
    )
    response.headers["X-Content-Type-Options"] = (
        "nosniff" if settings.SECURE_CONTENT_TYPE_NOSNIFF else ""
    )
    response.headers["Cache-Control"] = settings.SECURE_CACHE_CONTROL
    response.headers["Access-Control-Allow-Credentials"] = (
        "true" if settings.SECURE_ACCESS_CONTROL_ALLOW_CREDENTIALS else "false"
    )

    return response


def get_application() -> FastAPI:
    """Get application."""
    # Import views after Django setup
    # Third-Party Libraries
    from xfd_api.views import api_router  # pylint: disable=C0415

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
        # Initialize Redis with the ElastiCache endpoint
        app.state.redis = await aioredis.from_url(
            "redis://{}".format(settings.ELASTICACHE_ENDPOINT),
            encoding="utf-8",
            decode_responses=True,
            max_connections=100,
            socket_timeout=5,
        )
        app.state.redis_semaphore = Semaphore(20)

        # Run scheduler during local development. When deployed on AWS,
        # the scheduler runs on a separate lambda function.
        if settings.IS_LOCAL:
            # Start listening for Docker events
            run_docker_events_listener()

            # Start the scheduler in local development
            asyncio.create_task(run_scheduler())

    @app.on_event("shutdown")
    async def redis_shutdown():
        """Shut down Redis connection."""
        await app.state.redis.close()
        await app.state.redis.connection_pool.disconnect()

    return app


def run_docker_events_listener():
    """Run the Docker events listener for local development in a separate thread."""
    thread = threading.Thread(target=listen_for_docker_events, daemon=True)
    thread.start()
    print("Docker events listener started in a separate thread.")


async def run_scheduler():
    """Run the scheduler in local development."""
    try:
        print("Starting local scheduler...")
        while True:
            await scheduler_handler({}, {})
            await asyncio.sleep(120)  # Run every 120 seconds
    except Exception as e:
        print("Error running local scheduler: {}".format(e))


app = get_application()
handler = Mangum(app)
