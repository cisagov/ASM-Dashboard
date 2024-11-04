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
from django.core.wsgi import get_wsgi_application
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.wsgi import WSGIMiddleware
from mangum import Mangum
from redis import asyncio as aioredis

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "xfd_django.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()

# Ensure apps are populated
apps.populate(settings.INSTALLED_APPS)


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
    app.include_router(api_router)

    app.mount("/", WSGIMiddleware(get_wsgi_application()))

    @app.on_event("startup")
    async def startup():
        """Start up Redis with ElastiCache."""
        # Initialize Redis with the ElastiCache endpoint using the modern Redis-Py Asyncio
        app.state.redis = await aioredis.from_url(
            f"redis://{settings.ELASTICACHE_ENDPOINT}",
            encoding="utf-8",
            decode_responses=True,
        )

    @app.on_event("shutdown")
    async def redis_shutdown():
        """Shut down Redis connection."""
        await app.state.redis.close()

    return app


app = get_application()
handler = Mangum(app)
