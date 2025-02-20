"""User event logging decorator."""
import functools
import inspect
from datetime import datetime
from asgiref.sync import sync_to_async
from fastapi import Request
import json

from xfd_api.models import Log, User, Organization, Role

async def maybe_async_call(func, *args, **kwargs):
    """Call a function and await it if it is a coroutine."""
    if inspect.iscoroutinefunction(func):
        return await func(*args, **kwargs)
    else:
        return func(*args, **kwargs)

def log_action(action: str, message_or_cb=None):
    """
    Decorator to log an event after an endpoint is executed.
    
    :param action: A string identifier for the event (e.g., "USER ASSIGNED").
    :param message_or_cb: Either a dict or a callable that returns a dict payload.
           If a callable, it will be passed the endpoint's parameters (for example,
           current_user, response, and any other parameters) and should return a dict.
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Try to extract the FastAPI Request and current_user if provided.
            request: Request = kwargs.get("request", None)
            current_user = kwargs.get("current_user", None)

            result = "success"
            response = None
            try:
                response = await func(*args, **kwargs)
            except Exception as e:
                result = "fail"
                raise e
            finally:
                try:
                    # Filter out keys that we are already passing explicitly.
                    filtered_kwargs = {k: v for k, v in kwargs.items() if k not in ["current_user", "response"]}
                    
                    # Determine the payload to log.
                    if callable(message_or_cb):
                        payload = await maybe_async_call(
                            message_or_cb, current_user=current_user, response=response, **filtered_kwargs
                        )
                    else:
                        payload = message_or_cb or {}

                    # Ensure payload is a dict and add a timestamp if missing.
                    if not isinstance(payload, dict):
                        payload = {}
                    if "timestamp" not in payload:
                        payload["timestamp"] = datetime.now().isoformat()

                    # Record the log entry using Django ORM.
                    await sync_to_async(Log.objects.create)(
                        payload=json.dumps(payload),
                        createdAt=payload["timestamp"],
                        result=result,
                        eventType=action,
                    )
                except Exception as log_error:
                    # If logging fails, print a warning (or use your logging system).
                    print("Logging error: {}".format(log_error))
            return response
        return wrapper
    return decorator

def get_organization_sync(org_id: str):
    return Organization.objects.get(id=org_id)

def get_user_sync(user_id: str):
    return User.objects.get(id=user_id)
