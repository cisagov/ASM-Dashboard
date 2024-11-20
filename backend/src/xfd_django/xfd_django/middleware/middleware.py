from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
import uuid
from xfd_api.helpers.logger import logger


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Generate a unique request ID
        request_id = str(uuid.uuid4())
        
        # Log request info
        logger.info(
            "Request received",
            extra={
                "request_id": request_id,
                "method": request.method,
                "url": str(request.url),
                "headers": {k: v for k, v in request.headers.items() if k.lower() != "authorization"}
            }
        )
        
        # Process the request
        response = await call_next(request)

        # Log response info
        logger.info(
            "Response sent",
            extra={
                "request_id": request_id,
                "status_code": response.status_code
            }
        )
        return response
