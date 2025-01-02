# Standard Python Libraries
from datetime import datetime
import logging
import json

# Third-Party Libraries
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class LoggingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.logger = self._configure_logger()

    def _configure_logger(self):
        logger = logging.getLogger("fastapi")
        logger.propagate = False  # Prevent duplicate logs
        if not logger.handlers:
            log_handler = logging.StreamHandler()
            log_handler.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(log_handler)
            logger.setLevel(logging.INFO)
        return logger

    async def dispatch(self, request: Request, call_next):
        # Extract request details
        method = request.method
        protocol = request.url.scheme
        original_url = str(request.url)
        path = request.url.path
        headers = dict(request.headers)

        # Retrieve request ID
        aws_context = request.scope.get("aws.context", None)
        request_id = (
            getattr(aws_context, "aws_request_id", "undefined")
            if aws_context
            else "undefined"
        )

        # Default to "undefined" for userEmail if not provided
        user_email = (
            request.state.user_email
            if hasattr(request.state, "user_email")
            else "undefined"
        )

        # Log the initial request
        start_log = {
            "httpMethod": method,
            "protocol": protocol,
            "originalURL": original_url,
            "path": path,
            "statusCode": None,  # Status is not known at this point
            "headers": headers,
            "userEmail": user_email,
        }
        self.logger.info(
            f"INFO RequestId: {request_id} {datetime.utcnow().isoformat()}Z Request Info: {json.dumps(start_log)}"
        )

        # Process the request and capture the response
        start_time = datetime.utcnow()
        response = await call_next(request)
        end_time = datetime.utcnow()

        # Update userEmail after endpoint execution if it was set
        user_email = (
            request.state.user_email
            if hasattr(request.state, "user_email")
            else user_email
        )

        # Log the completed request
        end_log = {
            "httpMethod": method,
            "protocol": protocol,
            "originalURL": original_url,
            "path": path,
            "statusCode": response.status_code,
            "headers": headers,
            "userEmail": user_email,
            "durationMs": (end_time - start_time).total_seconds() * 1000,  # Response time in ms
        }
        self.logger.info(
            f"INFO RequestId: {request_id} {end_time.isoformat()}Z Request Info: {json.dumps(end_log)}"
        )

        return response
