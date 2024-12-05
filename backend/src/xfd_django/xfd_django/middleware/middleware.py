# Standard Python Libraries
from datetime import datetime
import logging

# Third-Party Libraries
from pythonjsonlogger import jsonlogger
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class LoggingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.logger = self._configure_logger()

    def _configure_logger(self):
        logger = logging.getLogger("fastapi")
        if not logger.handlers:  # Avoid duplicate handlers
            log_handler = logging.StreamHandler()
            formatter = jsonlogger.JsonFormatter(
                "%(levelname)s RequestId: %(request_id)s %(asctime)s Request Info: %(message)s"
            )
            log_handler.setFormatter(formatter)
            logger.addHandler(log_handler)
            logger.setLevel(logging.INFO)
        return logger

    async def dispatch(self, request: Request, call_next):
        # Extract relevant request details
        headers = dict(request.headers)
        method = request.method
        path = request.url.path
        protocol = request.url.scheme
        original_url = str(request.url)

        # Get request ID from scope or set it to "undefined"
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

        # Proceed with the request
        response = await call_next(request)

        # Prepare log details
        log_info = {
            "httpMethod": method,
            "protocol": protocol,
            "originalURL": original_url,
            "path": path,
            "headers": headers,
            "userEmail": user_email,
            "statusCode": response.status_code,
            "timestamp": datetime.utcnow().isoformat(),
            "requestId": request_id,
        }

        # Log in JSON format
        self.logger.info(log_info)
        return response
