import logging
import json
import uuid
from pythonjsonlogger import jsonlogger

# Custom formatter for JSON logs
class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        log_record['level'] = record.levelname.upper()
        log_record['timestamp'] = self.formatTime(record, self.datefmt)
        log_record['request_id'] = getattr(record, 'request_id', None) or 'undefined'

# Initialize the logger
def setup_logger(name="app"):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Create handler
    handler = logging.StreamHandler()
    formatter = CustomJsonFormatter('%(level)s %(request_id)s %(timestamp)s %(message)s')
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    return logger

logger = setup_logger()
