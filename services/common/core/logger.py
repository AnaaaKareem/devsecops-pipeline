"""
Centralized Logging Module.

Provides a standardized logger with JSON formatting for observability tools (Loki).
Guarantees consistent JSON structure for all logs.
"""

import logging
import sys
import os
import json
import datetime
import traceback

class JsonFormatter(logging.Formatter):
    """
    Custom formatter to output logs in JSON format for Loki/Grafana ingestion.
    """
    def format(self, record):
        # Build base log record with standard fields
        log_record = {
            "timestamp": datetime.datetime.fromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "name": record.name,
            "service": os.getenv("SERVICE_NAME", "unknown"),  # Service name from env
            "message": record.getMessage(),
            "module": record.module,
            "func": record.funcName,
            "process": record.process,
            "thread": record.thread,
        }
        
        # Include exception info and traceback if present
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
            log_record["traceback"] = traceback.format_exception(*record.exc_info)

        # Merge custom metrics/context passed via extra_info kwarg
        if hasattr(record, 'extra_info') and isinstance(record.extra_info, dict):
            log_record.update(record.extra_info)
            
        return json.dumps(log_record)  # Serialize to JSON string

class CustomAdapter(logging.LoggerAdapter):
    """
    Adapter to allow passing 'extra_info' as a keyword argument.
    Enables: logger.info("msg", extra_info={"event": "scan_start"})
    """
    def process(self, msg, kwargs):
        # Extract extra_info from kwargs and merge into 'extra' dict
        extra_info = kwargs.pop('extra_info', {})
        extra = kwargs.get('extra', {})
        if extra_info:
            extra['extra_info'] = extra_info
        
        kwargs['extra'] = extra
        return msg, kwargs

def get_logger(name: str):
    """
    Factory to retrieve a configured logger with JSON formatting.

    Args:
        name (str): The name of the logger (usually __name__).

    Returns:
        CustomAdapter: The wrapped logger instance.
    """
    logger = logging.getLogger(name)
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logger.setLevel(log_level)

    # Clear existing handlers to prevent duplicate logs on re-import
    if logger.hasHandlers():
        logger.handlers.clear()

    # File Handler - writes JSON logs to shared volume for Loki
    service_name = os.getenv("SERVICE_NAME", "unknown_service")
    log_dir = "/app/logs"
    
    if os.path.exists(log_dir):
        log_file = os.path.join(log_dir, f"{service_name}.json")
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(JsonFormatter())
        logger.addHandler(file_handler)

    # Stream Handler - outputs to stdout for Docker log collection
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(JsonFormatter())
    logger.addHandler(stream_handler)

    logger.propagate = False  # Prevent duplicate logs from parent loggers
    
    return CustomAdapter(logger, {})
