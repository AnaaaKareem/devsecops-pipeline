"""
Celery Configuration Module.

Configures the Celery distributed task queue for the Orchestrator service.
This enables asynchronous processing of security scan and triage jobs.

Configuration:
    - Broker: RabbitMQ (for task distribution)
    - Backend: Redis (for result storage)
    - Concurrency: 1 (sequential processing to avoid resource contention)

The module also prevents Celery from hijacking the application's logging
configuration to ensure consistent log formatting.
"""

from celery import Celery
from celery.signals import setup_logging

# Import from Vault secrets module (falls back to env vars if Vault unavailable)
from common.core.secrets import get_rabbitmq_url, get_redis_url


@setup_logging.connect
def config_loggers(*args, **kwargs):
    """
    Prevents Celery from overriding the application's logging configuration.
    
    This signal handler is intentionally empty to ensure that logs formatted
    by our custom logger (get_logger) are not suppressed or reformatted.
    """
    pass

# Broker URL (RabbitMQ) and Backend (Redis) from Vault
RABBITMQ_URL = get_rabbitmq_url()
REDIS_URL = get_redis_url()

celery_app = Celery(
    "orchestrator",
    broker=RABBITMQ_URL,
    backend=REDIS_URL,
    include=["tasks"]
)

# Configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    worker_hijack_root_logger=False, # Double insurance
    worker_concurrency=1, # Enforce sequential processing default
    task_acks_late=True, # Ensure robustness
)
