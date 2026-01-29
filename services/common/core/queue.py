"""
Message Queue Abstraction.

Handles asynchronous task dispatching and state management using Redis.
Includes a TaskQueue for job processing and StateManager for tracking scan progress.
"""

import redis
import json
import time
import uuid
from typing import Dict, Any, Optional

# Import from Vault secrets module (falls back to env vars if Vault unavailable)
from .secrets import get_redis_url

# --- REDIS CONFIGURATION ---
REDIS_URL = get_redis_url()

class RedisClient:
    """
    Singleton Redis client factory.
    Ensures only one connection pool is created across all imports.
    """
    _instance = None  # Class-level singleton instance

    @classmethod
    def get_client(cls):
        """
        Returns a shared Redis client instance.
        Creates connection on first call, reuses on subsequent calls.
        """
        if cls._instance is None:
            # decode_responses=True returns strings instead of bytes
            cls._instance = redis.from_url(REDIS_URL, decode_responses=True)
        return cls._instance



class StateManager:
    """
    Abstraction for Redis Hash-based Dashboard State.
    Tracks scan progress in real-time via Redis hashes.
    """
    def __init__(self, scan_id: int):
        self.scan_id = scan_id
        self.state_key = f"scan:{scan_id}:state"  # Redis key: scan:<id>:state
        self.client = RedisClient.get_client()

    def update_stage(self, stage: str):
        """Update the current stage name (e.g., 'Scanning', 'Analyzing')."""
        self.client.hset(self.state_key, mapping={
            "stage": stage,
            "updated_at": str(time.time())
        })

    def update_step(self, step: int, total: int, message: str, status: str = "running"):
        """Update progress step (e.g., step 3 of 10)."""
        self.client.hset(self.state_key, mapping={
            "step_number": step,
            "total_steps": total,
            "message": message,
            "status": status,
            "updated_at": str(time.time())
        })

    def complete(self):
        """Mark scan as completed."""
        self.client.hset(self.state_key, "status", "completed")

    def fail(self, error: str):
        """Mark scan as failed with error message."""
        self.client.hset(self.state_key, mapping={
            "status": "failed",
            "error": error
        })
