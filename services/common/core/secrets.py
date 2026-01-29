"""
Vault Secrets Management Module.

Provides a centralized interface for retrieving secrets from HashiCorp Vault
with fallback to environment variables for backward compatibility.

Key features:
- Automatic token discovery from shared volume
- LRU caching for performance
- Graceful fallback to environment variables
"""

import os
import logging
from functools import lru_cache
from typing import Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

# Vault configuration
VAULT_ADDR = os.getenv("VAULT_ADDR", "http://vault:8200")
VAULT_TOKEN_FILE = Path("/vault/data/.root-token")
VAULT_ENABLED = os.getenv("VAULT_ENABLED", "true").lower() == "true"

_vault_client = None


def _get_vault_token() -> Optional[str]:
    """Get Vault token from environment or token file."""
    # First try environment variable
    token = os.getenv("VAULT_TOKEN")
    if token:
        return token
    
    # Then try reading from shared volume
    if VAULT_TOKEN_FILE.exists():
        try:
            return VAULT_TOKEN_FILE.read_text().strip()
        except Exception as e:
            logger.debug(f"Could not read token file: {e}")
    
    return None


def _get_vault_client():
    """Lazily initialize and return the Vault client."""
    global _vault_client
    
    if _vault_client is not None:
        return _vault_client
    
    if not VAULT_ENABLED:
        return None
    
    token = _get_vault_token()
    if not token:
        logger.info("No Vault token available, using environment variables")
        return None
    
    try:
        import hvac
        _vault_client = hvac.Client(url=VAULT_ADDR, token=token)
        if _vault_client.is_authenticated():
            logger.info("Successfully connected to Vault")
            return _vault_client
        else:
            logger.warning("Vault authentication failed, falling back to env vars")
            _vault_client = None
    except ImportError:
        logger.warning("hvac package not installed, using environment variables")
    except Exception as e:
        logger.warning(f"Vault connection failed: {e}, falling back to env vars")
    
    return None


@lru_cache(maxsize=128)
def get_secret(path: str, key: str, default: Optional[str] = None) -> Optional[str]:
    """
    Retrieve a secret from Vault, with fallback to environment variables.
    
    Args:
        path: The Vault secret path (e.g., 'secret/database')
        key: The key within the secret (e.g., 'url')
        default: Default value if secret not found
        
    Returns:
        The secret value or default
    """
    # Try Vault first
    client = _get_vault_client()
    if client:
        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=path.replace("secret/", ""),
                mount_point="secret"
            )
            value = response["data"]["data"].get(key)
            if value is not None:
                return value
        except Exception as e:
            logger.debug(f"Vault lookup failed for {path}/{key}: {e}")
    
    # Fallback to environment variables
    env_key = f"{path.split('/')[-1].upper()}_{key.upper()}"
    return os.getenv(env_key, default)


def get_secrets(path: str) -> Dict[str, Any]:
    """
    Retrieve all secrets at a path from Vault.
    
    Args:
        path: The Vault secret path (e.g., 'secret/database')
        
    Returns:
        Dictionary of all secrets at that path
    """
    client = _get_vault_client()
    if client:
        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=path.replace("secret/", ""),
                mount_point="secret"
            )
            return response["data"]["data"]
        except Exception as e:
            logger.debug(f"Vault lookup failed for {path}: {e}")
    return {}


# =============================================================================
# Convenience Functions for Common Secrets
# =============================================================================

def get_database_url() -> str:
    """Get the database connection URL."""
    return get_secret("secret/database", "url", 
                      os.getenv("DATABASE_URL", "sqlite:///./test.db"))


def get_redis_url() -> str:
    """Get the Redis connection URL."""
    return get_secret("secret/redis", "url",
                      os.getenv("REDIS_URL", "redis://redis:6379/0"))


def get_rabbitmq_url() -> str:
    """Get the RabbitMQ connection URL."""
    return get_secret("secret/rabbitmq", "url",
                      os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672//"))


def get_github_token() -> Optional[str]:
    """Get the GitHub personal access token."""
    return get_secret("secret/github", "token", os.getenv("GITHUB_TOKEN"))


def get_llm_config() -> Dict[str, str]:
    """Get all LLM configuration values."""
    secrets = get_secrets("secret/llm")
    if secrets:
        return secrets
    # Fallback to environment variables
    return {
        "base_url": os.getenv("LLM_BASE_URL", "https://openrouter.ai/api/v1"),
        "api_key": os.getenv("LLM_API_KEY", ""),
        "model": os.getenv("LLM_MODEL", "qwen/qwen3-coder:free"),
        "max_tokens": os.getenv("LLM_MAX_TOKENS", "10000"),
        "temperature": os.getenv("LLM_TEMPERATURE", "0.1"),
        "timeout": os.getenv("LLM_TIMEOUT", "600"),
        "max_retries": os.getenv("LLM_MAX_RETRIES", "2"),
    }


def get_ai_api_key() -> str:
    """Get the AI API key."""
    return get_secret("secret/ai", "api_key", os.getenv("AI_API_KEY", "token"))


def get_container_image(lang: str) -> str:
    """Get the container image for a specific language."""
    defaults = {
        "python": "python:3.9-slim",
        "go": "golang:1.23-alpine",
        "node": "node:18-alpine",
        "java": "openjdk:17-slim",
    }
    return get_secret("secret/images", lang, 
                      os.getenv(f"{lang.upper()}_IMAGE", defaults.get(lang, "")))


def get_setting(key: str, default: str = "") -> str:
    """Get a configuration setting."""
    return get_secret("secret/settings", key, os.getenv(key.upper(), default))


def clear_secret_cache():
    """Clear the secret cache to pick up rotated secrets."""
    get_secret.cache_clear()
