#!/bin/sh
set -e

VAULT_DATA_DIR="/vault/data"
INIT_FILE="$VAULT_DATA_DIR/.vault-init.json"
SECRETS_LOADED_FLAG="$VAULT_DATA_DIR/.secrets-loaded"
ENV_FILE="/vault/env/.env"

# Start Vault server in background
vault server -config=/vault/config/config.hcl &
VAULT_PID=$!

# Wait for Vault to be ready
echo "⏳ Waiting for Vault to start..."
sleep 5

# Keep trying until vault responds
MAX_ATTEMPTS=30
ATTEMPT=0
while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
  if vault status 2>/dev/null; then
    break
  fi
  if vault status 2>&1 | grep -q "Initialized"; then
    break
  fi
  ATTEMPT=$((ATTEMPT + 1))
  echo "Waiting for Vault... (attempt $ATTEMPT/$MAX_ATTEMPTS)"
  sleep 2
done

# Check if Vault is already initialized
if vault status 2>&1 | grep -q "Initialized.*false"; then
  echo "🔐 Initializing Vault for the first time..."
  
  # Initialize with 1 key share for simplicity (use 5 shares in production)
  vault operator init -key-shares=1 -key-threshold=1 -format=json > "$INIT_FILE"
  
  echo "✅ Vault initialized. Keys saved to persistent storage."
fi

# Install jq for robust JSON parsing
if ! command -v jq >/dev/null 2>&1; then
    echo "📦 Installing jq for JSON parsing..."
    if [ -x "$(command -v apk)" ]; then
        apk add --no-cache jq >/dev/null 2>&1
    elif [ -x "$(command -v apt-get)" ]; then
        apt-get update >/dev/null 2>&1 && apt-get install -y jq >/dev/null 2>&1
    fi
fi

# Check if Vault is sealed
if vault status -format=json 2>/dev/null | jq -e '.sealed == true' >/dev/null; then
  echo "🔓 Unsealing Vault..."
  
  # Read unseal key from init file using jq
  UNSEAL_KEY=$(jq -r '.unseal_keys_b64[0]' "$INIT_FILE")
  
  if [ -z "$UNSEAL_KEY" ] || [ "$UNSEAL_KEY" = "null" ]; then
      echo "❌ Error: Failed to extract unseal key from $INIT_FILE"
      exit 1
  fi

  echo "🔑 Unsealing with extracted key..."
  vault operator unseal "$UNSEAL_KEY"
  
  echo "✅ Vault unsealed."
fi

# Authenticate with root token
ROOT_TOKEN=$(jq -r '.root_token' "$INIT_FILE")
export VAULT_TOKEN="$ROOT_TOKEN"

# Save token for other services to use
echo "$ROOT_TOKEN" > "$VAULT_DATA_DIR/.root-token"
chmod 644 "$VAULT_DATA_DIR/.root-token"

# Check if secrets need to be loaded from .env
if [ ! -f "$SECRETS_LOADED_FLAG" ] && [ -f "$ENV_FILE" ]; then
  echo "📥 Loading secrets from .env file..."
  
  # Enable KV v2 secrets engine
  vault secrets enable -path=secret kv-v2 2>/dev/null || true
  
  # Source the .env file to get variables
  set -a
  . "$ENV_FILE"
  set +a
  
  # Database secrets
  vault kv put secret/database \
    url="${DATABASE_URL:-postgresql://postgres:password@db:5432/security_brain}" \
    postgres_password="${POSTGRES_PASSWORD:-password}"
  
  # Redis secrets
  vault kv put secret/redis \
    url="${REDIS_URL:-redis://redis:6379/0}"
  
  # RabbitMQ secrets
  vault kv put secret/rabbitmq \
    url="amqp://guest:guest@rabbitmq:5672//" \
    user="guest" \
    password="guest"
  
  # GitHub secrets
  vault kv put secret/github \
    token="${GITHUB_TOKEN:-}"
  
  # LLM/AI secrets
  vault kv put secret/llm \
    base_url="${LLM_BASE_URL:-https://openrouter.ai/api/v1}" \
    api_key="${LLM_API_KEY:-}" \
    model="${LLM_MODEL:-qwen/qwen3-coder:free}" \
    max_tokens="${LLM_MAX_TOKENS:-10000}" \
    temperature="${LLM_TEMPERATURE:-0.1}" \
    timeout="${LLM_TIMEOUT:-600}" \
    max_retries="${LLM_MAX_RETRIES:-2}"
  
  vault kv put secret/ai \
    api_key="${AI_API_KEY:-token}"
  
  # Container images
  vault kv put secret/images \
    python="${PYTHON_IMAGE:-python:3.9-slim}" \
    go="${GO_IMAGE:-golang:1.23-alpine}" \
    node="${NODE_IMAGE:-node:18-alpine}" \
    java="${JAVA_IMAGE:-openjdk:17-slim}"
  
  # Service settings
  vault kv put secret/settings \
    human_interaction="${HUMAN_INTERACTION:-false}" \
    skip_model_check="${SKIP_MODEL_CHECK:-false}" \
    log_level="${LOG_LEVEL:-INFO}" \
    red_team_rate_limit_delay="${RED_TEAM_RATE_LIMIT_DELAY:-10}" \
    triage_max_tokens="${TRIAGE_MAX_TOKENS:-1024}"
  
  # Mark secrets as loaded
  touch "$SECRETS_LOADED_FLAG"
  
  echo "✅ Secrets loaded from .env file!"
else
  echo "ℹ️  Secrets already loaded (or no .env file found)."
fi

echo "🚀 Vault is ready! Token saved to $VAULT_DATA_DIR/.root-token"
echo "📋 Access Vault UI at: http://localhost:8200"

# Keep Vault running in foreground
wait $VAULT_PID
