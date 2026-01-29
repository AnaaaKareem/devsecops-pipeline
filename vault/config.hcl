# Vault Server Configuration
# Uses file-based storage for persistence across restarts

ui = true
disable_mlock = true

# File-based storage (data persists in Docker volume)
storage "file" {
  path = "/vault/data"
}

# HTTP listener (use TLS in production)
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

# API address for internal communication
api_addr = "http://0.0.0.0:8200"
