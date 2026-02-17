#!/usr/bin/env bash
set -euo pipefail

# SSH Vault - Agent-driven install
# Usage: bash install.sh <domain> [port]
# Example: bash install.sh ssh.example.com 3001

DOMAIN="${1:?Usage: install.sh <domain> [port]}"
PORT="${2:-3001}"
IMAGE="qsobad/ssh-vault-mcp:latest"
NAME="ssh-vault"

# Determine protocol
if [[ "$DOMAIN" == "localhost" ]] || [[ "$DOMAIN" == "127."* ]]; then
  ORIGIN="http://${DOMAIN}:${PORT}"
else
  ORIGIN="https://${DOMAIN}"
fi

# Check Docker
command -v docker &>/dev/null || { echo "ERROR: Docker required"; exit 1; }
docker info &>/dev/null 2>&1 || { echo "ERROR: Docker not running"; exit 1; }

# Stop existing
if docker ps -a --format '{{.Names}}' | grep -q "^${NAME}$"; then
  docker stop "$NAME" 2>/dev/null || true
  docker rm "$NAME" 2>/dev/null || true
fi

# Config
CONFIG=$(mktemp)
cat > "$CONFIG" << EOF
webauthn:
  rpId: "${DOMAIN}"
  rpName: "SSH Vault"
  origin: "${ORIGIN}"
web:
  port: ${PORT}
  external_url: "${ORIGIN}"
vault:
  path: /app/data/vault.enc
  auto_lock_minutes: 15
session:
  mode: session
  timeout_minutes: 30
EOF

# Pull & run
docker pull "$IMAGE"
docker run -d --name "$NAME" --restart unless-stopped \
  -p "${PORT}:3001" \
  -v ssh-vault-data:/app/data \
  -v "${CONFIG}:/app/config.yml:ro" \
  -e SSH_VAULT_CONFIG=/app/config.yml \
  "$IMAGE"

# Wait for health
for i in $(seq 1 10); do
  curl -sf "http://localhost:${PORT}/health" &>/dev/null && break
  sleep 1
done

echo "OK"
echo "URL=${ORIGIN}"
echo "SETUP_URL=${ORIGIN}/setup"
