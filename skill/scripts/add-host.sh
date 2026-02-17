#!/usr/bin/env bash
set -euo pipefail

# SSH Vault - Request host addition
# Usage: bash add-host.sh <vault_url> <name> <host> <username> <credential> [port] [authType]
# Output: JSON with approvalUrl

VAULT_URL="${1:?Usage: add-host.sh <vault_url> <name> <host> <username> <credential> [port] [authType]}"
NAME="$2"
HOST="$3"
USERNAME="$4"
CREDENTIAL="$5"
PORT="${6:-22}"
AUTH_TYPE="${7:-password}"

curl -sf "${VAULT_URL}/api/agent/request-host" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"${NAME}\",\"host\":\"${HOST}\",\"port\":${PORT},\"username\":\"${USERNAME}\",\"credential\":\"${CREDENTIAL}\",\"authType\":\"${AUTH_TYPE}\"}"
