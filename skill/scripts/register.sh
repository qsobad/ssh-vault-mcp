#!/usr/bin/env bash
set -euo pipefail

# SSH Vault - Agent self-registration
# Usage: bash register.sh <vault_url> [agent_name] [key_path]
# Output: JSON with approvalUrl

VAULT_URL="${1:?Usage: register.sh <vault_url> [agent_name] [key_path]}"
AGENT_NAME="${2:-OpenClaw Agent}"
KEY_PATH="${3:-$HOME/.ssh/ssh-vault-agent}"

# Generate keypair if needed
if [ ! -f "${KEY_PATH}.pub" ]; then
  ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "$AGENT_NAME" -q
fi

FINGERPRINT=$(ssh-keygen -lf "${KEY_PATH}.pub" | awk '{print $2}')
PUBKEY=$(awk '{print $2}' "${KEY_PATH}.pub")

# Register
curl -sf "${VAULT_URL}/api/agent/register" \
  -H 'Content-Type: application/json' \
  -d "{\"fingerprint\":\"${FINGERPRINT}\",\"publicKey\":\"${PUBKEY}\",\"name\":\"${AGENT_NAME}\"}"
