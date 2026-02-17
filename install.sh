#!/usr/bin/env bash
set -euo pipefail

# SSH Vault MCP - One-line installer
#
# Interactive (human):
#   curl -fsSL https://raw.githubusercontent.com/qsobad/ssh-vault-mcp/main/install.sh | bash
#
# Non-interactive (agent):
#   curl -fsSL ... | SSH_VAULT_DOMAIN=ssh.example.com SSH_VAULT_AGENT_NAME="MyAgent" bash
#
# Environment variables:
#   SSH_VAULT_DOMAIN     - Domain or URL (default: localhost:3001)
#   SSH_VAULT_PORT       - Port (default: 3001)
#   SSH_VAULT_DIR        - Data directory (default: ~/.ssh-vault)
#   SSH_VAULT_AGENT_NAME - Agent name for auto-registration (triggers non-interactive mode)
#   SSH_VAULT_AGENT_KEY  - Path to agent Ed25519 public key (default: ~/.ssh/ssh-vault-agent.pub)
#   SSH_VAULT_NO_PROMPT  - Skip all prompts (default: auto-detect from tty)

VAULT_IMAGE="qsobad/ssh-vault-mcp:latest"
VAULT_NAME="ssh-vault"
VAULT_PORT="${SSH_VAULT_PORT:-3001}"
VAULT_DIR="${SSH_VAULT_DIR:-$HOME/.ssh-vault}"
AGENT_NAME="${SSH_VAULT_AGENT_NAME:-}"
AGENT_KEY="${SSH_VAULT_AGENT_KEY:-$HOME/.ssh/ssh-vault-agent.pub}"

# Auto-detect interactive mode
if [[ -n "$AGENT_NAME" ]] || [[ "${SSH_VAULT_NO_PROMPT:-}" == "1" ]] || ! [[ -t 0 ]]; then
  INTERACTIVE=false
else
  INTERACTIVE=true
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[i]${NC} $1"; }
json() { echo "$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$2',''))" 2>/dev/null || echo ""; }

echo ""
echo -e "${BLUE}╔══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     🔐 SSH Vault MCP Installer       ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════╝${NC}"
echo ""

if [[ "$INTERACTIVE" == false ]]; then
  info "Non-interactive mode"
fi

# Check Docker
if ! command -v docker &>/dev/null; then
  err "Docker is required but not installed. Install it first: https://docs.docker.com/get-docker/"
fi

if ! docker info &>/dev/null 2>&1; then
  err "Docker daemon is not running. Start it first."
fi

log "Docker detected"

# Create data directory
mkdir -p "$VAULT_DIR"
log "Data directory: $VAULT_DIR"

# Determine domain/URL
EXTERNAL_URL="http://localhost:${VAULT_PORT}"
RP_ID="localhost"
USER_DOMAIN="${SSH_VAULT_DOMAIN:-}"

if [[ -z "$USER_DOMAIN" ]] && [[ "$INTERACTIVE" == true ]]; then
  echo ""
  info "The vault needs a web URL for Passkey authentication."
  info "For local use, just press Enter. For remote access, enter your domain."
  echo ""
  read -rp "Domain or URL [localhost:${VAULT_PORT}]: " USER_DOMAIN
fi

if [[ -n "$USER_DOMAIN" ]]; then
  # Strip protocol if provided
  USER_DOMAIN="${USER_DOMAIN#http://}"
  USER_DOMAIN="${USER_DOMAIN#https://}"
  USER_DOMAIN="${USER_DOMAIN%/}"
  
  # Determine protocol
  if [[ "$USER_DOMAIN" == *":3001"* ]] || [[ "$USER_DOMAIN" == "localhost"* ]] || [[ "$USER_DOMAIN" == "127."* ]]; then
    EXTERNAL_URL="http://${USER_DOMAIN}"
    RP_ID="${USER_DOMAIN%%:*}"
  else
    EXTERNAL_URL="https://${USER_DOMAIN}"
    RP_ID="${USER_DOMAIN%%:*}"
  fi
fi

log "URL: $EXTERNAL_URL"
log "Passkey RP ID: $RP_ID"

# Generate config
CONFIG_FILE="$VAULT_DIR/config.yml"
if [[ -f "$CONFIG_FILE" ]]; then
  warn "Config already exists at $CONFIG_FILE, keeping it"
else
  cat > "$CONFIG_FILE" << EOF
webauthn:
  rpId: "${RP_ID}"
  rpName: "SSH Vault"
  origin: "${EXTERNAL_URL}"

web:
  port: ${VAULT_PORT}
  external_url: "${EXTERNAL_URL}"

vault:
  path: /app/data/vault.enc
  auto_lock_minutes: 15

session:
  mode: session
  timeout_minutes: 30
EOF
  log "Config written to $CONFIG_FILE"
fi

# Pull image
echo ""
info "Pulling Docker image..."
docker pull "$VAULT_IMAGE"
log "Image pulled"

# Stop existing container if running
if docker ps -a --format '{{.Names}}' | grep -q "^${VAULT_NAME}$"; then
  warn "Existing container found, replacing..."
  docker stop "$VAULT_NAME" 2>/dev/null || true
  docker rm "$VAULT_NAME" 2>/dev/null || true
fi

# Run container
docker run -d \
  --name "$VAULT_NAME" \
  --restart unless-stopped \
  -p "${VAULT_PORT}:3001" \
  -v "${VAULT_DIR}/data:/app/data" \
  -v "${CONFIG_FILE}:/app/config.yml:ro" \
  -e SSH_VAULT_CONFIG=/app/config.yml \
  "$VAULT_IMAGE"

log "Container started"

# Wait for health check
echo ""
info "Waiting for vault to start..."
for i in $(seq 1 15); do
  if curl -sf "http://localhost:${VAULT_PORT}/health" &>/dev/null; then
    log "Vault is running!"
    break
  fi
  sleep 1
  if [[ $i -eq 15 ]]; then
    err "Vault failed to start. Check: docker logs $VAULT_NAME"
  fi
done

# Done
echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     🎉 SSH Vault MCP is ready!       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
echo -e "  📎 Open:   ${BLUE}${EXTERNAL_URL}${NC}"
echo -e "  📂 Data:   ${VAULT_DIR}"
echo -e "  📋 Config: ${CONFIG_FILE}"
echo -e "  🐳 Container: ${VAULT_NAME}"
echo ""
echo -e "  ${YELLOW}Next steps:${NC}"
echo -e "  1. Open ${EXTERNAL_URL} in your browser"
echo -e "  2. Set your Master Password"
echo -e "  3. Register a Passkey"
echo -e "  4. Add SSH hosts and agents"
echo ""
echo -e "  ${YELLOW}Commands:${NC}"
echo -e "  docker logs ${VAULT_NAME}        # View logs"
echo -e "  docker restart ${VAULT_NAME}     # Restart"
echo -e "  docker stop ${VAULT_NAME}        # Stop"
echo ""

# Agent auto-registration (non-interactive mode)
if [[ -n "$AGENT_NAME" ]]; then
  echo ""
  info "Agent registration: ${AGENT_NAME}"

  # Generate agent keypair if needed
  if [[ ! -f "$AGENT_KEY" ]]; then
    KEY_PRIVATE="${AGENT_KEY%.pub}"
    info "Generating Ed25519 keypair..."
    ssh-keygen -t ed25519 -f "$KEY_PRIVATE" -N "" -C "$AGENT_NAME" -q
    log "Keypair: $KEY_PRIVATE"
  fi

  # Get fingerprint and public key
  FINGERPRINT=$(ssh-keygen -lf "$AGENT_KEY" | awk '{print $2}')
  PUBKEY=$(awk '{print $2}' "$AGENT_KEY")

  log "Fingerprint: $FINGERPRINT"

  # Register agent
  REGISTER_RESULT=$(curl -sf "http://localhost:${VAULT_PORT}/api/agent/register" \
    -H 'Content-Type: application/json' \
    -d "{\"fingerprint\":\"${FINGERPRINT}\",\"publicKey\":\"${PUBKEY}\",\"name\":\"${AGENT_NAME}\"}" 2>/dev/null || echo "")

  if [[ -n "$REGISTER_RESULT" ]]; then
    APPROVAL_URL=$(json "$REGISTER_RESULT" "approvalUrl")
    CHALLENGE_ID=$(json "$REGISTER_RESULT" "challengeId")

    if [[ -n "$APPROVAL_URL" ]]; then
      log "Registration request created"
      echo ""
      echo -e "  ${YELLOW}⚠️  Approve this agent:${NC}"
      echo -e "  ${BLUE}${APPROVAL_URL}${NC}"
      echo ""
      echo -e "  Link expires in 5 minutes."
      echo ""

      # Output machine-readable result for agents to parse
      echo "---AGENT_REGISTRATION---"
      echo "CHALLENGE_ID=${CHALLENGE_ID}"
      echo "APPROVAL_URL=${APPROVAL_URL}"
      echo "FINGERPRINT=${FINGERPRINT}"
      echo "AGENT_KEY=${AGENT_KEY}"
      echo "---END---"
    fi
  else
    warn "Agent registration failed. Register manually after setup."
  fi
fi
