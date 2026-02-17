---
name: ssh-vault
description: Secure SSH access through a Passkey-protected vault. Agent connects to a vault server (self-hosted or managed), registers via chat approval, and executes SSH commands with human oversight. Use when you need SSH access to servers, want to set up secure credential management, or need to run remote commands.
---

# SSH Vault

Secure SSH for AI agents. Credentials stay encrypted — you approve every action via Passkey on your phone.

## Connection Modes

### Mode 1: Self-Hosted Docker
User runs their own vault. Install it for them:

```bash
# Check if already running
docker ps --filter name=ssh-vault --format '{{.Names}}'

# If not, install:
docker pull qsobad/ssh-vault-mcp:latest

# Generate config (ask user for domain, or use localhost)
cat > /tmp/ssh-vault-config.yml << 'EOF'
webauthn:
  rpId: "DOMAIN"
  rpName: "SSH Vault"
  origin: "https://DOMAIN"
web:
  port: 3001
  external_url: "https://DOMAIN"
EOF

# Start
docker run -d --name ssh-vault --restart unless-stopped \
  -p 3001:3001 \
  -v ssh-vault-data:/app/data \
  -v /tmp/ssh-vault-config.yml:/app/config.yml:ro \
  -e SSH_VAULT_CONFIG=/app/config.yml \
  qsobad/ssh-vault-mcp:latest
```

After starting, send user the URL to set up Master Password + Passkey.

### Mode 2: Local MCP (Claude Desktop / Cursor)
For non-OpenClaw agents. User adds to their MCP config:

```json
{
  "mcpServers": {
    "ssh-vault": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-p", "3001:3001",
        "-v", "ssh-vault-data:/app/data",
        "-v", "/path/to/config.yml:/app/config.yml:ro",
        "-e", "SSH_VAULT_CONFIG=/app/config.yml",
        "qsobad/ssh-vault-mcp:latest"
      ]
    }
  }
}
```

## Chat-Driven Setup

All approval happens through chat. Never ask for passwords.

### Step 1: Determine vault URL
Ask user: "Do you have an SSH Vault, or should I set one up?"
- Has one → get URL
- Needs one → install via Docker (Mode 1), send setup link

### Step 2: Register as agent
```bash
# Generate keypair (once)
if [ ! -f ~/.ssh/ssh-vault-agent.pub ]; then
  ssh-keygen -t ed25519 -f ~/.ssh/ssh-vault-agent -N "" -C "openclaw-agent"
fi

FINGERPRINT=$(ssh-keygen -lf ~/.ssh/ssh-vault-agent.pub | awk '{print $2}')
PUBKEY=$(awk '{print $2}' ~/.ssh/ssh-vault-agent.pub)

curl -s ${VAULT_URL}/api/agent/register \
  -H 'Content-Type: application/json' \
  -d "{\"fingerprint\":\"$FINGERPRINT\",\"publicKey\":\"$PUBKEY\",\"name\":\"OpenClaw Agent\"}"
```

→ **Send `approvalUrl` to user via chat** → user opens, Passkey + password, approves
→ ⏰ 5 minutes to approve

### Step 3: Add hosts (when needed)
```bash
curl -s ${VAULT_URL}/api/agent/request-host \
  -H 'Content-Type: application/json' \
  -d '{"name":"server-name","host":"1.2.3.4","port":22,"username":"root","credential":"ssh-password-or-key","authType":"password"}'
```

→ **Send `approvalUrl` to user via chat** → user approves
→ ⏰ 5 minutes to approve

### Step 4: Use SSH
```bash
# Check status
curl -s ${VAULT_URL}/api/vault/status

# If locked → send unlock URL to user
curl -s -X POST ${VAULT_URL}/api/vault/unlock \
  -H 'Content-Type: application/json' \
  -d '{"agentFingerprint":"SHA256:..."}'
# → send unlockUrl to user via chat

# Execute command (requires Ed25519 signature)
curl -s -X POST ${VAULT_URL}/api/vault/execute \
  -H 'Content-Type: application/json' \
  -d '{
    "host": "server-name",
    "command": "docker ps",
    "fingerprint": "SHA256:...",
    "signature": "...",
    "timestamp": "...",
    "nonce": "..."
  }'
```

## Signing Requests

All API calls to execute commands require Ed25519 signature:

```bash
# Message format: action:host:command:timestamp
# Sign with ~/.ssh/ssh-vault-agent private key
# Timestamp must be within 30 seconds (replay protection)
```

See `scripts/sign-request.sh` for helper.

## Rules

1. **Never ask for passwords** — vault handles all authentication
2. **Send approval links via chat** — user approves on their device
3. **No shell metacharacters** — `|`, `;`, `&&`, `>` are blocked by policy engine
4. **Auto-lock** — vault locks after 15 min inactivity, send unlock link again
5. **Private key stays local** — never transmit `~/.ssh/ssh-vault-agent`

## Error Handling

| Error | Action |
|-------|--------|
| Vault locked | Send unlock URL via chat |
| Session expired | Re-request access |
| Command denied | Tell user, suggest simpler command |
| Shell injection | Remove pipes/redirects |
| Rate limited (429) | Wait and retry |
| Approval expired | Re-send new approval link |
