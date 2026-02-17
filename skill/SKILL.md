---
name: ssh-vault
description: Secure SSH access through a Passkey-protected vault. Agent connects to a vault server (self-hosted or local MCP), registers via chat approval, and executes SSH commands with human oversight. Use when you need SSH access to servers, want to set up secure credential management, or need to run remote commands.
---

# SSH Vault

Secure SSH for AI agents. Credentials stay encrypted — user approves every action via Passkey.

## Connection Modes

### Mode 1: Self-Hosted Docker (User installs)

User installs the vault themselves with one command:

```bash
curl -fsSL https://raw.githubusercontent.com/qsobad/ssh-vault-mcp/main/install.sh | bash
```

The script asks for domain, generates config, pulls Docker image, and starts the vault.

After install, user:
1. Opens the vault URL in browser
2. Sets Master Password + registers Passkey
3. Gives you the vault URL to connect

**To connect as agent:** follow "Agent Registration" below.

### Mode 2: Local MCP (Agent helps configure)

For Claude Desktop, Cursor, or other MCP clients. Help user add to their config:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "ssh-vault": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-p", "3001:3001",
        "-v", "ssh-vault-data:/app/data",
        "-v", "CONFIG_PATH:/app/config.yml:ro",
        "-e", "SSH_VAULT_CONFIG=/app/config.yml",
        "qsobad/ssh-vault-mcp:latest"
      ]
    }
  }
}
```

Help user create `config.yml`:
```yaml
webauthn:
  rpId: "localhost"
  rpName: "SSH Vault"
  origin: "http://localhost:3001"
web:
  port: 3001
  external_url: "http://localhost:3001"
```

Then restart their MCP client. Vault UI at `http://localhost:3001`.

## Agent Registration

After vault is running and user has set up password + passkey:

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

→ **Send `approvalUrl` to user via chat** → user opens, Passkey + password → approves
→ ⏰ 5 minutes to approve

## Adding Hosts

```bash
curl -s ${VAULT_URL}/api/agent/request-host \
  -H 'Content-Type: application/json' \
  -d '{"name":"server-name","host":"1.2.3.4","port":22,"username":"root","credential":"ssh-password-or-key","authType":"password"}'
```

→ **Send `approvalUrl` to user via chat** → ⏰ 5 minutes

## Using SSH

```bash
# Check status
curl -s ${VAULT_URL}/api/vault/status

# If locked → request unlock, send URL to user
curl -s -X POST ${VAULT_URL}/api/vault/unlock \
  -H 'Content-Type: application/json' \
  -d '{"agentFingerprint":"SHA256:..."}'

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

## Rules

1. **Never ask for passwords** — vault handles all auth
2. **Send approval links via chat** — user approves on their device
3. **No shell metacharacters** — `|`, `;`, `&&`, `>` blocked by policy
4. **Auto-lock** — 15 min inactivity, send unlock link again
5. **Private key stays local** — never transmit `~/.ssh/ssh-vault-agent`

## Error Handling

| Error | Action |
|-------|--------|
| Vault locked | Send unlock URL via chat |
| Session expired | Re-request access |
| Command denied | Tell user, suggest simpler command |
| Shell injection | Remove pipes/redirects |
| Rate limited (429) | Wait and retry |
| Approval expired | Send new approval link |
