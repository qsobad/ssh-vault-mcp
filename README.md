# SSH Vault MCP

A secure SSH credential vault with [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) interface. Human approves via Passkey, AI agent executes SSH commands.

## Features

- 🔐 **Passkey + Master Password**: Passkey for identity, Master Password for encryption
- 🔒 **Strong Encryption**: Argon2id key derivation + XSalsa20-Poly1305 (tweetnacl)
- 🤖 **MCP Interface**: AI agents access SSH through standardized tools
- ✍️ **Ed25519 Agent Signatures**: Every request cryptographically signed
- 📋 **Policy Engine**: Command whitelist/blacklist + shell injection detection
- ⏱️ **Auto-lock**: Vault locks after 15 min inactivity, VEK wiped from memory
- 🔑 **On-demand Decryption**: Credentials decrypted per-command, never held in memory
- 🚫 **No Proxy**: Vault handles auth — SSH runs server-side, not through agent

## Architecture

```
┌──────────────┐     Passkey + Password     ┌──────────────┐
│   User       │ ◄─────────────────────────► │  Vault Web   │
│  (Browser)   │     approve/unlock          │  (Express)   │
└──────────────┘                             └──────┬───────┘
                                                    │
┌──────────────┐     Ed25519 signed requests ┌──────┴───────┐     SSH
│   AI Agent   │ ◄─────────────────────────► │  MCP Server  │ ──────► Target
│ (Claude etc) │     MCP tools               │  (stdio/HTTP)│        Hosts
└──────────────┘                             └──────────────┘
```

## Quick Start

### 1. Run with Docker

```bash
docker run -d \
  --name ssh-vault \
  -p 3001:3001 \
  -v ssh-vault-data:/app/data \
  -e VAULT_RPID=vault.example.com \
  -e VAULT_ORIGIN=https://vault.example.com \
  -e VAULT_EXTERNAL_URL=https://vault.example.com \
  qsobad/ssh-vault-mcp:latest
```

### 2. Or with Docker Compose

Create `docker-compose.yml`:

```yaml
services:
  ssh-vault:
    image: qsobad/ssh-vault-mcp:latest
    container_name: ssh-vault
    restart: unless-stopped
    ports:
      - "3001:3001"
    volumes:
      - ./data:/app/data
      - ./config.yml:/app/config.yml:ro
    environment:
      - SSH_VAULT_CONFIG=/app/config.yml
```

Create `config.yml`:

```yaml
server:
  port: 3000
  host: 0.0.0.0

vault:
  path: ./data/vault.enc
  backup: true

webauthn:
  rpId: vault.example.com
  rpName: SSH Vault
  origin: https://vault.example.com

web:
  port: 3001
  externalUrl: https://vault.example.com

session:
  timeoutMinutes: 30

autoLockMinutes: 15
```

```bash
docker compose up -d
```

### 3. Setup Vault

Visit `https://vault.example.com` → Set Master Password → Register Passkey → Add SSH hosts via **Manage** page.

## Claude Desktop MCP Configuration

Add to your Claude Desktop config:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### Using Docker (recommended)

The MCP server runs inside Docker. Claude Desktop connects to the HTTP API:

```json
{
  "mcpServers": {
    "ssh-vault": {
      "command": "npx",
      "args": ["-y", "@anthropic-ai/mcp-remote", "https://vault.example.com/mcp"]
    }
  }
}
```

> **Note**: Replace `vault.example.com` with your actual domain. The vault must be accessible over HTTPS.

### Using stdio (local development)

If running from source locally:

```json
{
  "mcpServers": {
    "ssh-vault": {
      "command": "node",
      "args": ["/path/to/ssh-vault-mcp/dist/index.js"],
      "env": {
        "SSH_VAULT_CONFIG": "/path/to/config.yml"
      }
    }
  }
}
```

### After Configuration

1. Restart Claude Desktop
2. Look for the 🔌 icon — "ssh-vault" should appear in MCP servers
3. Ask Claude: *"Check the SSH vault status"*
4. Claude will use `vault_status`, `request_unlock`, `execute_command` etc.

### Agent Keypair

The agent needs an Ed25519 keypair to sign requests:

```bash
node -e "
const nacl = require('tweetnacl');
const kp = nacl.sign.keyPair();
const crypto = require('crypto');
const fp = 'SHA256:' + crypto.createHash('sha256').update(kp.publicKey).digest('base64').replace(/=+\$/, '');
console.log(JSON.stringify({
  publicKey: Buffer.from(kp.publicKey).toString('base64'),
  privateKey: Buffer.from(kp.secretKey).toString('base64'),
  fingerprint: fp
}, null, 2));
"
```

Store the keypair securely on the machine running Claude Desktop.

## MCP Tools

| Tool | Description | Auth |
|------|-------------|------|
| `vault_status` | Check lock status | Signed |
| `request_unlock` | Get Passkey auth URL | Signed |
| `submit_unlock` | Submit unlock code | Signed |
| `list_hosts` | List SSH hosts | Signed |
| `execute_command` | Run SSH command | Signed + Session + Policy |
| `manage_vault` | Manage hosts/agents | Signed |
| `revoke_session` | End session | Signed |
| `request_access` | Request host access | No auth (auto-enlists) |

## Security

### Encryption
- **At rest**: Argon2id(Master Password, salt) → VEK → XSalsa20-Poly1305
- **Vault file**: `0600` permissions
- **On-demand**: Credentials decrypted per command, wiped immediately

### Runtime Protection
- **Auto-lock**: VEK wiped after 15 min inactivity
- **No plaintext in memory**: Credential placeholders only
- **30s nonce window**: Replay protection
- **Rate limiting**: 5 attempts/IP/5min on auth endpoints

### Policy Engine
- Command whitelist/blacklist (global + per-agent)
- Dangerous pattern detection (`rm -rf /`, `mkfs`, `dd`, fork bombs)
- Shell injection blocking (`|`, `;`, `&&`, `||`, `>`, `` ` ``, `$()`)
- Timeout limits: 1-300s

## HTTP API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/vault/status` | Vault lock status |
| POST | `/api/vault/execute` | Execute SSH command (signed) |
| POST | `/api/vault/submit-unlock` | Submit unlock code |
| POST | `/api/agent/request-access` | Request host access |
| GET | `/api/challenge/:id/listen` | SSE approval notifications |
| POST | `/api/auth/options` | Passkey auth options |
| POST | `/api/auth/verify` | Passkey auth verify |
| GET | `/api/manage/data` | List hosts/agents (authed) |
| POST | `/api/manage/hosts` | Add host (authed) |

## Development

```bash
git clone https://github.com/qsobad/ssh-vault-mcp.git
cd ssh-vault-mcp
npm install
npx tsx src/index.ts     # Dev mode
npx tsc --noEmit         # Type check
npm run build            # Build
```

## License

MIT
