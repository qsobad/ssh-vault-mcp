# SSH Vault MCP

A secure SSH credential vault with [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) interface. Human approves via Passkey, AI agent executes SSH commands.

## Why?

AI agents need SSH access to manage servers — but giving them raw credentials is dangerous. SSH Vault solves this:

- **Agent never sees passwords or keys** — the vault authenticates on its behalf
- **You approve every action** — via Passkey on your phone, in real-time
- **Policy engine limits what agents can do** — whitelist/blacklist commands, block dangerous patterns
- **Works with any MCP-compatible AI** — Claude, GPT, or your own agent

Think of it as a **SSH keychain where you're the only keyholder**, and the AI just asks you to unlock the door.

## Features

- 🔐 **Passkey + Master Password**: Passkey for identity, Master Password for encryption
- 🔒 **Strong Encryption**: Argon2id key derivation (t=3, m=64MB, p=1) + XSalsa20-Poly1305 (tweetnacl)
- 🤖 **MCP Interface**: AI agents access SSH through standardized tools
- ✍️ **Ed25519 Agent Signatures**: Every request cryptographically signed
- 📋 **Policy Engine**: Command whitelist/blacklist + shell injection detection
- ⏱️ **Auto-lock**: Vault locks after 15 min inactivity, VEK wiped from memory
- 🔑 **On-demand Decryption**: Credentials decrypted per-command, never held in memory
- 🚫 **No Proxy**: Vault handles auth — SSH runs server-side, not through agent
- 🤖 **Agent-Initiated Registration**: Agents can self-register, pending user Passkey + password approval
- 🖥️ **Agent-Initiated Host Addition**: Agents can request new hosts, pending user approval
- 🔄 **Change Master Password**: Requires Passkey verification, re-encrypts entire vault
- 💪 **Password Strength Check**: zxcvbn-based strength validation with real-time feedback
- 📱 **Responsive Design**: Mobile-friendly UI, works on phones and tablets
- ⏳ **5-Minute Approval Links**: All approval/challenge links expire after 5 minutes

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

## Installation

Three ways to get started:

### 1. Self-Hosted Docker (one command)

For users with a VPS or server:

```bash
curl -fsSL https://raw.githubusercontent.com/qsobad/ssh-vault-mcp/main/install.sh | bash
```

The script pulls the Docker image, asks for your domain, generates config, and starts the vault. Then open the URL → set Master Password → register Passkey → done.

### 2. Local MCP (Claude Desktop / Cursor)

For AI coding tools with MCP support. Add to your MCP client config:

```json
{
  "mcpServers": {
    "ssh-vault": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-p", "3001:3001",
        "-v", "ssh-vault-data:/app/data",
        "-e", "SSH_VAULT_DOMAIN=localhost",
        "qsobad/ssh-vault-mcp:latest"
      ]
    }
  }
}
```

No config file needed — the `SSH_VAULT_DOMAIN` env var handles it. Restart your MCP client, then visit `http://localhost:3001` to set up.

### 3. OpenClaw Skill (chat-driven)

For [OpenClaw](https://openclaw.ai) agents. Install the skill, then everything happens through chat:

- Agent self-registers → sends approval link to chat
- Adding hosts → sends approval link to chat
- SSH commands → sends unlock link when needed

User only needs to tap links and authenticate with Passkey.

---

> **All methods require the same two steps from the user:**
> 1. Set Master Password + register Passkey
> 2. Approve agent requests on your device

### Manual Docker install

#### Pull the image

```bash
docker pull qsobad/ssh-vault-mcp:latest
```

### 2. Run standalone (without Claude Desktop)

```bash
docker run -d \
  --name ssh-vault \
  -p 3001:3001 \
  -v ssh-vault-data:/app/data \
  -v ./config.yml:/app/config.yml:ro \
  -e SSH_VAULT_CONFIG=/app/config.yml \
  qsobad/ssh-vault-mcp:latest
```

Or with Docker Compose:

```yaml
services:
  ssh-vault:
    image: qsobad/ssh-vault-mcp:latest
    container_name: ssh-vault
    restart: unless-stopped
    ports:
      - "3001:3001"
    volumes:
      - ssh-vault-data:/app/data
      - ./config.yml:/app/config.yml:ro
    environment:
      - SSH_VAULT_CONFIG=/app/config.yml

volumes:
  ssh-vault-data:
```

### 3. Setup Vault

Visit `http://localhost:3001` → Set Master Password → Register Passkey → Add SSH hosts via **Manage** page.

## Claude Desktop MCP Configuration

Add to your Claude Desktop config:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### Docker (recommended)

Claude Desktop launches the Docker container locally. MCP communicates via stdio, the web UI is exposed on port 3001:

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

> **Note**: `-i` keeps stdin open for MCP stdio transport. `--rm` cleans up on exit. The vault data persists in the `ssh-vault-data` Docker volume.

#### Minimal config.yml

```yaml
webauthn:
  rpId: localhost
  rpName: SSH Vault
  origin: http://localhost:3001

web:
  port: 3001
  externalUrl: http://localhost:3001
```

Then visit `http://localhost:3001` to set up your vault (Master Password + Passkey).

### From source (development)

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
3. Visit `http://localhost:3001` to set up vault and add SSH hosts
4. Ask Claude: *"Check the SSH vault status"*
5. Claude will use `vault_status`, `request_unlock`, `execute_command` etc.

### Agent Keypair

The agent needs an Ed25519 keypair to sign requests. Generate one:

```bash
docker run --rm qsobad/ssh-vault-mcp:latest node -e "
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

Store the keypair securely. The agent uses it to sign all MCP requests.

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
- **KDF parameters**: t=3 (iterations), m=64MB (memory), p=1 (parallelism) — Argon2id
- **Vault file**: `0600` permissions
- **On-demand**: Credentials decrypted per command, wiped immediately

### Runtime Protection
- **Auto-lock**: VEK wiped after 15 min inactivity
- **No plaintext in memory**: Credential placeholders only
- **30s nonce window**: Replay protection
- **Rate limiting**: 5 attempts/IP/5min on auth endpoints
- **Approval link expiry**: All challenge/approval links expire after 5 minutes
- **Password strength**: zxcvbn validation enforced on registration and password change

### Policy Engine
- Command whitelist/blacklist (global + per-agent)
- Dangerous pattern detection (`rm -rf /`, `mkfs`, `dd`, fork bombs)
- Shell injection blocking (`|`, `;`, `&&`, `||`, `>`, `` ` ``, `$()`)
- Timeout limits: 1-300s

### Agent-Initiated Flows
- **Registration**: Agent calls `POST /api/agent/register` → user receives approval link → authenticates with Passkey + enters master password → agent is registered
- **Host Addition**: Agent calls `POST /api/agent/request-host` → user receives approval link → authenticates with Passkey + enters master password → host is added to vault
- **Password Change**: Requires Passkey verification before re-encrypting vault with new password

## HTTP API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/vault/status` | Vault lock status |
| POST | `/api/vault/execute` | Execute SSH command (signed) |
| POST | `/api/vault/submit-unlock` | Submit unlock code |
| POST | `/api/agent/request-access` | Request host access |
| POST | `/api/agent/register` | Agent-initiated registration (pending approval) |
| GET | `/api/agent/register/:id/listen` | SSE listener for registration approval |
| POST | `/api/agent/register/:id/approve` | Approve agent registration (Passkey + password) |
| POST | `/api/agent/register/:id/reject` | Reject agent registration |
| POST | `/api/agent/request-host` | Agent-initiated host addition (pending approval) |
| GET | `/api/agent/request-host/:id/listen` | SSE listener for host request approval |
| POST | `/api/agent/request-host/:id/approve` | Approve host addition (Passkey + password) |
| POST | `/api/agent/request-host/:id/reject` | Reject host addition |
| GET | `/api/challenge/:id/listen` | SSE approval notifications |
| POST | `/api/auth/options` | Passkey auth options |
| POST | `/api/auth/verify` | Passkey auth verify |
| GET | `/api/manage/data` | List hosts/agents (authed) |
| POST | `/api/manage/hosts` | Add host (authed) |
| POST | `/api/manage/change-password` | Change master password (Passkey required) |
| POST | `/api/password-strength` | Check password strength (zxcvbn) |

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
