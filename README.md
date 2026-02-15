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

### 1. Install

```bash
git clone https://github.com/qsobad/ssh-vault-mcp.git
cd ssh-vault-mcp
npm install
```

### 2. Configure

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

### 3. Setup Vault

```bash
npm start
```

Visit `https://vault.example.com` → Set Master Password → Register Passkey → Add SSH hosts.

### 4. Add Hosts

Go to **Manage** (`/manage`) → Passkey login → Add Host with:
- Host ID, hostname, port, username
- SSH credential (private key or password)

## Claude Desktop MCP Configuration

Add to your Claude Desktop config file:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### Option A: Local (stdio transport)

Run the vault server locally and connect via stdio:

```json
{
  "mcpServers": {
    "ssh-vault": {
      "command": "npx",
      "args": ["tsx", "/path/to/ssh-vault-mcp/src/index.ts"],
      "env": {
        "SSH_VAULT_CONFIG": "/path/to/ssh-vault-mcp/config.yml"
      }
    }
  }
}
```

### Option B: Local with node

```json
{
  "mcpServers": {
    "ssh-vault": {
      "command": "node",
      "args": ["--loader", "tsx", "/path/to/ssh-vault-mcp/src/index.ts"],
      "env": {
        "SSH_VAULT_CONFIG": "/path/to/ssh-vault-mcp/config.yml"
      }
    }
  }
}
```

### Option C: Built version

Build first, then point to the compiled output:

```bash
npm run build
```

```json
{
  "mcpServers": {
    "ssh-vault": {
      "command": "node",
      "args": ["/path/to/ssh-vault-mcp/dist/index.js"]
    }
  }
}
```

### After Configuration

1. Restart Claude Desktop
2. Look for the 🔌 icon — "ssh-vault" should appear in the MCP servers list
3. Ask Claude: *"Check the SSH vault status"*
4. Claude will use `vault_status`, `request_unlock`, `execute_command` etc.

### Agent Keypair Setup

The agent (Claude) needs an Ed25519 keypair to sign requests. On first use:

```bash
# Generate keypair (store securely on the machine running Claude Desktop)
node -e "
const nacl = require('tweetnacl');
const kp = nacl.sign.keyPair();
const crypto = require('crypto');
const fp = 'SHA256:' + crypto.createHash('sha256').update(kp.publicKey).digest('base64').replace(/=+$/, '');
console.log(JSON.stringify({
  publicKey: Buffer.from(kp.publicKey).toString('base64'),
  privateKey: Buffer.from(kp.secretKey).toString('base64'),
  fingerprint: fp
}, null, 2));
"
```

Save the output to a secure location. The agent will use this to sign all MCP requests.

## MCP Tools

| Tool | Description | Auth Required |
|------|-------------|---------------|
| `vault_status` | Check if vault is locked/unlocked | Yes |
| `request_unlock` | Get URL for Passkey authentication | Yes |
| `submit_unlock` | Submit unlock code from signing page | Yes |
| `list_hosts` | List available SSH hosts | Yes |
| `execute_command` | Run command on a host | Yes (+ session + policy) |
| `manage_vault` | Add/remove hosts and agents | Yes |
| `revoke_session` | End current session | Yes |
| `request_access` | Request access to hosts | No (auto-enlists agent) |

## Security Model

### Encryption
- **At rest**: Argon2id(Master Password, salt) → VEK → XSalsa20-Poly1305
- **Passkey**: Proves user identity (WebAuthn), does not derive encryption key
- **Vault file**: `0600` permissions, encrypted with VEK

### Runtime
- **On-demand decryption**: Credentials decrypted per SSH command, `secureWipe()`d immediately after
- **Auto-lock**: VEK wiped from memory after 15 min inactivity
- **No plaintext in memory**: Vault object holds `[encrypted]` placeholders for credentials

### Agent Auth
- **Ed25519 signatures**: Every request signed with agent's private key
- **30-second nonce window**: Timestamps older than 30s rejected (replay protection)
- **Session-based**: Agent must request access → human approves → session issued

### Policy Engine
- **Command whitelist/blacklist**: Global + per-agent
- **Dangerous patterns**: `rm -rf /`, `mkfs`, `dd if=`, fork bombs
- **Shell injection**: Blocks `|`, `;`, `&&`, `||`, `>`, `<`, `` ` ``, `$()`
- **Timeout limits**: 1-300 seconds, default 30

### Rate Limiting
- 5 attempts per IP per 5 minutes on all auth endpoints
- Returns `429 Too Many Requests` on exceed

## HTTP API

All endpoints at `https://your-vault-domain/api/`:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/vault/status` | Vault lock status |
| POST | `/vault/execute` | Execute SSH command (signed) |
| POST | `/vault/submit-unlock` | Submit unlock code |
| POST | `/agent/request-access` | Agent requests host access |
| GET | `/challenge/:id/listen` | SSE for approval notifications |
| POST | `/auth/options` | Passkey auth options |
| POST | `/auth/verify` | Passkey auth verify |
| GET | `/manage/data` | List hosts/agents (authed) |
| POST | `/manage/hosts` | Add host (authed) |
| PUT | `/manage/hosts/:id` | Update host (authed) |
| DELETE | `/manage/hosts/:id` | Remove host (authed) |

## Development

```bash
npx tsx src/index.ts     # Dev mode
npx tsc --noEmit         # Type check
npm run build            # Build
```

## License

MIT
