# SSH Vault MCP (Secret Vault)

A secure secret vault with [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) interface. Store any secret as encrypted markdown — SSH credentials, API keys, certificates, notes. Human approves via Passkey, AI agent accesses secrets securely.

## Why?

AI agents need access to secrets (SSH keys, API tokens, passwords) — but giving them raw credentials is dangerous. Secret Vault solves this:

- **Agent requests secrets by name** — never browses raw credential stores
- **You approve every access** — via Passkey on your phone, in real-time
- **Flexible storage** — any secret stored as markdown (SSH hosts, API keys, notes)
- **SSH built-in** — secrets tagged `ssh` can be used directly for remote execution
- **Works with any MCP-compatible AI** — Claude, GPT, or your own agent

## Features

- 🔐 **Passkey + Master Password** — dual-factor vault access
- 🔒 **End-to-end encryption** — secrets never stored in plaintext (Argon2id + XSalsa20-Poly1305)
- 🤖 **MCP compatible** — works with Claude Desktop, Cursor, OpenClaw, and any MCP client
- 📝 **Markdown secrets** — store any secret as structured markdown
- ⚡ **One-step approval** — agent requests secret → you tap Passkey → secret delivered
- 🔑 **Session reuse** — after first approval, subsequent requests don't need re-approval
- ⏱️ **Auto-lock** — vault locks after inactivity, keys wiped from memory
- 🖥️ **SSH execution** — secrets with SSH info can be used to execute remote commands

## Quick Start

### 1. Self-Hosted Docker

```bash
docker run -d -p 3001:3001 \
  -v vault-data:/app/data \
  -v vault-config:/app/config \
  qsobad/ssh-vault-mcp:latest
```

- **Config:** `/app/config/config.yml` — auto-created with localhost defaults if missing
- **Data:** `/app/data/` — encrypted vault storage (persist this!)
- **Custom domain:** set `SSH_VAULT_ORIGIN` env var (e.g. `-e SSH_VAULT_ORIGIN=https://ssh.example.com`)

Open `http://localhost:3001` → set Master Password → register Passkey → done.

### 2. Local MCP (Claude Desktop / Cursor)

Add to your MCP client config:

```json
{
  "mcpServers": {
    "ssh-vault": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-p", "3001:3001",
        "-v", "ssh-vault-data:/app/data",
        "-v", "ssh-vault-config:/app/config",
        "-e", "SSH_VAULT_ORIGIN=http://localhost:3001",
        "qsobad/ssh-vault-mcp:latest"
      ]
    }
  }
}
```

### 3. OpenClaw Skill

For [OpenClaw](https://openclaw.ai) agents — everything happens through chat. Agent self-registers, adds hosts, and runs commands via approval links.

## How It Works

### Execution Flow

1. Agent calls `execute` with host + command
2. If no session → vault returns approval URL
3. **User opens URL** → sees host + command → authenticates with **Master Password + Passkey**
4. Vault unlocks → creates session → executes command → returns result to agent via SSE
5. Agent receives `sessionId` — subsequent commands execute immediately without re-approval

### Adding Hosts

1. Agent requests to add a host (name, IP, username)
2. User opens approval URL → **enters SSH password or private key** during approval
3. Credentials are encrypted and stored in vault — agent never sees them

### SSE Status Flow

```
pending → approved → executing → completed
```

Agent listens on SSE endpoint and receives:
```json
{"status":"completed","stdout":"...","stderr":"...","exitCode":0,"sessionId":"..."}
```

## Configuration

Config file at `/app/config/config.yml`. Auto-created with localhost defaults if missing.

```yaml
vault:
  path: /app/data/vault.enc
  backup: true

webauthn:
  rp_id: "your-domain.com"
  rp_name: "SSH Vault"
  origin: "https://your-domain.com"

web:
  port: 3001
  external_url: "https://your-domain.com"

session:
  timeout_minutes: 15
```

Environment variable overrides: `SSH_VAULT_ORIGIN`, `SSH_VAULT_PORT`, `SSH_VAULT_DATA_PATH`

## Technical Details

For API reference, security details, and development setup, see **[TECHNICAL.md](TECHNICAL.md)**.

## License

MIT
