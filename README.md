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

- 🔐 **Passkey + Master Password** — dual-factor vault access
- 🔒 **End-to-end encryption** — credentials never stored in plaintext
- 🤖 **MCP compatible** — works with Claude Desktop, Cursor, OpenClaw, and any MCP client
- 📋 **Policy engine** — control which commands agents can run
- 🤝 **Chat-driven approval** — agents request access, you approve on your phone
- ⏱️ **Auto-lock** — vault locks after inactivity, keys wiped from memory

## Quick Start

Three ways to get started — pick the one that fits you:

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

## How It Works

1. **You set up the vault** — set a Master Password and register your Passkey (fingerprint / Face ID)
2. **AI agent connects** — it registers itself and you approve via Passkey
3. **Agent requests SSH access** — you approve adding each host
4. **Agent runs commands** — each session requires your Passkey unlock
5. **Vault auto-locks** — after 15 min inactivity, everything is wiped from memory

The agent **never** sees your SSH passwords or keys. It sends commands, the vault authenticates on its behalf.

## Technical Details

For advanced configuration, API reference, security details, and development setup, see **[TECHNICAL.md](TECHNICAL.md)**.

## License

MIT
