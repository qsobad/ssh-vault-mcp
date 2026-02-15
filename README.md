# SSH Vault MCP

A secure SSH credential vault with MCP (Model Context Protocol) interface and Passkey authentication.

## Features

- 🔐 **Passkey Authentication**: Use Face ID, Touch ID, or Windows Hello to unlock
- 🔒 **Strong Encryption**: Argon2id key derivation + XSalsa20-Poly1305 (libsodium)
- 🤖 **MCP Interface**: AI agents can request SSH access through standardized tools
- 📋 **Policy Engine**: Whitelist/blacklist commands per agent
- ⏱️ **Session-based Access**: Temporary authorization that expires
- 🚫 **No Middle-man**: MCP server doesn't proxy SSH - just handles auth

## Architecture

```
User (Passkey)
     │
     ▼
Signing Page ──────► MCP Server ──────► Target SSH
                         │
                         │ MCP Tools
                         ▼
                      AI Agent
```

## Quick Start

### 1. Install

```bash
npm install
npm run build
```

### 2. Configure

Create `config.yml`:

```yaml
server:
  port: 3000

vault:
  path: ./data/vault.enc

webauthn:
  rp_id: "vault.example.com"
  rp_name: "SSH Vault"
  origin: "https://vault.example.com"

web:
  port: 3001
  external_url: "https://vault.example.com"

session:
  timeout_minutes: 30
```

### 3. Setup Vault

Visit `https://vault.example.com/setup` to create your Passkey.

### 4. Run

```bash
npm start
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `vault_status` | Check if vault is locked/unlocked |
| `request_unlock` | Get URL for Passkey authentication |
| `submit_unlock` | Submit unlock code from signing page |
| `list_hosts` | List available SSH hosts |
| `execute_command` | Run command on a host |
| `manage_vault` | Add/remove hosts and agents |
| `revoke_session` | End current session |

## Agent Configuration

Add agents to the vault with specific permissions:

```yaml
agents:
  - fingerprint: "SHA256:abc123..."
    name: "coding-agent"
    allowed_hosts: ["dev-*", "staging-*"]
    allowed_commands: ["ls", "cat", "grep", "tail"]
    denied_commands: ["rm", "sudo", "reboot"]
```

## Security Model

- **Vault at rest**: Encrypted with key derived from Passkey signature
- **No stored secrets**: Passkey private key stays in device secure element
- **Session isolation**: Each agent gets separate session
- **Policy enforcement**: Commands checked against whitelist/blacklist
- **Dangerous command detection**: Blocks known dangerous patterns

## Docker

```bash
docker build -t ssh-vault-mcp .
docker run -p 3000:3000 -p 3001:3001 -v ./data:/app/data ssh-vault-mcp
```

## Development

```bash
npm run dev      # Watch mode
npm test         # Run tests
npm run lint     # Lint code
```

## License

MIT
