# Secret Vault MCP — Technical Reference

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

## Secret Storage

Each secret is stored as an encrypted markdown document with metadata:

```json
{
  "id": "uuid",
  "name": "my-server",
  "tags": ["ssh", "production"],
  "content": "# my-server\n- host: 1.2.3.4\n- user: root\n- password: xxx",
  "createdAt": 1234567890,
  "updatedAt": 1234567890
}
```

### SSH Secret Format

Secrets tagged with `ssh` can be used for SSH command execution. The markdown content is parsed for:
- `- host: <hostname>` — SSH host
- `- port: <port>` — SSH port (default: 22)
- `- user: <username>` — SSH username
- `- password: <password>` — Password auth
- `- key: <private-key>` — Key auth

### API Endpoints (Secrets)

**Agent endpoints (require Ed25519 signature):**
- `POST /api/secrets/request` — Request a secret's content by name
- `GET /api/secrets/list` — List secret names and tags
- `POST /api/secrets/create-request` — Request creation of a new secret

**Management endpoints (require manage session):**
- `GET /api/manage/secrets` — List all secrets
- `GET /api/manage/secrets/:id/content` — Get secret content
- `POST /api/manage/secrets` — Add secret
- `PUT /api/manage/secrets/:id` — Update secret
- `DELETE /api/manage/secrets/:id` — Delete secret (requires passkey)

### Migration

When loading a vault with `hosts` but no `secrets`, hosts are automatically migrated to secrets with the `ssh` tag. The original `hosts` array is preserved for backward compatibility.

## Docker Setup

### Volumes

- `/app/config/` — config directory (auto-creates `config.yml` with localhost defaults if missing)
- `/app/data/` — encrypted vault storage (persist this!)

### Run standalone

```bash
docker run -d \
  --name ssh-vault \
  -p 3001:3001 \
  -v vault-data:/app/data \
  -v vault-config:/app/config \
  qsobad/ssh-vault-mcp:latest
```

### With custom domain

```bash
docker run -d \
  --name ssh-vault \
  -p 3001:3001 \
  -v vault-data:/app/data \
  -v vault-config:/app/config \
  -e SSH_VAULT_ORIGIN=https://ssh.example.com \
  qsobad/ssh-vault-mcp:latest
```

### Docker Compose

```yaml
services:
  ssh-vault:
    image: qsobad/ssh-vault-mcp:latest
    container_name: ssh-vault
    restart: unless-stopped
    ports:
      - "3001:3001"
    volumes:
      - vault-data:/app/data
      - vault-config:/app/config
    environment:
      - SSH_VAULT_ORIGIN=https://ssh.example.com

volumes:
  vault-data:
  vault-config:
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `SSH_VAULT_ORIGIN` | Full origin URL (e.g. `https://ssh.example.com`). Sets rpId, webauthn origin, and external URL. |
| `SSH_VAULT_PORT` | Web server port (default: 3001) |
| `SSH_VAULT_DATA_PATH` | Vault data path (default: `/app/data/vault.enc`) |

### Config File

Located at `/app/config/config.yml`. Auto-created with localhost defaults if missing.

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

`SSH_VAULT_ORIGIN` env var overrides `webauthn.rp_id`, `webauthn.origin`, and `web.external_url`.

## Claude Desktop MCP Configuration

Add to your Claude Desktop config:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

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

> `-i` keeps stdin open for MCP stdio transport. `--rm` cleans up on exit. Vault data persists in Docker volumes.

## Agent Keypair

Generate an Ed25519 keypair for agent request signing:

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

Store the keypair securely. The agent uses it to sign all API requests.

## Execution Flow

### One-Step Approve-Exec

When agent calls `POST /api/vault/execute` without a valid session:

1. Vault creates an exec-request and returns `{ needsApproval, approvalUrl, listenUrl, execRequestId }`
2. Agent presents `approvalUrl` to user and listens on SSE (`listenUrl`)
3. User opens `/approve-exec` page — sees host + command
4. User authenticates with **Master Password + Passkey**
5. Vault unlocks → creates session → executes command
6. SSE delivers: `pending → approved → executing → completed`
7. Completed event includes `{ stdout, stderr, exitCode, sessionId }`
8. Agent uses `sessionId` for subsequent calls — no re-approval needed

### Shell Commands

All shell metacharacters are allowed (`&&`, `;`, `|`, `$()`, backticks, etc.). Agent is trusted after Passkey approval.

### Adding Hosts

Agent requests host addition without providing credentials. User enters password or private key during approval on the `/approve-host` page.

## MCP Tools

| Tool | Description | Auth |
|------|-------------|------|
| `vault_status` | Check lock status | Signed |
| `request_unlock` | Get Passkey auth URL | Signed |
| `submit_unlock` | Submit unlock code | Signed |
| `list_hosts` | List SSH hosts | Signed |
| `execute_command` | Run SSH command | Signed + Session |
| `manage_vault` | Manage hosts/agents | Signed |
| `revoke_session` | End session | Signed |
| `request_access` | Request host access | No auth (auto-enlists) |

## HTTP API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/vault/status` | Vault lock status |
| POST | `/api/vault/execute` | Execute SSH command (signed, auto-creates exec-request if no session) |
| POST | `/api/vault/submit-unlock` | Submit unlock code |
| GET | `/api/vault/exec-request/:id` | Get exec request info/status |
| GET | `/api/vault/exec-request/:id/listen` | SSE for exec request status |
| POST | `/api/vault/exec-request/:id/approve` | Approve exec (Passkey + password → unlock + execute) |
| POST | `/api/vault/exec-request/:id/reject` | Reject exec request |
| POST | `/api/vault/upload` | SFTP upload (base64 content) |
| POST | `/api/vault/download` | SFTP download (returns base64) |
| POST | `/api/vault/ls` | SFTP directory listing |
| POST | `/api/agent/request-access` | Request host access |
| POST | `/api/agent/register` | Agent-initiated registration |
| GET | `/api/agent/register/:id/listen` | SSE for registration approval |
| POST | `/api/agent/register/:id/approve` | Approve agent registration |
| POST | `/api/agent/request-host` | Agent-initiated host addition (credential optional) |
| GET | `/api/agent/request-host/:id/listen` | SSE for host request approval |
| POST | `/api/agent/request-host/:id/approve` | Approve host (user provides credential) |
| GET | `/api/challenge/:id/listen` | SSE approval notifications |
| POST | `/api/auth/options` | Passkey auth options |
| POST | `/api/auth/verify` | Passkey auth verify |
| GET | `/api/manage/data` | List hosts/agents (authed) |
| POST | `/api/manage/change-password` | Change master password (Passkey required) |

## Security

### Encryption
- **At rest**: Argon2id(Master Password, salt) → VEK → XSalsa20-Poly1305
- **KDF parameters**: t=3, m=64MB, p=1 — Argon2id
- **Vault file**: `0600` permissions
- **On-demand**: Credentials decrypted per command, wiped immediately

### Runtime Protection
- **Auto-lock**: VEK wiped after configurable inactivity (default 15 min)
- **30s nonce window**: Replay protection
- **Rate limiting**: 5 attempts/IP/5min on auth endpoints
- **Approval link expiry**: All challenge/approval links expire after 5 minutes
- **Password strength**: zxcvbn validation enforced

### Policy Engine
- Command whitelist/blacklist (global + per-agent)
- Dangerous pattern detection (`rm -rf /`, `mkfs`, `dd`, fork bombs)
- Timeout limits: 1-300s
- Shell metacharacters allowed (agent trusted after Passkey approval)

## Development

```bash
git clone https://github.com/qsobad/ssh-vault-mcp.git
cd ssh-vault-mcp
npm install
npx tsx src/index.ts     # Dev mode
npm run build            # Build
npx tsc --noEmit         # Type check
```

## License

MIT
