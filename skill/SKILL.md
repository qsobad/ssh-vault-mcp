# SSH Vault Skill

Secure SSH access through a Passkey-protected vault. Agent installs, connects, and operates — user approves via chat.

## Quick Start (Agent Self-Install)

If SSH Vault is not running, install it yourself:

```bash
# 1. Pull and start
docker pull qsobad/ssh-vault-mcp:latest
docker run -d --name ssh-vault --restart unless-stopped \
  -p 3001:3001 \
  -v ssh-vault-data:/app/data \
  -v ./config.yml:/app/config.yml:ro \
  -e SSH_VAULT_CONFIG=/app/config.yml \
  qsobad/ssh-vault-mcp:latest

# 2. Generate your agent keypair
ssh-keygen -t ed25519 -f ~/.ssh/ssh-vault-agent -N "" -C "openclaw-agent"
```

Then follow the **Chat-Driven Setup** flow below.

## Chat-Driven Setup Flow

Everything happens through conversation with the user:

### Step 1: Install (if needed)
- Check: `docker ps --filter name=ssh-vault`
- If not running: pull image, generate config, start container
- Send user: "SSH Vault 已安装，请打开 {URL} 设置密码和Passkey"

### Step 2: Wait for user to set up vault
- User opens the URL in browser
- Sets Master Password + registers Passkey
- Tells you when done

### Step 3: Register yourself as agent
```bash
FINGERPRINT=$(ssh-keygen -lf ~/.ssh/ssh-vault-agent.pub | awk '{print $2}')
PUBKEY=$(awk '{print $2}' ~/.ssh/ssh-vault-agent.pub)

curl -s http://localhost:3001/api/agent/register \
  -H 'Content-Type: application/json' \
  -d "{\"fingerprint\":\"$FINGERPRINT\",\"publicKey\":\"$PUBKEY\",\"name\":\"OpenClaw Agent\"}"
```

- **Send the `approvalUrl` to user via chat**
- User opens link → Passkey + password → approves
- ⏰ Link expires in 5 minutes

### Step 4: Add hosts (when needed)
```bash
curl -s http://localhost:3001/api/agent/request-host \
  -H 'Content-Type: application/json' \
  -d '{"name":"my-server","host":"1.2.3.4","port":22,"username":"root","credential":"...","authType":"password"}'
```

- **Send the `approvalUrl` to user via chat**
- User approves
- ⏰ Link expires in 5 minutes

### Config Template
```yaml
webauthn:
  rpId: "localhost"          # or your domain
  rpName: "SSH Vault"
  origin: "http://localhost:3001"  # or https://your-domain

web:
  port: 3001
  external_url: "http://localhost:3001"
```

For HTTPS with a domain, set `rpId` to the domain and `origin` to `https://domain`.

## Security Model

- **Encryption**: Argon2id(Master Password) → VEK → XSalsa20-Poly1305
- **KDF**: t=3, m=64MB, p=1
- **Auth**: Passkey (WebAuthn) for user, Ed25519 signatures for agent
- **Auto-lock**: 15 min inactivity → VEK wiped
- **On-demand decryption**: Credentials decrypted per-command, wiped immediately
- **Policy**: Command whitelist/blacklist + shell injection detection
- **Rate limiting**: 5 attempts/IP/5min
- **Approval expiry**: All links expire in 5 minutes
- **Password strength**: zxcvbn validation

## Workflow (After Setup)

### 1. Check status
```bash
curl -s http://localhost:3001/health
curl -s http://localhost:3001/api/vault/status
```

### 2. Unlock vault (if locked)
```bash
curl -s -X POST http://localhost:3001/api/vault/unlock \
  -H 'Content-Type: application/json' \
  -d '{"agentFingerprint":"SHA256:..."}'
```
→ Send `unlockUrl` to user via chat → user authenticates with Passkey

### 3. Execute SSH command
```bash
curl -s -X POST http://localhost:3001/api/vault/execute \
  -H 'Content-Type: application/json' \
  -d '{
    "host": "my-server",
    "command": "docker ps",
    "fingerprint": "SHA256:...",
    "publicKey": "...",
    "signature": "...",
    "timestamp": "...",
    "nonce": "..."
  }'
```

All requests must be Ed25519 signed. Timestamp within 30 seconds.

### 4. If command needs approval
Response includes `approvalUrl` → send to user via chat → user approves

## Key Rules for Agents

1. **Never ask for passwords** — you don't need them, the vault handles auth
2. **Send all approval links via chat** — the user approves on their device
3. **No shell metacharacters** — `|`, `;`, `&&` are blocked. Use simple commands
4. **Watch for auto-lock** — vault locks after 15 min, need user to unlock again
5. **Private key stays local** — never transmit `~/.ssh/ssh-vault-agent`
6. **Credential in request-host** — this is the SSH password or key for the target server, encrypted in vault

## Error Handling

| Error | Action |
|-------|--------|
| "Vault is locked" | Send unlock URL to user via chat |
| "Session expired" | Request access again |
| "Command denied" | Tell user, suggest alternative |
| "Shell injection" | Simplify command, remove pipes |
| "Rate limited" (429) | Wait and retry |

## File Locations

- Agent keypair: `~/.ssh/ssh-vault-agent` / `~/.ssh/ssh-vault-agent.pub`
- Vault data: Docker volume `ssh-vault-data`
- Config: Mounted as `/app/config.yml`
