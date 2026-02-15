# SSH Vault Skill

This skill enables secure SSH access through a Passkey-protected vault with Master Password encryption.

## Overview

SSH Vault MCP provides secure, human-approved SSH access. Credentials are encrypted with Argon2id + XSalsa20 (Master Password → VEK). Passkey authenticates the user. Agent signs all requests with Ed25519.

## Security Model

- **Encryption**: Argon2id(Master Password) → VEK → XSalsa20-Poly1305
- **Auth**: Passkey (WebAuthn) for human, Ed25519 signatures for agents
- **Credentials**: Never in memory as plaintext — decrypted on-demand per command, wiped immediately after
- **Auto-lock**: Vault locks after 15 min inactivity, VEK wiped from memory
- **Policy**: Global command whitelist/blacklist + shell injection detection
- **Rate limiting**: 5 attempts/IP/5min on all auth endpoints

## Agent Setup

### 1. Generate Ed25519 Keypair (locally)

```javascript
import nacl from 'tweetnacl';

const keypair = nacl.sign.keyPair();
const publicKey = Buffer.from(keypair.publicKey).toString('base64');
const privateKey = Buffer.from(keypair.secretKey).toString('base64');
```

**⚠️ Private key stays with the agent. Never send it to the vault.**

Store as JSON:
```json
{
  "name": "my-agent",
  "publicKey": "base64...",
  "privateKey": "base64...",
  "fingerprint": "SHA256:..."
}
```

### 2. Request Access

```bash
curl -X POST https://ssh.29cp.cn/api/agent/request-access \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-agent",
    "publicKey": "BASE64_PUBLIC_KEY",
    "requestedHosts": ["s1"]
  }'
```

Response:
```json
{
  "status": "pending_approval",
  "approvalUrl": "https://ssh.29cp.cn/request-access?challenge=xxx",
  "listenUrl": "https://ssh.29cp.cn/api/challenge/xxx/listen",
  "challengeId": "xxx"
}
```

User visits `approvalUrl` → Passkey auth → approves → agent gets session.

### 3. Listen for Approval (SSE)

Connect to `listenUrl` with `?agentFingerprint=SHA256:...` to receive events:

```javascript
const es = new EventSource(listenUrl + '?agentFingerprint=' + fingerprint);
es.onmessage = (e) => {
  const data = JSON.parse(e.data);
  if (data.type === 'approved') {
    // data.sessionId is your session token
  }
};
```

### 4. Sign Requests

All API calls require Ed25519 signature:

```javascript
const timestamp = Date.now().toString();
const message = `execute:${host}:${command}:${timestamp}`;
const signature = Buffer.from(
  nacl.sign.detached(new TextEncoder().encode(message), privateKeyBytes)
).toString('base64');
```

**Timestamp must be within 30 seconds** (replay protection).

## Workflow

### 1. Check Vault Status

```json
{ "tool": "vault_status" }
```

- `locked: true` → need unlock
- `locked: false` → ready

### 2. Unlock Vault (if locked)

```json
{ "tool": "request_unlock" }
```

Returns URL for user to authenticate with Passkey + Master Password. Two completion paths:

**Option A: SSE auto-notification (preferred)**
- Listen on `listenUrl` for `approved` event
- Continue automatically

**Option B: Manual unlock code**
- User copies code from web page
- Submit: `{ "tool": "submit_unlock", "unlock_code": "UNLOCK-X7K9P" }`

### 3. List Available Hosts

```json
{ "tool": "list_hosts" }
```

### 4. Execute Commands

```json
{
  "tool": "execute_command",
  "host": "s1",
  "command": "docker ps"
}
```

Requires:
- Valid session (from approved access request)
- Agent signature + timestamp
- Command passes policy engine (whitelist/blacklist + no shell injection)
- Timeout: 1-300 seconds (default 30)

**If command needs approval:**
```json
{
  "needsApproval": true,
  "approvalUrl": "https://ssh.29cp.cn/approve?challenge=xyz"
}
```

### 5. End Session

```json
{ "tool": "revoke_session" }
```

## Command Policy

**Blocked patterns:**
- `rm -rf /`, `mkfs`, `dd if=`, `:(){ :|:& };:`
- Shell metacharacters: `|`, `;`, `&&`, `||`, `>`, `<`, `` ` ``, `$()`

**Allowed commands** are configured per-agent during approval.

## Error Handling

| Error | Action |
|-------|--------|
| "Vault is locked" | Call `request_unlock` |
| "Session expired" | Request access again |
| "Command denied by policy" | Inform user, suggest alternative |
| "Shell injection detected" | Remove pipes/redirects, use simple commands |
| "Host not found" | Call `list_hosts` |
| "Rate limited" (429) | Wait and retry |
| "Invalid signature" | Check timestamp is within 30s, verify keypair |

## Important Notes

1. **Auto-lock**: Vault locks after 15 min inactivity. You'll need user to unlock again.
2. **On-demand decryption**: SSH credentials are never held in memory. Decrypted per-command, wiped immediately.
3. **No shell metacharacters**: Use simple commands. `cat file | grep x` is blocked — use `grep x file` instead.
4. **Agent private key**: Store securely on agent side only. Never transmit.
5. **Nonce window**: Timestamps older than 30 seconds are rejected.

## Server URL

```
https://ssh.29cp.cn
```

## File Locations

- Agent keypair: Store in agent's local environment (e.g., `data/my-agent.json`)
- Vault data: `data/vault.enc` (encrypted, 0600 permissions)
- Config: `src/config.ts`
