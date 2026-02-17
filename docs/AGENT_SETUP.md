# Agent Setup Guide

## 1. Generate Keypair (Agent-side)

Agent generates its own Ed25519 keypair locally. Private key never leaves the agent.

```javascript
import { getPublicKey, utils } from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';

// Generate keypair
const privateKey = utils.randomPrivateKey();
const publicKey = await getPublicKey(privateKey);

// Base64 encode
const privB64 = Buffer.from(privateKey).toString('base64');
const pubB64 = Buffer.from(publicKey).toString('base64');

// Generate fingerprint (SSH-style)
const hash = sha256(publicKey);
const fingerprint = 'SHA256:' + Buffer.from(hash).toString('base64').replace(/=+$/, '');

// Save securely
fs.writeFileSync('.ssh-vault-key', JSON.stringify({
  privateKey: privB64,
  publicKey: pubB64,
  fingerprint
}));
```

**⚠️ Store the privateKey securely!** It's needed to sign all requests.

## 2. Register Agent (Two Options)

### Option A: Agent-Initiated Registration (Recommended)

The agent registers itself, and the user approves via Passkey + Master Password:

```bash
curl -X POST https://ssh.29cp.cn/api/agent/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "clawdbot",
    "publicKey": "YOUR_PUBLIC_KEY"
  }'
```

Response:
```json
{
  "status": "pending_approval",
  "challengeId": "xxx",
  "approvalUrl": "https://ssh.29cp.cn/agent-register?id=xxx",
  "listenUrl": "https://ssh.29cp.cn/api/agent/register/xxx/listen"
}
```

**⚠️ Approval link expires in 5 minutes!**

The agent listens on `listenUrl` (SSE) for the approval event. The user opens `approvalUrl`, authenticates with Passkey, enters Master Password, configures agent permissions, and approves.

### Option B: Request Access (Legacy)

```bash
curl -X POST https://ssh.29cp.cn/api/agent/request-access \
  -H "Content-Type: application/json" \
  -d '{
    "name": "clawdbot",
    "publicKey": "YOUR_PUBLIC_KEY",
    "requestedHosts": ["*"],
    "reason": "SSH access for automation"
  }'
```

Response:
```json
{
  "status": "pending_approval",
  "approvalUrl": "https://ssh.29cp.cn/request-access?challenge=xxx",
  "listenUrl": "https://ssh.29cp.cn/api/challenge/xxx/listen"
}
```

**User clicks approvalUrl → authenticates with Passkey → approves access.**

## 3. Request Host Addition (Agent-Initiated)

Agents can request new SSH hosts to be added to the vault:

```bash
curl -X POST https://ssh.29cp.cn/api/agent/request-host \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-web-01",
    "hostname": "192.168.1.100",
    "port": 22,
    "username": "deploy",
    "authType": "key"
  }'
```

Response:
```json
{
  "status": "pending_approval",
  "challengeId": "yyy",
  "approvalUrl": "https://ssh.29cp.cn/agent-request-host?id=yyy",
  "listenUrl": "https://ssh.29cp.cn/api/agent/request-host/yyy/listen"
}
```

**⚠️ Approval link expires in 5 minutes!**

The user opens `approvalUrl`, authenticates with Passkey, enters Master Password, provides the SSH credential (password or private key), and approves. The agent never sees the credential.

## 3. Sign Requests

All MCP tool calls (except `generate_keypair`, `request_access`) require a signature.

### Signature Format

```javascript
// Message to sign
const message = JSON.stringify({
  tool: "vault_status",
  timestamp: Date.now(),
  nonce: crypto.randomUUID()
});

// Sign with Ed25519
const signature = ed25519.sign(message, privateKey);

// Call tool with signature
{
  "tool": "vault_status",
  "arguments": {
    "publicKey": "YOUR_PUBLIC_KEY",
    "timestamp": 1234567890,
    "nonce": "uuid-here",
    "signature": "BASE64_SIGNATURE"
  }
}
```

### Node.js Example

```javascript
import { sign } from '@noble/ed25519';

async function signRequest(tool, args, privateKey) {
  const timestamp = Date.now();
  const nonce = crypto.randomUUID();
  
  const message = JSON.stringify({ tool, timestamp, nonce });
  const msgBytes = new TextEncoder().encode(message);
  const privBytes = Buffer.from(privateKey, 'base64');
  
  const signature = await sign(msgBytes, privBytes);
  
  return {
    ...args,
    publicKey: YOUR_PUBLIC_KEY,
    timestamp,
    nonce,
    signature: Buffer.from(signature).toString('base64')
  };
}
```

## 5. Available Tools

| Tool | Description | Signed? |
|------|-------------|---------|
| `request_access` | Request host access | No |
| `vault_status` | Check vault status | Yes |
| `request_unlock` | Request vault unlock | Yes |
| `submit_unlock` | Submit unlock code | Yes |
| `list_hosts` | List available hosts | Yes |
| `execute_command` | Run SSH command | Yes |

## HTTP API Endpoints (Agent-Initiated)

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/agent/register` | Register agent (pending approval) | None |
| GET | `/api/agent/register/:id/listen` | SSE for registration status | None |
| POST | `/api/agent/request-host` | Request host addition (pending approval) | None |
| GET | `/api/agent/request-host/:id/listen` | SSE for host request status | None |
| POST | `/api/password-strength` | Check password strength | None |

## 5. Execute Command Flow

```
1. vault_status → check if unlocked
2. If locked: request_unlock → get URL → wait for approval
3. list_hosts → see available hosts
4. execute_command { host: "s1", command: "ls -la" }
```

## MCP Server URL

```
https://ssh.29cp.cn
```

The server exposes both HTTP API and MCP over stdio (for local use).
