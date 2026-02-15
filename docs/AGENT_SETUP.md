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

## 2. Request Access

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

## 4. Available Tools

| Tool | Description | Signed? |
|------|-------------|---------|
| `request_access` | Request host access | No |
| `vault_status` | Check vault status | Yes |
| `request_unlock` | Request vault unlock | Yes |
| `submit_unlock` | Submit unlock code | Yes |
| `list_hosts` | List available hosts | Yes |
| `execute_command` | Run SSH command | Yes |

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
