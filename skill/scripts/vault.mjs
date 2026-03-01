#!/usr/bin/env node
/**
 * Secret Vault CLI — sign requests with agent Ed25519 key and interact with vault API.
 * Usage: node vault.mjs <command> [args...]
 * 
 * Commands:
 *   status                       - Check vault lock status
 *   session                      - Show cached session info
 *   register                     - Register agent with vault
 *   secrets                      - List secrets (name + description)
 *   get-secret <name>            - Request secret content (triggers approval if needed)
 *   create-secret <name> [desc]  - Request secret creation (user fills content)
 *   exec <host> <cmd> [timeout]  - Execute SSH command on host
 */

import _sodium from 'libsodium-wrappers';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import crypto from 'crypto';

await _sodium.ready;
const sodium = _sodium;

const VAULT_URL = process.env.SSH_VAULT_URL;
if (!VAULT_URL) {
  console.error('Error: SSH_VAULT_URL env var required');
  process.exit(1);
}
const SESSION_FILE = '/tmp/ssh-vault-session.json';

const PRIVATE_KEY_B64 = process.env.SSH_VAULT_AGENT_PRIVATE_KEY;
const PUBLIC_KEY_B64 = process.env.SSH_VAULT_AGENT_PUBLIC_KEY;
if (!PRIVATE_KEY_B64 || !PUBLIC_KEY_B64) {
  console.error('Error: SSH_VAULT_AGENT_PRIVATE_KEY and SSH_VAULT_AGENT_PUBLIC_KEY env vars required');
  process.exit(1);
}

const FINGERPRINT = 'SHA256:' + crypto.createHash('sha256').update(Buffer.from(PUBLIC_KEY_B64, 'base64')).digest('base64').replace(/=+$/, '');
const PRIVATE_KEY = Buffer.from(PRIVATE_KEY_B64, 'base64');

function sign(payloadObj) {
  const payload = JSON.stringify(payloadObj);
  const timestamp = Date.now();
  const nonce = Buffer.from(sodium.randombytes_buf(16)).toString('hex');
  const message = `${payload}:${timestamp}:${nonce}`;
  const signature = Buffer.from(
    sodium.crypto_sign_detached(Buffer.from(message), PRIVATE_KEY)
  ).toString('base64');
  return { signature, publicKey: PUBLIC_KEY_B64, timestamp, nonce };
}

function loadSession() {
  try {
    if (existsSync(SESSION_FILE)) {
      const data = JSON.parse(readFileSync(SESSION_FILE, 'utf-8'));
      if (data.expiresAt && data.expiresAt > Date.now()) return data;
    }
  } catch {}
  return null;
}

function saveSession(session) {
  writeFileSync(SESSION_FILE, JSON.stringify(session, null, 2));
}

async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`${VAULT_URL}${path}`, opts);
  const text = await res.text();
  try { return JSON.parse(text); } catch { return { raw: text, status: res.status }; }
}

async function signedApi(method, path, payload = {}) {
  const sig = sign(payload);
  const session = loadSession();
  if (method === 'GET') {
    const params = new URLSearchParams({
      publicKey: PUBLIC_KEY_B64,
      signature: sig.signature,
      timestamp: String(sig.timestamp),
      nonce: sig.nonce,
      fingerprint: FINGERPRINT,
      payload: JSON.stringify(payload),
    });
    if (session) params.set('sessionId', session.sessionId);
    return api('GET', `${path}?${params}`);
  }
  const body = { ...payload, ...sig, payload: JSON.stringify(payload) };
  if (session) body.sessionId = session.sessionId;
  return api('POST', path, body);
}

/** Listen on SSE until terminal event, return parsed data */
function listenSSE(url, timeoutMs = 300000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('SSE timeout')), timeoutMs);
    fetch(url).then(res => {
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      function read() {
        reader.read().then(({ done, value }) => {
          if (done) { clearTimeout(timer); resolve(null); return; }
          buf += decoder.decode(value, { stream: true });
          const lines = buf.split('\n');
          buf = lines.pop();
          for (const line of lines) {
            if (line.startsWith('data: ')) {
              try {
                const data = JSON.parse(line.slice(6));
                if (data.status === 'completed' || data.status === 'approved' || data.status === 'rejected' || data.status === 'error') {
                  clearTimeout(timer);
                  // Save session if returned
                  if (data.sessionId) saveSession({ sessionId: data.sessionId, expiresAt: data.expiresAt || Date.now() + 900000 });
                  resolve(data);
                  return;
                }
              } catch {}
            }
          }
          read();
        });
      }
      read();
    }).catch(e => { clearTimeout(timer); reject(e); });
  });
}

// Commands
const cmd = process.argv[2];

if (cmd === 'status') {
  console.log(JSON.stringify(await api('GET', '/api/vault/status'), null, 2));

} else if (cmd === 'session') {
  const s = loadSession();
  if (s) {
    console.log(JSON.stringify({ ...s, expiresAtHuman: new Date(s.expiresAt).toISOString(), valid: true }, null, 2));
  } else {
    console.log(JSON.stringify({ valid: false, message: 'No active session' }, null, 2));
  }

} else if (cmd === 'register') {
  const r = await api('POST', '/api/agent/request-access', {
    name: 'openclaw',
    publicKey: PUBLIC_KEY_B64,
    requestedHosts: ['*'],
  });
  console.log(JSON.stringify(r, null, 2));

} else if (cmd === 'secrets') {
  // Server expects payload='list_secrets' for this endpoint
  const payload = 'list_secrets';
  const timestamp = Date.now();
  const nonce = Buffer.from(sodium.randombytes_buf(16)).toString('hex');
  const message = `${payload}:${timestamp}:${nonce}`;
  const signature = Buffer.from(sodium.crypto_sign_detached(Buffer.from(message), PRIVATE_KEY)).toString('base64');
  const session = loadSession();
  const params = new URLSearchParams({ publicKey: PUBLIC_KEY_B64, signature, timestamp: String(timestamp), nonce });
  if (session) params.set('sessionId', session.sessionId);
  const r = await api('GET', `/api/secrets/list?${params}`);
  console.log(JSON.stringify(r, null, 2));

} else if (cmd === 'get-secret') {
  const name = process.argv[3];
  if (!name) { console.error('Usage: vault.mjs get-secret <name>'); process.exit(1); }
  const r = await signedApi('POST', '/api/secrets/request', { name });
  if (r.needsApproval) {
    console.error(`Approval needed: ${r.approvalUrl}`);
    console.error('Waiting for approval...');
    const result = await listenSSE(r.listenUrl);
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(JSON.stringify(r, null, 2));
  }

} else if (cmd === 'create-secret') {
  const name = process.argv[3];
  const description = process.argv[4] || '';
  if (!name) { console.error('Usage: vault.mjs create-secret <name> [description]'); process.exit(1); }
  const r = await signedApi('POST', '/api/secrets/create-request', { name, description });
  if (r.approvalUrl) {
    console.error(`User must fill content: ${r.approvalUrl}`);
    console.error('Waiting...');
    const result = await listenSSE(r.listenUrl);
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(JSON.stringify(r, null, 2));
  }

} else if (cmd === 'exec') {
  const host = process.argv[3];
  const command = process.argv[4];
  const timeout = process.argv[5] ? parseInt(process.argv[5]) : 30;
  if (!host || !command) { console.error('Usage: vault.mjs exec <host> <command> [timeout]'); process.exit(1); }

  const payload = { host, command };
  const sig = sign(payload);
  const body = { ...payload, timeout, ...sig };
  const session = loadSession();
  if (session) body.sessionId = session.sessionId;

  const r = await api('POST', '/api/vault/execute', body);
  
  if (r.needsApproval) {
    console.error(`Approval needed: ${r.approvalUrl}`);
    console.error('Waiting...');
    const result = await listenSSE(r.listenUrl);
    if (result?.stdout !== undefined) {
      process.stdout.write(result.stdout);
      if (result.stderr) process.stderr.write(result.stderr);
    } else {
      console.log(JSON.stringify(result, null, 2));
    }
  } else if (r.output !== undefined) {
    process.stdout.write(r.output);
    if (r.exitCode !== undefined && r.exitCode !== 0) {
      process.stderr.write(`\n[exit code: ${r.exitCode}]`);
    }
  } else {
    console.log(JSON.stringify(r, null, 2));
  }

} else {
  console.log(`Secret Vault CLI
Usage: node vault.mjs <command> [args...]

Commands:
  status                       Check vault lock status
  session                      Show cached session
  register                     Register agent with vault
  secrets                      List secrets (name + description)
  get-secret <name>            Request secret content
  create-secret <name> [desc]  Request secret creation
  exec <host> <cmd> [timeout]  Execute SSH command on host`);
}
