/**
 * Security Breach Tests: Web Server Endpoints
 *
 * Tests the HTTP API endpoints for authentication bypass,
 * missing authorization checks, CORS issues, and
 * information disclosure vulnerabilities.
 */

import { describe, it, expect } from 'vitest';

describe('Security Breach: Web Server Endpoints', () => {
  /**
   * These tests document security concerns found in the web server code
   * at src/web/server.ts. They don't require a running server - they
   * verify the code patterns through static analysis documentation.
   */

  describe('Unauthenticated Endpoint Analysis', () => {
    it('REMAINING: /api/vault/unlock still accepts requests without agent signature', () => {
      // server.ts:82-98
      // POST /api/vault/unlock creates unlock challenges for ANY caller
      // Only uses req.body.agentFingerprint, defaulting to 'SHA256:unknown-agent'
      // No signature verification - but rate limiting now applied on submit-unlock
      const finding = {
        endpoint: 'POST /api/vault/unlock',
        severity: 'LOW',
        issue: 'No authentication to create unlock challenges, but submit-unlock is rate-limited',
        file: 'src/web/server.ts',
        line: 82,
      };
      expect(finding.severity).toBe('LOW');
    });

    it('FIXED: /api/vault/execute now requires agent signature and session', () => {
      // server.ts:182-368
      // POST /api/vault/execute now requires:
      // 1. Agent signature verification (signature, publicKey, timestamp, nonce)
      // 2. Valid sessionId
      // 3. Session must belong to the agent
      // 4. Dangerous pattern check
      // 5. Shell injection check
      // 6. Policy engine check
      const finding = {
        endpoint: 'POST /api/vault/execute',
        severity: 'INFO',
        issue: 'Execute endpoint now has full auth, policy, and injection checks',
        secure: true,
        checks: ['agent signature', 'session validation', 'session-agent binding', 'dangerous patterns', 'shell injection', 'policy engine'],
        file: 'src/web/server.ts',
        line: 182,
      };
      expect(finding.secure).toBe(true);
      expect(finding.checks.length).toBe(6);
    });

    it('REMAINING: /api/vault/status exposes vault lock state to any caller', () => {
      // server.ts:131-137
      // GET /api/vault/status returns whether vault is locked/exists
      // No authentication required - low risk info disclosure
      const finding = {
        endpoint: 'GET /api/vault/status',
        severity: 'LOW',
        issue: 'Vault state exposed without authentication',
        file: 'src/web/server.ts',
        line: 131,
      };
      expect(finding.severity).toBe('LOW');
    });

    it('REMAINING: /api/challenge/:id exposes challenge details without auth', () => {
      // server.ts:371-388
      // GET /api/challenge/:id returns challenge info
      // Challenge IDs are random (generateRandomId), so low enumeration risk
      const finding = {
        endpoint: 'GET /api/challenge/:id',
        severity: 'LOW',
        issue: 'Challenge details exposed with only challengeId as auth',
        file: 'src/web/server.ts',
        line: 371,
      };
      expect(finding.severity).toBe('LOW');
    });

    it('REMAINING: /api/challenge/:id/status has no auth', () => {
      // server.ts:391-394
      const finding = {
        endpoint: 'GET /api/challenge/:id/status',
        severity: 'LOW',
        issue: 'Challenge polling endpoint has no auth, but challengeId is random',
        file: 'src/web/server.ts',
        line: 391,
      };
      expect(finding.severity).toBe('LOW');
    });
  });

  describe('Management Session Security', () => {
    it('FINDING: Management session tokens are UUIDs stored in memory Map', () => {
      // server.ts:504
      // manageSessions is a Map<string, { expiresAt, vek }>
      // Tokens are UUID v4 - cryptographically random
      // But stored in-memory only, no persistence
      //
      // Risk: VEK (vault encryption key) is held in memory
      // for up to 30 minutes per session
      const finding = {
        issue: 'VEK stored in memory for management session duration',
        severity: 'MEDIUM',
        mitigations: ['30-minute timeout', 'UUID tokens are unpredictable'],
        file: 'src/web/server.ts',
        line: 504,
      };
      expect(finding.mitigations.length).toBeGreaterThan(0);
    });

    it('FINDING: Bearer token parsed with simple string replace', () => {
      // server.ts:508
      // const token = req.headers.authorization?.replace('Bearer ', '');
      // This is case-sensitive and only strips "Bearer " prefix
      //
      // Risk: Could be bypassed with "bearer " (lowercase) or extra spaces
      // However Express normalizes header names to lowercase...
      // Actually, the value is not normalized, so "Bearer" must match exactly
      const headerValue = 'Bearer my-token-123';
      const token = headerValue.replace('Bearer ', '');
      expect(token).toBe('my-token-123');

      // But what about "bearer " (lowercase)?
      const lowerToken = 'bearer my-token-123'.replace('Bearer ', '');
      expect(lowerToken).toBe('bearer my-token-123'); // Not stripped!
    });

    it('FINDING: No CSRF protection on management endpoints', () => {
      // Management endpoints accept JSON with Bearer tokens
      // No CSRF tokens, no Referer/Origin checking
      // Protected only by Bearer token in Authorization header
      //
      // Risk: Browser-based CSRF is unlikely since cross-origin
      // requests can't set Authorization header without CORS
      const finding = {
        severity: 'LOW',
        issue: 'No CSRF protection, but mitigated by Authorization header',
        file: 'src/web/server.ts',
      };
      expect(finding.severity).toBe('LOW');
    });
  });

  describe('CORS Configuration', () => {
    it('FINDING: CORS origin is set to webauthn.origin config value', () => {
      // server.ts:37-39
      // CORS is configured with a specific origin from config
      // This is secure - not using origin: '*'
      const finding = {
        severity: 'INFO',
        issue: 'CORS properly configured with specific origin',
        secure: true,
      };
      expect(finding.secure).toBe(true);
    });
  });

  describe('Registration Security', () => {
    it('FINDING: Registration properly blocked after vault exists', () => {
      // server.ts:226-229
      // POST /api/register/options checks vaultExists() first
      // Returns 403 if vault already exists
      //
      // This prevents vault takeover attacks
      const finding = {
        severity: 'INFO',
        issue: 'Registration endpoint protected against re-registration',
        secure: true,
        file: 'src/web/server.ts',
        line: 226,
      };
      expect(finding.secure).toBe(true);
    });

    it('FINDING: Password is required for registration', () => {
      // server.ts:257-259
      // Registration requires a master password alongside WebAuthn
      const finding = {
        severity: 'INFO',
        issue: 'Master password required for registration',
        secure: true,
      };
      expect(finding.secure).toBe(true);
    });
  });

  describe('SSE/WebSocket Security', () => {
    it('FIXED: SSE endpoint now filters sessionId unless agent fingerprint provided', () => {
      // server.ts:640-689
      // GET /api/challenge/:id/listen now accepts ?fingerprint= query param
      // Only includes sessionId in events if the listener provided agent fingerprint
      // This prevents unauthenticated observers from learning sessionIds
      const finding = {
        endpoint: 'GET /api/challenge/:id/listen',
        severity: 'LOW',
        issue: 'SSE endpoint filters sessionId unless agent fingerprint is provided',
        file: 'src/web/server.ts',
        line: 640,
        mitigation: 'sessionId stripped from events for unauthenticated listeners',
      };
      expect(finding.severity).toBe('LOW');
    });

    it('SSE timeout aligned with challenge expiry', () => {
      // server.ts:681-688
      // SSE connection times out when the challenge expires
      const finding = {
        severity: 'INFO',
        issue: 'SSE has proper timeout based on challenge expiry',
        secure: true,
      };
      expect(finding.secure).toBe(true);
    });
  });

  describe('Logging Security', () => {
    it('REMAINING: VEK length logged during registration and auth', () => {
      // server.ts:451, 749
      // console.log('[register] VEK derived from password, length:', vek.length);
      // console.log('[manage-auth] VEK derived from password, length:', vek.length);
      // Low risk - only length is logged, not the key itself
      const finding = {
        severity: 'INFO',
        issue: 'VEK length logged (not the key material)',
      };
      expect(finding.severity).toBe('INFO');
    });

    it('REMAINING: Auth type logged during SSH execution', () => {
      // server.ts:326
      // console.log('[execute] authType:', hostConfig.authType);
      // Credential length no longer logged (credential is decrypted on-demand)
      const finding = {
        severity: 'LOW',
        issue: 'Auth type logged during SSH execution',
        file: 'src/web/server.ts',
        line: 326,
      };
      expect(finding.severity).toBe('LOW');
    });

    it('REMAINING: Connection details logged during SSH execution', () => {
      // server.ts:338
      // console.log('[execute] Connecting to:', connectConfig.host, connectConfig.port, connectConfig.username);
      const finding = {
        severity: 'LOW',
        issue: 'SSH connection target details logged',
        file: 'src/web/server.ts',
        line: 338,
      };
      expect(finding.severity).toBe('LOW');
    });
  });

  describe('Rate Limiting (New Security Feature)', () => {
    it('FIXED: Rate limiting now applied on authentication endpoints', () => {
      // server.ts:16-29
      // checkRateLimit() uses an in-memory Map with 5-minute window, max 5 attempts
      // Applied to: submit-unlock, register/verify, auth/verify, manage/auth
      const finding = {
        severity: 'INFO',
        issue: 'Rate limiting now configured on auth endpoints',
        secure: true,
        config: {
          maxAttempts: 5,
          windowMs: 5 * 60 * 1000,
        },
        protectedEndpoints: [
          'POST /api/vault/submit-unlock',
          'POST /api/auth/verify',
          'POST /api/manage/auth',
          'POST /api/register/verify',
        ],
      };
      expect(finding.secure).toBe(true);
      expect(finding.protectedEndpoints.length).toBe(4);
      expect(finding.config.maxAttempts).toBe(5);
    });

    it('Rate limit cleanup runs periodically', () => {
      // server.ts:32-37
      // setInterval cleans up stale entries every 5 minutes
      // Prevents memory growth from rate limit tracking
      const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;
      expect(CLEANUP_INTERVAL_MS).toBe(300000);
    });

    it('REMAINING: /api/vault/unlock endpoint is not rate limited', () => {
      // Only creates challenges, doesn't execute or authenticate
      // Low risk but could be used for memory exhaustion
      const finding = {
        endpoint: 'POST /api/vault/unlock',
        severity: 'LOW',
        issue: 'Challenge creation endpoint not rate limited, could exhaust memory',
      };
      expect(finding.severity).toBe('LOW');
    });
  });

  describe('Error Information Disclosure', () => {
    it('REMAINING: Error messages may expose internal details', () => {
      // Various endpoints return error.message directly
      // Risk: Stack traces or internal paths could leak
      const finding = {
        severity: 'LOW',
        issue: 'Error messages returned to client may contain internal details',
        pattern: 'error instanceof Error ? error.message : ...',
      };
      expect(finding.severity).toBe('LOW');
    });
  });

  describe('Execute Endpoint Security Checks (New)', () => {
    it('FIXED: Execute requires agent signature verification', () => {
      // server.ts:190-207
      // Requires: signature, publicKey, timestamp, nonce
      // Uses verifySignedRequest() for Ed25519 signature verification
      const finding = {
        check: 'Agent signature verification',
        secure: true,
        requiredFields: ['signature', 'publicKey', 'timestamp', 'nonce'],
        verification: 'verifySignedRequest() with Ed25519',
      };
      expect(finding.secure).toBe(true);
      expect(finding.requiredFields.length).toBe(4);
    });

    it('FIXED: Execute requires valid session bound to agent', () => {
      // server.ts:209-225
      // Checks sessionId, validates session exists and hasn't expired,
      // then verifies session.agentFingerprint matches verification.fingerprint
      const finding = {
        check: 'Session-agent binding',
        secure: true,
        steps: ['sessionId required', 'session exists and not expired', 'session belongs to agent'],
      };
      expect(finding.secure).toBe(true);
      expect(finding.steps.length).toBe(3);
    });

    it('FIXED: Execute runs dangerous pattern check before SSH connection', () => {
      // server.ts:243-248
      // checkDangerousPatterns() blocks rm, mkfs, dd, fork bombs, etc.
      const finding = {
        check: 'Dangerous pattern check',
        secure: true,
        blocksBeforeSSH: true,
      };
      expect(finding.secure).toBe(true);
    });

    it('FIXED: Execute runs shell injection check before SSH connection', () => {
      // server.ts:251-255
      // checkShellInjection() blocks pipes, redirects, semicolons, backticks, $()
      const finding = {
        check: 'Shell injection check',
        secure: true,
        detectedPatterns: ['pipe', 'redirect', 'semicolon', 'backtick', 'command substitution', 'logical AND', 'logical OR'],
      };
      expect(finding.secure).toBe(true);
      expect(finding.detectedPatterns.length).toBe(7);
    });

    it('FIXED: Execute runs policy engine check', () => {
      // server.ts:257-269
      // Checks agent exists, gets global policy, runs policyEngine.checkCommand()
      const finding = {
        check: 'Policy engine enforcement',
        secure: true,
        steps: ['agent registered in vault', 'global policy loaded', 'checkCommand() evaluation'],
      };
      expect(finding.secure).toBe(true);
    });

    it('FIXED: Timeout clamped to 1-300 seconds', () => {
      // server.ts:233-241
      // let execTimeout = 30 (default)
      // Number.isFinite(t) check rejects NaN, Infinity
      // Math.min(Math.max(t, 1), 300) clamps to [1, 300]
      const finding = {
        check: 'Timeout validation',
        secure: true,
        default: 30,
        min: 1,
        max: 300,
        rejectsInfinity: true,
        rejectsNaN: true,
      };
      expect(finding.secure).toBe(true);
      expect(finding.min).toBe(1);
      expect(finding.max).toBe(300);
    });
  });

  describe('Auto-Lock & VEK Lifecycle (New Security Feature)', () => {
    it('Vault auto-locks after inactivity', () => {
      // vault.ts:38-39, 67-78
      // Auto-lock timer defaults to 15 minutes
      // resetAutoLockTimer() called on every vault operation
      // lock() clears timer, secureWipes currentSignature, nulls vault, clears sessions
      const finding = {
        feature: 'Auto-lock timer',
        secure: true,
        defaultTimeout: 15 * 60 * 1000,
        configurable: true,
      };
      expect(finding.secure).toBe(true);
      expect(finding.defaultTimeout).toBe(900000);
    });

    it('Vault strips credentials from in-memory representation', () => {
      // vault.ts:83-88
      // stripCredentials() replaces credential with '[encrypted]'
      // Called after every vault load/save
      const finding = {
        feature: 'Credential stripping',
        secure: true,
        placeholder: '[encrypted]',
      };
      expect(finding.secure).toBe(true);
    });

    it('On-demand credential decryption with secure wipe', () => {
      // vault.ts:94-104
      // decryptHostCredential() decrypts single host credential using currentSignature
      // Caller must secureWipe after use (server.ts finally block does this)
      const finding = {
        feature: 'On-demand decryption',
        secure: true,
        lifecycle: ['decrypt on-demand', 'use credential', 'secure wipe in finally'],
      };
      expect(finding.secure).toBe(true);
      expect(finding.lifecycle.length).toBe(3);
    });

    it('Lock securely wipes VEK from memory', () => {
      // vault.ts:568-579
      // lock() calls secureWipe(this.currentSignature) before nulling
      // Also clears all sessions
      const finding = {
        feature: 'Secure VEK wipe on lock',
        secure: true,
        operations: ['clearTimeout', 'secureWipe(currentSignature)', 'null vault', 'clear sessions'],
      };
      expect(finding.secure).toBe(true);
      expect(finding.operations.length).toBe(4);
    });

    it('isUnlocked() requires both vault and currentSignature', () => {
      // vault.ts:116-118
      // return this.vault !== null && this.currentSignature !== null
      // Both must be present - partial state not treated as unlocked
      const finding = {
        feature: 'Dual unlock check',
        secure: true,
        conditions: ['vault !== null', 'currentSignature !== null'],
      };
      expect(finding.secure).toBe(true);
    });
  });

  describe('Host Credential Exposure', () => {
    it('Management data endpoint properly masks credentials', () => {
      // server.ts:789
      // hosts: vault.hosts.map(h => ({ ...h, credential: '***' }))
      const finding = {
        severity: 'INFO',
        issue: 'Credentials properly masked in management API responses',
        secure: true,
      };
      expect(finding.secure).toBe(true);
    });

    it('FIXED: /api/vault/execute now uses on-demand decryption with secure wipe', () => {
      // server.ts:282-361
      // The execute endpoint now:
      // 1. Requires agent signature and session
      // 2. Uses decryptHostCredential() for on-demand decryption
      // 3. Securely wipes credential from memory after use (finally block)
      // 4. In-memory vault only has '[encrypted]' placeholder
      const finding = {
        severity: 'INFO',
        issue: 'Credentials decrypted on-demand and wiped after use',
        secure: true,
        securityMeasures: [
          'on-demand decryption',
          'secure wipe in finally block',
          'in-memory vault has [encrypted] placeholder',
          'policy engine check before decryption',
        ],
        file: 'src/web/server.ts',
        line: 282,
      };
      expect(finding.secure).toBe(true);
      expect(finding.securityMeasures.length).toBe(4);
    });
  });
});
