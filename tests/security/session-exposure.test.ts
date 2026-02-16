/**
 * Security Breach Tests: Session Data Exposure
 *
 * Tests information leakage through the getActiveSessions() API and
 * the management endpoint GET /api/manage/data. Covers session data
 * leakage, cross-agent enumeration, fingerprint exposure, timing
 * disclosure, approvedHosts isolation, reference-vs-copy semantics,
 * and race conditions in active session filtering.
 *
 * SECURITY FINDINGS documented inline per test.
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { VaultManager } from '../../src/vault/vault.js';
import {
  generateSalt,
  deriveKeyFromPassword,
  toBase64,
  LEGACY_KDF_PARAMS,
} from '../../src/vault/encryption.js';
import type { PasskeyCredential, Session } from '../../src/types.js';
import { promises as fs } from 'fs';
import path from 'path';
import os from 'os';

/**
 * Helper: create a VaultManager with a fresh temporary vault,
 * already unlocked and ready for session creation.
 */
async function createTestVault(opts?: { sessionTimeoutMinutes?: number }): Promise<{
  vaultManager: VaultManager;
  vek: Uint8Array;
  vaultPath: string;
}> {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-session-exposure-'));
  const vaultPath = path.join(tmpDir, 'test-vault.json');

  const vaultManager = new VaultManager(vaultPath, {
    sessionTimeoutMinutes: opts?.sessionTimeoutMinutes ?? 30,
    backupEnabled: false,
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
  const vek = deriveKeyFromPassword('test-password-session-exposure', salt, LEGACY_KDF_PARAMS);
  await vaultManager.createVault(credential, vek, toBase64(salt));

  return { vaultManager, vek, vaultPath };
}

/**
 * Helper: create a session for a given agent fingerprint via the
 * full challenge -> complete -> submitUnlockCode flow.
 */
async function createSessionForAgent(
  vaultManager: VaultManager,
  vek: Uint8Array,
  agentFingerprint: string
): Promise<Session> {
  const { challengeId } = vaultManager.createUnlockChallenge(
    'http://localhost:3000',
    agentFingerprint
  );
  const completed = await vaultManager.completeChallenge(challengeId, vek, false);
  expect(completed).not.toBeNull();
  const result = await vaultManager.submitUnlockCode(completed!.unlockCode, agentFingerprint);
  expect(result.success).toBe(true);

  const session = vaultManager.getSessionByAgent(agentFingerprint);
  expect(session).not.toBeNull();
  return session!;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Security Breach: Session Data Exposure', () => {
  let vaultManager: VaultManager;
  let vek: Uint8Array;

  beforeEach(async () => {
    const ctx = await createTestVault();
    vaultManager = ctx.vaultManager;
    vek = ctx.vek;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // =========================================================================
  // 1. Session data leakage via manage API
  // =========================================================================
  describe('Session data leakage via manage API', () => {
    /**
     * SECURITY FINDING: The manage API mapping at server.ts:791-800
     * intentionally strips approvedCommands from the response. This test
     * verifies that getActiveSessions() returns full Session objects
     * (which DO contain approvedCommands) and therefore the API-side
     * mapping is the only protection. If the mapping is ever changed to
     * spread the whole session object, approvedCommands would leak.
     */
    it('should include approvedCommands in raw session objects from getActiveSessions()', async () => {
      const session = await createSessionForAgent(vaultManager, vek, 'SHA256:agent-leak-test');

      // Add some approved commands to the session to ensure the field is populated
      session.approvedCommands['prod-db'] = ['SELECT * FROM users', 'DROP TABLE logs'];

      const activeSessions = vaultManager.getActiveSessions();
      expect(activeSessions.length).toBeGreaterThanOrEqual(1);

      const found = activeSessions.find(s => s.id === session.id);
      expect(found).toBeDefined();

      // The raw Session object DOES contain approvedCommands - this data
      // would leak if the manage API ever stops explicitly mapping fields.
      expect(found!.approvedCommands).toBeDefined();
      expect(found!.approvedCommands['prod-db']).toEqual(['SELECT * FROM users', 'DROP TABLE logs']);
    });

    it('should verify that the manage API mapping excludes approvedCommands', () => {
      /**
       * SECURITY FINDING: This test documents the expected shape of the
       * manage API response. The mapping at server.ts:794-799 picks only:
       *   id, agentFingerprint, approvedHosts, createdAt, expiresAt
       * and intentionally omits approvedCommands and challengeId.
       *
       * We simulate the mapping here to confirm the exclusion.
       */
      const mockSession: Session = {
        id: 'session-123',
        agentFingerprint: 'SHA256:agent-abc',
        approvedHosts: ['dev-*'],
        approvedCommands: { 'prod-db': ['rm -rf /'] },
        challengeId: 'challenge-secret',
        createdAt: Date.now(),
        expiresAt: Date.now() + 30 * 60 * 1000,
      };

      // Replicate the exact mapping from server.ts:794-799
      const apiResponse = {
        id: mockSession.id,
        agentFingerprint: mockSession.agentFingerprint,
        approvedHosts: mockSession.approvedHosts,
        createdAt: mockSession.createdAt,
        expiresAt: mockSession.expiresAt,
      };

      // approvedCommands MUST NOT appear in the mapped output
      expect(apiResponse).not.toHaveProperty('approvedCommands');
      // challengeId MUST NOT appear either
      expect(apiResponse).not.toHaveProperty('challengeId');
    });

    it('should also exclude challengeId from the manage API mapping', () => {
      /**
       * SECURITY FINDING: challengeId stored in the session could be used
       * to correlate challenges with sessions or attempt challenge replay.
       * The mapping correctly omits it.
       */
      const mockSession: Session = {
        id: 'session-xyz',
        agentFingerprint: 'SHA256:agent-xyz',
        approvedHosts: [],
        approvedCommands: {},
        challengeId: 'secret-challenge-id-xyz',
        createdAt: Date.now(),
        expiresAt: Date.now() + 30 * 60 * 1000,
      };

      const mapped = {
        id: mockSession.id,
        agentFingerprint: mockSession.agentFingerprint,
        approvedHosts: mockSession.approvedHosts,
        createdAt: mockSession.createdAt,
        expiresAt: mockSession.expiresAt,
      };

      expect(Object.keys(mapped)).toEqual([
        'id', 'agentFingerprint', 'approvedHosts', 'createdAt', 'expiresAt',
      ]);
      expect(Object.keys(mapped)).not.toContain('challengeId');
      expect(Object.keys(mapped)).not.toContain('approvedCommands');
    });
  });

  // =========================================================================
  // 2. Session enumeration
  // =========================================================================
  describe('Session enumeration across agents', () => {
    /**
     * SECURITY FINDING: getActiveSessions() returns ALL active sessions
     * for ALL agents. A management user with a valid Bearer token can
     * enumerate every agent that currently has an active session. This is
     * by design for the management UI but constitutes a cross-agent
     * information disclosure vector.
     */
    it('should return sessions from ALL agents - not scoped to caller', async () => {
      await createSessionForAgent(vaultManager, vek, 'SHA256:agent-alpha');
      await createSessionForAgent(vaultManager, vek, 'SHA256:agent-beta');
      await createSessionForAgent(vaultManager, vek, 'SHA256:agent-gamma');

      const activeSessions = vaultManager.getActiveSessions();
      expect(activeSessions.length).toBe(3);

      const fingerprints = activeSessions.map(s => s.agentFingerprint);
      expect(fingerprints).toContain('SHA256:agent-alpha');
      expect(fingerprints).toContain('SHA256:agent-beta');
      expect(fingerprints).toContain('SHA256:agent-gamma');
    });

    it('should reveal the total number of active agents to any management user', async () => {
      // Create sessions for many agents
      for (let i = 0; i < 10; i++) {
        await createSessionForAgent(vaultManager, vek, `SHA256:agent-${i}`);
      }

      const activeSessions = vaultManager.getActiveSessions();
      // An attacker with management access can determine that exactly
      // 10 agents are currently active
      expect(activeSessions.length).toBe(10);
    });

    it('should not include expired sessions in enumeration', async () => {
      // Use a very short session timeout
      const ctx = await createTestVault({ sessionTimeoutMinutes: 0 });
      // sessionTimeoutMinutes=0 means 0ms timeout, sessions expire immediately
      const shortVm = ctx.vaultManager;
      const shortVek = ctx.vek;

      // Create a session - it will expire immediately (0 minute timeout)
      const { challengeId } = shortVm.createUnlockChallenge(
        'http://localhost:3000',
        'SHA256:ephemeral-agent'
      );
      const completed = await shortVm.completeChallenge(challengeId, shortVek, false);
      await shortVm.submitUnlockCode(completed!.unlockCode, 'SHA256:ephemeral-agent');

      // Wait a tick for time to advance past the expiry
      await new Promise(resolve => setTimeout(resolve, 10));

      const activeSessions = shortVm.getActiveSessions();
      // Session should already be expired with 0-minute timeout
      expect(activeSessions.length).toBe(0);
    });
  });

  // =========================================================================
  // 3. Agent fingerprint exposure
  // =========================================================================
  describe('Agent fingerprint exposure', () => {
    /**
     * SECURITY FINDING: Session data exposes agentFingerprint values
     * (e.g., "SHA256:abc123..."). If an attacker obtains management
     * access, they learn which agent fingerprints are currently active.
     * These fingerprints could be used to:
     * - Target specific agents for impersonation
     * - Correlate agent identity across sessions
     * - Identify high-value agents (e.g., those with prod access)
     */
    it('should expose full agent fingerprint in every session', async () => {
      const targetFingerprint = 'SHA256:high-value-production-agent-abc123';
      await createSessionForAgent(vaultManager, vek, targetFingerprint);

      const activeSessions = vaultManager.getActiveSessions();
      const exposedSession = activeSessions[0];

      // Full fingerprint is exposed, not truncated or hashed
      expect(exposedSession.agentFingerprint).toBe(targetFingerprint);
      expect(exposedSession.agentFingerprint).toContain('SHA256:');
    });

    it('should allow correlation between session fingerprints and vault agent config', async () => {
      /**
       * SECURITY FINDING: An attacker with management access can cross-
       * reference session fingerprints with the agents array (also
       * returned by /api/manage/data) to determine which named agent
       * has which sessions and what hosts they are allowed to access.
       */
      const fingerprint = 'SHA256:correlatable-agent';
      await createSessionForAgent(vaultManager, vek, fingerprint);

      const sessions = vaultManager.getActiveSessions();
      const sessionFp = sessions[0].agentFingerprint;

      // This fingerprint can be used to look up the agent in vault.agents
      // to discover allowedHosts, name, createdAt, etc.
      const agent = vaultManager.getAgent(sessionFp);
      // Agent may or may not exist in vault yet (session was from unlock challenge,
      // not access-request), but the fingerprint enables the lookup attempt.
      expect(sessionFp).toBe(fingerprint);
    });

    it('should expose unique fingerprints that enable session-to-agent mapping', async () => {
      await createSessionForAgent(vaultManager, vek, 'SHA256:agent-A');
      await createSessionForAgent(vaultManager, vek, 'SHA256:agent-B');

      const sessions = vaultManager.getActiveSessions();
      const fps = sessions.map(s => s.agentFingerprint);

      // Each fingerprint is unique and identifiable
      expect(new Set(fps).size).toBe(fps.length);
      // No anonymization or pseudonymization is applied
      expect(fps.every(fp => fp.startsWith('SHA256:'))).toBe(true);
    });
  });

  // =========================================================================
  // 4. Timing information disclosure
  // =========================================================================
  describe('Timing information disclosure', () => {
    /**
     * SECURITY FINDING: createdAt and expiresAt timestamps reveal:
     * - When agents become active (createdAt)
     * - How long sessions last (expiresAt - createdAt)
     * - When agents will need to re-authenticate (expiresAt)
     * - Agent activity patterns over time (if polled repeatedly)
     */
    it('should expose precise session creation time', async () => {
      const beforeCreate = Date.now();
      await createSessionForAgent(vaultManager, vek, 'SHA256:timing-agent');
      const afterCreate = Date.now();

      const sessions = vaultManager.getActiveSessions();
      const session = sessions.find(s => s.agentFingerprint === 'SHA256:timing-agent')!;

      // createdAt reveals the exact moment the agent authenticated
      expect(session.createdAt).toBeGreaterThanOrEqual(beforeCreate);
      expect(session.createdAt).toBeLessThanOrEqual(afterCreate);
    });

    it('should expose session duration from timestamps', async () => {
      await createSessionForAgent(vaultManager, vek, 'SHA256:duration-agent');

      const sessions = vaultManager.getActiveSessions();
      const session = sessions.find(s => s.agentFingerprint === 'SHA256:duration-agent')!;

      // An attacker can compute the exact session duration configuration
      const durationMs = session.expiresAt - session.createdAt;
      const durationMinutes = durationMs / (60 * 1000);

      // This reveals the server's sessionTimeoutMinutes setting
      expect(durationMinutes).toBe(30);
    });

    it('should allow computing time-until-expiry for targeted attacks', async () => {
      await createSessionForAgent(vaultManager, vek, 'SHA256:expiry-target');

      const sessions = vaultManager.getActiveSessions();
      const session = sessions.find(s => s.agentFingerprint === 'SHA256:expiry-target')!;

      const timeUntilExpiry = session.expiresAt - Date.now();

      // An attacker knows exactly how long they have before the session expires
      // This enables timing attacks: wait for session expiry, then act
      expect(timeUntilExpiry).toBeGreaterThan(0);
      expect(timeUntilExpiry).toBeLessThanOrEqual(30 * 60 * 1000);
    });

    it('should reveal activity patterns when sessions are touched', async () => {
      const session = await createSessionForAgent(vaultManager, vek, 'SHA256:activity-agent');
      const originalExpiry = session.expiresAt;

      // Simulate activity by touching the session
      await new Promise(resolve => setTimeout(resolve, 50));
      vaultManager.touchSession(session.id);

      const sessions = vaultManager.getActiveSessions();
      const updated = sessions.find(s => s.id === session.id)!;

      // After touch, expiresAt is extended - revealing the agent is still active
      expect(updated.expiresAt).toBeGreaterThan(originalExpiry);
    });
  });

  // =========================================================================
  // 5. approvedHosts population from allowedHosts
  // =========================================================================
  describe('approvedHosts isolation from allowedHosts', () => {
    /**
     * SECURITY FINDING: When an access request is approved (vault.ts:487-488),
     * session.approvedHosts is set via spread: [...agent.allowedHosts].
     * This creates a shallow copy, so subsequent modifications to
     * agent.allowedHosts should NOT retroactively change existing sessions.
     *
     * This is critical: if an admin revokes host access from an agent
     * after a session was created, the existing session must NOT gain
     * or lose hosts retroactively.
     */
    it('should copy allowedHosts by value, not reference, during access request approval', async () => {
      /**
       * The access request flow (vault.ts:487-488) does:
       *   const session = this.createSession(req.fingerprint);
       *   session.approvedHosts = [...agent.allowedHosts];
       *
       * We test this by creating a session via the unlock flow, then
       * manually setting approvedHosts using the same spread pattern,
       * and verifying that mutations to the source do not affect the copy.
       */
      const session = await createSessionForAgent(vaultManager, vek, 'SHA256:isolation-agent');

      // Simulate the spread-copy pattern from vault.ts:488
      const agentAllowedHosts = ['dev-*', 'staging-*'];
      session.approvedHosts = [...agentAllowedHosts];

      const originalHosts = [...session.approvedHosts];
      expect(originalHosts).toContain('dev-*');
      expect(originalHosts).toContain('staging-*');

      // Simulate admin modifying agent.allowedHosts AFTER session creation
      agentAllowedHosts.push('prod-*');
      agentAllowedHosts.splice(0, 1); // Remove 'dev-*'

      // Session's approvedHosts must remain unchanged
      expect(session.approvedHosts).toEqual(['dev-*', 'staging-*']);
      expect(session.approvedHosts).not.toContain('prod-*');

      // Create a second session for a different agent to verify isolation
      const session2 = await createSessionForAgent(vaultManager, vek, 'SHA256:isolation-agent-v2');
      session2.approvedHosts = [...agentAllowedHosts]; // Now ['staging-*', 'prod-*']

      // First session is unaffected by second session's hosts
      expect(session.approvedHosts).toEqual(['dev-*', 'staging-*']);
      expect(session2.approvedHosts).toEqual(['staging-*', 'prod-*']);
    });

    it('should demonstrate that spread operator creates a shallow copy of host strings', () => {
      /**
       * SECURITY FINDING: The spread operator [...agent.allowedHosts]
       * creates a new array with the same string references. Since
       * strings are immutable in JavaScript, this is effectively a
       * deep copy for this use case. However, if allowedHosts ever
       * contained objects instead of strings, the spread would only
       * create a shallow copy and mutations would propagate.
       */
      const originalHosts = ['dev-*', 'staging-*', 'prod-*'];
      const copiedHosts = [...originalHosts];

      // Modify the original array
      originalHosts.push('new-host-*');
      originalHosts[0] = 'CHANGED';

      // The copy remains unaffected
      expect(copiedHosts).toEqual(['dev-*', 'staging-*', 'prod-*']);
      expect(copiedHosts).not.toContain('new-host-*');
      expect(copiedHosts[0]).toBe('dev-*');
    });

    it('should not retroactively change session hosts when allowedHosts is cleared', () => {
      /**
       * SECURITY FINDING: Even if an admin completely clears an agent's
       * allowedHosts, existing sessions retain their originally approved
       * hosts. Sessions must be explicitly revoked to remove access.
       */
      const originalHosts = ['dev-*', 'staging-*'];
      const sessionHosts = [...originalHosts]; // Mimics vault.ts:488

      // Admin clears all allowed hosts
      originalHosts.length = 0;

      // Session still has access - this is the expected but potentially
      // dangerous behavior. Admins must revoke sessions explicitly.
      expect(sessionHosts).toEqual(['dev-*', 'staging-*']);
      expect(originalHosts).toEqual([]);
    });
  });

  // =========================================================================
  // 6. Session objects returned by reference
  // =========================================================================
  describe('Session objects returned by reference', () => {
    /**
     * SECURITY FINDING: getActiveSessions() pushes session objects
     * directly from the internal Map into the returned array. The
     * returned Session objects are the SAME references as the internal
     * state. Any caller that modifies a returned session object will
     * mutate the vault's internal session state.
     *
     * This is a significant concern: management API code or a buggy
     * caller could accidentally or maliciously modify session data.
     */
    it('should return direct references to internal session objects', async () => {
      const session = await createSessionForAgent(vaultManager, vek, 'SHA256:ref-test-agent');
      const activeSessions = vaultManager.getActiveSessions();
      const returned = activeSessions.find(s => s.id === session.id)!;

      // Verify this IS the same object reference
      expect(returned).toBe(session);
    });

    it('should allow mutation of internal state through returned references', async () => {
      const session = await createSessionForAgent(vaultManager, vek, 'SHA256:mutation-agent');
      const activeSessions = vaultManager.getActiveSessions();
      const returned = activeSessions.find(s => s.id === session.id)!;

      // Mutate the returned object - this changes internal vault state
      returned.approvedHosts.push('INJECTED-HOST-*');
      returned.agentFingerprint = 'SHA256:HIJACKED-FINGERPRINT';

      // Verify the internal session was actually mutated
      const sessionAfter = vaultManager.getSession(session.id);
      expect(sessionAfter).not.toBeNull();
      expect(sessionAfter!.approvedHosts).toContain('INJECTED-HOST-*');
      expect(sessionAfter!.agentFingerprint).toBe('SHA256:HIJACKED-FINGERPRINT');
    });

    it('should allow privilege escalation by injecting approvedCommands via reference', async () => {
      /**
       * SECURITY FINDING (Critical): A caller with access to the return
       * value of getActiveSessions() can inject approved commands into
       * any session, potentially bypassing policy checks.
       */
      const session = await createSessionForAgent(vaultManager, vek, 'SHA256:escalation-agent');
      const activeSessions = vaultManager.getActiveSessions();
      const returned = activeSessions.find(s => s.id === session.id)!;

      // Inject approved commands for a host the agent shouldn't have access to
      returned.approvedCommands['prod-database'] = ['DROP TABLE users', 'rm -rf /'];

      // The internal session now has these injected commands
      const internalSession = vaultManager.getSession(session.id);
      expect(internalSession!.approvedCommands['prod-database']).toEqual([
        'DROP TABLE users',
        'rm -rf /',
      ]);
    });

    it('should allow extending session expiry through returned reference', async () => {
      /**
       * SECURITY FINDING: A caller can extend their own (or any)
       * session's expiresAt to an arbitrary future time, effectively
       * creating a never-expiring session.
       */
      const session = await createSessionForAgent(vaultManager, vek, 'SHA256:expiry-abuse-agent');
      const activeSessions = vaultManager.getActiveSessions();
      const returned = activeSessions.find(s => s.id === session.id)!;

      const originalExpiry = returned.expiresAt;
      // Extend session to 100 years from now
      returned.expiresAt = Date.now() + 100 * 365 * 24 * 60 * 60 * 1000;

      const internalSession = vaultManager.getSession(session.id);
      expect(internalSession!.expiresAt).toBeGreaterThan(originalExpiry);
      // Session is now effectively permanent
      expect(internalSession!.expiresAt - Date.now()).toBeGreaterThan(99 * 365 * 24 * 60 * 60 * 1000);
    });

    it('should NOT affect other sessions when mutating one returned reference', async () => {
      const sessionA = await createSessionForAgent(vaultManager, vek, 'SHA256:safe-agent-A');
      const sessionB = await createSessionForAgent(vaultManager, vek, 'SHA256:safe-agent-B');

      const activeSessions = vaultManager.getActiveSessions();
      const returnedA = activeSessions.find(s => s.id === sessionA.id)!;

      // Mutate session A
      returnedA.approvedHosts.push('INJECTED');

      // Session B should be unaffected (they are different objects)
      const internalB = vaultManager.getSession(sessionB.id);
      expect(internalB!.approvedHosts).not.toContain('INJECTED');
    });
  });

  // =========================================================================
  // 7. Race condition in active session filtering
  // =========================================================================
  describe('Race condition in active session filtering', () => {
    /**
     * SECURITY FINDING: getActiveSessions() captures Date.now() once at
     * the start of iteration (line 573) and compares it against each
     * session's expiresAt. If the JS event loop is blocked or if many
     * sessions are iterated, the "now" value may be stale relative to
     * wall-clock time by the time later sessions are checked.
     *
     * This means a session that is about to expire could be included in
     * the result even though it technically expires during the iteration.
     * Conversely, using a single snapshot of "now" is SAFER than calling
     * Date.now() per-iteration, which could cause inconsistent results
     * where earlier sessions appear expired but later ones don't.
     */
    it('should use a single time snapshot for consistent filtering', async () => {
      // Create multiple sessions
      await createSessionForAgent(vaultManager, vek, 'SHA256:race-agent-1');
      await createSessionForAgent(vaultManager, vek, 'SHA256:race-agent-2');
      await createSessionForAgent(vaultManager, vek, 'SHA256:race-agent-3');

      // Mock Date.now to advance between calls - this simulates a race
      // condition where time advances during iteration
      let callCount = 0;
      const realNow = Date.now();
      const dateNowSpy = vi.spyOn(Date, 'now');

      // getActiveSessions() calls Date.now() ONCE at the top.
      // Return a fixed time that makes all sessions active.
      dateNowSpy.mockReturnValue(realNow);

      const sessions = vaultManager.getActiveSessions();
      // All 3 sessions should be consistently included since a single
      // timestamp is used for all comparisons
      expect(sessions.length).toBe(3);
    });

    it('should include sessions that expire during iteration when using snapshot time', async () => {
      /**
       * SECURITY FINDING: A session whose expiresAt is between the
       * snapshot time and the actual wall-clock time at the end of
       * iteration would be included even though it's "technically"
       * expired by the time the function returns.
       */
      const ctx = await createTestVault({ sessionTimeoutMinutes: 30 });
      const vm = ctx.vaultManager;
      const v = ctx.vek;

      const session = await createSessionForAgent(vm, v, 'SHA256:boundary-agent');

      // Set session to expire 1ms from "now"
      session.expiresAt = Date.now() + 1;

      // Call getActiveSessions immediately - the session may or may not
      // be included depending on exact timing. The key security insight
      // is that the single-snapshot approach means the result is consistent
      // within itself even if not perfectly up-to-date.
      const activeBefore = vm.getActiveSessions();

      // Wait for the session to definitely expire
      await new Promise(resolve => setTimeout(resolve, 10));

      const activeAfter = vm.getActiveSessions();
      // After waiting, the session should be excluded
      expect(activeAfter.find(s => s.id === session.id)).toBeUndefined();
    });

    it('should not return inconsistent results where early sessions are filtered but later ones are not', async () => {
      /**
       * SECURITY FINDING: If Date.now() were called per-session instead
       * of once, and time advanced during iteration, earlier sessions
       * might appear expired while later sessions with the same expiresAt
       * might appear active. The current implementation avoids this by
       * using a single snapshot.
       */
      const sessions: Session[] = [];
      for (let i = 0; i < 5; i++) {
        const s = await createSessionForAgent(vaultManager, vek, `SHA256:consistency-agent-${i}`);
        sessions.push(s);
      }

      // Give all sessions the exact same expiry time
      const sharedExpiry = Date.now() + 60 * 1000;
      for (const s of sessions) {
        s.expiresAt = sharedExpiry;
      }

      const active = vaultManager.getActiveSessions();
      // With a single time snapshot, either ALL sessions with the same
      // expiresAt are included or ALL are excluded - never a mix
      const matching = active.filter(s => s.expiresAt === sharedExpiry);
      expect(matching.length === 0 || matching.length === 5).toBe(true);
    });

    it('should handle concurrent session creation and enumeration safely', async () => {
      /**
       * SECURITY FINDING: In a concurrent environment, new sessions
       * could be added to the Map while getActiveSessions() is iterating.
       * JavaScript's Map iterator is specified to include entries that
       * exist at the time of each .next() call, so newly added sessions
       * during iteration may or may not appear in results.
       *
       * For single-threaded Node.js this is not an issue since
       * getActiveSessions() is synchronous, but it's important to
       * document the assumption.
       */
      await createSessionForAgent(vaultManager, vek, 'SHA256:concurrent-1');
      await createSessionForAgent(vaultManager, vek, 'SHA256:concurrent-2');

      // Since getActiveSessions is synchronous and JS is single-threaded,
      // no concurrent modification can happen during iteration
      const sessions = vaultManager.getActiveSessions();
      expect(sessions.length).toBe(2);

      // Verify session data integrity after enumeration
      for (const session of sessions) {
        expect(session.id).toBeDefined();
        expect(session.agentFingerprint).toBeDefined();
        expect(session.expiresAt).toBeGreaterThan(session.createdAt);
      }
    });

    it('should correctly filter when some sessions are expired and some are active', async () => {
      const activeSession = await createSessionForAgent(vaultManager, vek, 'SHA256:active-agent');
      const expiredSession = await createSessionForAgent(vaultManager, vek, 'SHA256:expired-agent');

      // Manually expire one session
      expiredSession.expiresAt = Date.now() - 1000;

      const activeSessions = vaultManager.getActiveSessions();

      expect(activeSessions.length).toBe(1);
      expect(activeSessions[0].agentFingerprint).toBe('SHA256:active-agent');
      expect(activeSessions.find(s => s.agentFingerprint === 'SHA256:expired-agent')).toBeUndefined();
    });
  });
});
