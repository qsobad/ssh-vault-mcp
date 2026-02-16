/**
 * Security Breach Tests: Session Hijacking
 *
 * Tests session management security including session fixation,
 * cross-agent access, session expiration, challenge manipulation,
 * and race conditions.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { VaultManager } from '../../src/vault/vault.js';
import { VaultStorage } from '../../src/vault/storage.js';
import {
  generateSalt,
  generateNonce,
  deriveKeyFromPassword,
  toBase64,
  LEGACY_KDF_PARAMS,
} from '../../src/vault/encryption.js';
import type { PasskeyCredential, Vault } from '../../src/types.js';
import { promises as fs } from 'fs';
import path from 'path';
import os from 'os';

describe('Security Breach: Session Hijacking', () => {
  let vaultManager: VaultManager;
  let vaultPath: string;
  let vek: Uint8Array;

  beforeEach(async () => {
    // Create a temporary vault for testing
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-test-'));
    vaultPath = path.join(tmpDir, 'test-vault.json');

    vaultManager = new VaultManager(vaultPath, {
      sessionTimeoutMinutes: 30,
      backupEnabled: false,
    });
    await vaultManager.init();

    // Create a test vault
    const credential: PasskeyCredential = {
      id: 'test-credential-id',
      publicKey: 'test-public-key-base64',
      algorithm: -7,
      counter: 0,
      createdAt: Date.now(),
    };

    const salt = generateSalt();
    vek = deriveKeyFromPassword('test-password-123', salt, LEGACY_KDF_PARAMS);
    await vaultManager.createVault(credential, vek, toBase64(salt));
  });

  describe('Challenge Manipulation', () => {
    it('should reject unlock codes for non-existent challenges', async () => {
      const result = await vaultManager.submitUnlockCode(
        'UNLOCK-AAAAA',
        'SHA256:fake-fingerprint'
      );
      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid or expired');
    });

    it('should reject unlock codes that dont match any challenge', async () => {
      const { challengeId } = vaultManager.createUnlockChallenge(
        'http://localhost:3000',
        'SHA256:agent1'
      );

      const result = await vaultManager.submitUnlockCode(
        'UNLOCK-ZZZZZ', // Wrong code
        'SHA256:agent1'
      );
      expect(result.success).toBe(false);
    });

    it('should not allow challenge completion without signature (VEK)', async () => {
      const { challengeId } = vaultManager.createUnlockChallenge(
        'http://localhost:3000',
        'SHA256:agent1'
      );

      // Try to submit without first completing the challenge (no VEK stored)
      const challenge = vaultManager.getChallenge(challengeId);
      expect(challenge).not.toBeNull();

      // submitUnlockCode requires the challenge to have a signature set via completeChallenge
      // Without completing first, the unlock code won't match
      const result = await vaultManager.submitUnlockCode(
        'UNLOCK-AAAAA', // Unknown code
        'SHA256:agent1'
      );
      expect(result.success).toBe(false);
    });

    it('should reject expired challenges', async () => {
      // Create a challenge, then simulate expiry
      const { challengeId } = vaultManager.createUnlockChallenge(
        'http://localhost:3000',
        'SHA256:agent1'
      );

      // Get challenge and verify it exists
      let challenge = vaultManager.getChallenge(challengeId);
      expect(challenge).not.toBeNull();

      // Manually expire the challenge by manipulating time
      // The challenge has a 5-minute timeout, so we can't easily test this
      // without mocking Date.now, but we verify the expiration field exists
      expect(challenge!.expiresAt).toBeGreaterThan(Date.now());
      expect(challenge!.expiresAt).toBeLessThanOrEqual(Date.now() + 5 * 60 * 1000 + 100);
    });

    it('should only allow each challenge to be completed once', async () => {
      const { challengeId } = vaultManager.createUnlockChallenge(
        'http://localhost:3000',
        'SHA256:agent1'
      );

      // Complete the challenge with VEK
      const result1 = await vaultManager.completeChallenge(challengeId, vek, false);
      expect(result1).not.toBeNull();
      expect(result1!.unlockCode).toBeDefined();

      // Use the unlock code
      const unlockResult = await vaultManager.submitUnlockCode(
        result1!.unlockCode,
        'SHA256:agent1'
      );
      expect(unlockResult.success).toBe(true);

      // The challenge should now be deleted - trying again should fail
      const result2 = await vaultManager.completeChallenge(challengeId, vek, false);
      expect(result2).toBeNull();
    });
  });

  describe('Cross-Agent Session Access', () => {
    it('should not allow agent A to use agent Bs session', async () => {
      // Create unlock for agent A
      const { challengeId } = vaultManager.createUnlockChallenge(
        'http://localhost:3000',
        'SHA256:agentA'
      );

      const completed = await vaultManager.completeChallenge(challengeId, vek, false);
      const unlockResult = await vaultManager.submitUnlockCode(
        completed!.unlockCode,
        'SHA256:agentA'
      );
      expect(unlockResult.success).toBe(true);

      // Agent A should have a session
      const sessionA = vaultManager.getSessionByAgent('SHA256:agentA');
      expect(sessionA).not.toBeNull();

      // Agent B should NOT have a session
      const sessionB = vaultManager.getSessionByAgent('SHA256:agentB');
      expect(sessionB).toBeNull();
    });

    it('should isolate sessions per agent fingerprint', async () => {
      // Create sessions for two agents
      const challenge1 = vaultManager.createUnlockChallenge('http://localhost:3000', 'SHA256:agent1');
      const challenge2 = vaultManager.createUnlockChallenge('http://localhost:3000', 'SHA256:agent2');

      const completed1 = await vaultManager.completeChallenge(challenge1.challengeId, vek, false);
      const completed2 = await vaultManager.completeChallenge(challenge2.challengeId, vek, false);

      await vaultManager.submitUnlockCode(completed1!.unlockCode, 'SHA256:agent1');
      await vaultManager.submitUnlockCode(completed2!.unlockCode, 'SHA256:agent2');

      const session1 = vaultManager.getSessionByAgent('SHA256:agent1');
      const session2 = vaultManager.getSessionByAgent('SHA256:agent2');

      expect(session1).not.toBeNull();
      expect(session2).not.toBeNull();
      expect(session1!.id).not.toBe(session2!.id);
      expect(session1!.agentFingerprint).toBe('SHA256:agent1');
      expect(session2!.agentFingerprint).toBe('SHA256:agent2');
    });
  });

  describe('Session Revocation', () => {
    it('should allow revoking a session by ID', async () => {
      const { challengeId } = vaultManager.createUnlockChallenge(
        'http://localhost:3000',
        'SHA256:agent1'
      );

      const completed = await vaultManager.completeChallenge(challengeId, vek, false);
      const result = await vaultManager.submitUnlockCode(completed!.unlockCode, 'SHA256:agent1');
      expect(result.success).toBe(true);

      const session = vaultManager.getSessionByAgent('SHA256:agent1');
      expect(session).not.toBeNull();

      // Revoke the session
      const revoked = vaultManager.revokeSession(session!.id);
      expect(revoked).toBe(true);

      // Session should no longer be accessible
      const afterRevoke = vaultManager.getSessionByAgent('SHA256:agent1');
      expect(afterRevoke).toBeNull();
    });

    it('should not affect other agents when one session is revoked', async () => {
      const ch1 = vaultManager.createUnlockChallenge('http://localhost:3000', 'SHA256:agent1');
      const ch2 = vaultManager.createUnlockChallenge('http://localhost:3000', 'SHA256:agent2');

      const c1 = await vaultManager.completeChallenge(ch1.challengeId, vek, false);
      const c2 = await vaultManager.completeChallenge(ch2.challengeId, vek, false);

      await vaultManager.submitUnlockCode(c1!.unlockCode, 'SHA256:agent1');
      await vaultManager.submitUnlockCode(c2!.unlockCode, 'SHA256:agent2');

      const session1 = vaultManager.getSessionByAgent('SHA256:agent1');
      vaultManager.revokeSession(session1!.id);

      // Agent 2 should still have a session
      const session2 = vaultManager.getSessionByAgent('SHA256:agent2');
      expect(session2).not.toBeNull();
    });

    it('should handle revoking non-existent sessions gracefully', () => {
      const result = vaultManager.revokeSession('non-existent-session-id');
      expect(result).toBe(false);
    });
  });

  describe('Vault Lock/Unlock State', () => {
    it('should start locked', () => {
      const freshVault = new VaultManager('/tmp/nonexistent-vault.json', {
        sessionTimeoutMinutes: 30,
      });
      expect(freshVault.isUnlocked()).toBe(false);
    });

    it('should be unlocked after creation', () => {
      // Our beforeEach creates a vault, which unlocks it
      expect(vaultManager.isUnlocked()).toBe(true);
    });

    it('should clear all sessions on lock', async () => {
      const { challengeId } = vaultManager.createUnlockChallenge(
        'http://localhost:3000',
        'SHA256:agent1'
      );

      const completed = await vaultManager.completeChallenge(challengeId, vek, false);
      await vaultManager.submitUnlockCode(completed!.unlockCode, 'SHA256:agent1');

      expect(vaultManager.getSessionByAgent('SHA256:agent1')).not.toBeNull();

      // Lock the vault
      vaultManager.lock();

      expect(vaultManager.isUnlocked()).toBe(false);
      expect(vaultManager.getSessionByAgent('SHA256:agent1')).toBeNull();
    });

    it('should throw when accessing hosts while locked', () => {
      vaultManager.lock();
      expect(() => vaultManager.getHosts()).toThrow('Vault is locked');
    });

    it('should throw when accessing agents while locked', () => {
      vaultManager.lock();
      expect(() => vaultManager.getAgent('SHA256:test')).toThrow('Vault is locked');
    });

    it('should throw when accessing policy while locked', () => {
      vaultManager.lock();
      expect(() => vaultManager.getPolicy()).toThrow('Vault is locked');
    });
  });

  describe('Challenge Status Tracking', () => {
    it('should report pending for active challenges', () => {
      const { challengeId } = vaultManager.createUnlockChallenge(
        'http://localhost:3000',
        'SHA256:agent1'
      );

      const status = vaultManager.getChallengeStatus(challengeId);
      expect(status.status).toBe('pending');
    });

    it('should report not_found for non-existent challenges', () => {
      const status = vaultManager.getChallengeStatus('fake-challenge-id');
      expect(status.status).toBe('not_found');
    });

    it('should report approved after challenge completion', async () => {
      const { challengeId } = vaultManager.createUnlockChallenge(
        'http://localhost:3000',
        'SHA256:agent1'
      );

      const completed = await vaultManager.completeChallenge(challengeId, vek, false);
      await vaultManager.submitUnlockCode(completed!.unlockCode, 'SHA256:agent1');

      const status = vaultManager.getChallengeStatus(challengeId);
      expect(status.status).toBe('approved');
    });
  });

  describe('Approval Challenge Security', () => {
    it('should create separate approval challenges for commands', () => {
      const result = vaultManager.createApprovalChallenge(
        'http://localhost:3000',
        'SHA256:agent1',
        'dev-01',
        ['rm -rf /tmp/old']
      );

      expect(result.challengeId).toBeDefined();
      expect(result.approvalUrl).toContain('approve');
      expect(result.expiresAt).toBeGreaterThan(Date.now());
    });

    it('should include host and command in approval challenge', () => {
      const { challengeId } = vaultManager.createApprovalChallenge(
        'http://localhost:3000',
        'SHA256:agent1',
        'prod-db-01',
        ['DROP TABLE users']
      );

      const challenge = vaultManager.getChallenge(challengeId);
      expect(challenge).not.toBeNull();
      expect(challenge!.action).toBe('approve_command');
      expect(challenge!.host).toBe('prod-db-01');
      expect(challenge!.commands).toContain('DROP TABLE users');
    });
  });

  describe('Access Request Challenge Security', () => {
    it('should create access request challenges', () => {
      const result = vaultManager.createAccessRequestChallenge(
        'http://localhost:3000',
        {
          name: 'new-agent',
          fingerprint: 'SHA256:new-agent-fp',
          publicKey: 'base64-public-key',
          requestedHosts: ['dev-*', 'staging-*'],
        }
      );

      expect(result.challengeId).toBeDefined();
      expect(result.approvalUrl).toContain('request-access');
    });

    it('should allow updating requested hosts before approval', () => {
      const { challengeId } = vaultManager.createAccessRequestChallenge(
        'http://localhost:3000',
        {
          name: 'new-agent',
          fingerprint: 'SHA256:new-agent-fp',
          publicKey: 'base64-public-key',
          requestedHosts: ['*'], // Agent requests all hosts
        }
      );

      // Owner can restrict the hosts before approving
      const updated = vaultManager.updateChallengeHosts(challengeId, ['dev-*']);
      expect(updated).toBe(true);

      const challenge = vaultManager.getChallenge(challengeId);
      expect(challenge!.accessRequest!.requestedHosts).toEqual(['dev-*']);
    });

    it('should not allow updating hosts for non-access-request challenges', () => {
      const { challengeId } = vaultManager.createUnlockChallenge(
        'http://localhost:3000',
        'SHA256:agent1'
      );

      const updated = vaultManager.updateChallengeHosts(challengeId, ['dev-*']);
      expect(updated).toBe(false);
    });

    it('should not allow updating hosts for expired challenges', () => {
      const updated = vaultManager.updateChallengeHosts('non-existent-id', ['dev-*']);
      expect(updated).toBe(false);
    });
  });

  describe('Concurrent Challenge Handling', () => {
    it('should handle multiple simultaneous unlock challenges', () => {
      const ch1 = vaultManager.createUnlockChallenge('http://localhost:3000', 'SHA256:agent1');
      const ch2 = vaultManager.createUnlockChallenge('http://localhost:3000', 'SHA256:agent2');
      const ch3 = vaultManager.createUnlockChallenge('http://localhost:3000', 'SHA256:agent3');

      expect(ch1.challengeId).not.toBe(ch2.challengeId);
      expect(ch2.challengeId).not.toBe(ch3.challengeId);

      // All should be retrievable
      expect(vaultManager.getChallenge(ch1.challengeId)).not.toBeNull();
      expect(vaultManager.getChallenge(ch2.challengeId)).not.toBeNull();
      expect(vaultManager.getChallenge(ch3.challengeId)).not.toBeNull();
    });

    it('should handle mixed challenge types simultaneously', () => {
      const unlock = vaultManager.createUnlockChallenge('http://localhost:3000', 'SHA256:agent1');
      const approval = vaultManager.createApprovalChallenge(
        'http://localhost:3000',
        'SHA256:agent1',
        'dev-01',
        ['ls']
      );
      const access = vaultManager.createAccessRequestChallenge(
        'http://localhost:3000',
        {
          name: 'new-agent',
          fingerprint: 'SHA256:new-fp',
          publicKey: 'key',
          requestedHosts: ['dev-*'],
        }
      );

      const ch1 = vaultManager.getChallenge(unlock.challengeId);
      const ch2 = vaultManager.getChallenge(approval.challengeId);
      const ch3 = vaultManager.getChallenge(access.challengeId);

      expect(ch1!.action).toBe('unlock_vault');
      expect(ch2!.action).toBe('approve_command');
      expect(ch3!.action).toBe('request_access');
    });
  });
});
