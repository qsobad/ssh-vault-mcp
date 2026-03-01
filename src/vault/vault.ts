/**
 * Vault main module
 * Manages vault state, sessions, and operations
 */

import { randomUUID } from 'crypto';
import type { Vault, AgentConfig, Session, UnlockChallenge, PasskeyCredential, GlobalPolicy, Secret } from '../types.js';
import { VaultStorage } from './storage.js';
import { generateRandomId, generateUnlockCode, secureWipe, initSodium } from './encryption.js';

interface PendingChallenge {
  challenge: UnlockChallenge;
  unlockCode: string;
  agentFingerprint: string;  // Store requesting agent
  signature?: Uint8Array;    // Stored after successful verification
}

// Event emitter for SSE notifications
type ChallengeEventListener = (event: {
  type: 'approved' | 'expired' | 'error';
  challengeId: string;
  sessionId?: string;
  error?: string;
  agentRegistered?: boolean;
}) => void;

export class VaultManager {
  private storage: VaultStorage;
  private vault: Vault | null = null;
  private sessions: Map<string, Session> = new Map();
  private pendingChallenges: Map<string, PendingChallenge> = new Map();
  private completedChallenges: Map<string, { status: string; sessionId?: string; error?: string; completedAt: number }> = new Map();
  private sessionTimeoutMs: number;
  private challengeTimeoutMs: number = 5 * 60 * 1000; // 5 minutes
  private currentSignature: Uint8Array | null = null;
  
  // Auto-lock timer
  private autoLockTimer: ReturnType<typeof setTimeout> | null = null;
  private autoLockMs: number;
  
  // SSE event listeners per challenge
  private challengeListeners: Map<string, Set<ChallengeEventListener>> = new Map();

  constructor(
    vaultPath: string,
    options: {
      sessionTimeoutMinutes?: number;
      backupEnabled?: boolean;
      autoLockMinutes?: number;
    } = {}
  ) {
    this.storage = new VaultStorage(vaultPath, options.backupEnabled ?? true);
    this.sessionTimeoutMs = (options.sessionTimeoutMinutes ?? 30) * 60 * 1000;
    this.autoLockMs = (options.autoLockMinutes ?? 15) * 60 * 1000;
  }

  /**
   * Initialize the vault manager
   */
  async init(): Promise<void> {
    await initSodium();
  }

  /**
   * Reset the auto-lock timer. Call on every vault operation.
   */
  resetAutoLockTimer(): void {
    if (this.autoLockTimer) {
      clearTimeout(this.autoLockTimer);
      this.autoLockTimer = null;
    }
    if (this.currentSignature) {
      this.autoLockTimer = setTimeout(() => {
        console.error('[vault] Auto-lock triggered after inactivity');
        this.lock();
      }, this.autoLockMs);
    }
  }

  /**
   * Strip plaintext credentials from in-memory vault, replacing with placeholder
   */
  private stripCredentials(vault: Vault): Vault {
    return {
      ...vault,
      secrets: (vault.secrets || []).map(s => ({ ...s, content: '[encrypted]' })),
    };
  }

  /**
   * Check if vault exists
   */
  async vaultExists(): Promise<boolean> {
    return this.storage.exists();
  }

  /**
   * Check if vault is currently unlocked
   */
  isUnlocked(): boolean {
    return this.vault !== null && this.currentSignature !== null;
  }

  /**
   * Reload vault from storage (refresh in-memory data, credentials stripped)
   */
  async reloadVault(): Promise<void> {
    if (this.currentSignature) {
      const fullVault = await this.storage.load(this.currentSignature);
      this.vault = this.stripCredentials(fullVault);
      this.resetAutoLockTimer();
    }
  }

  /**
   * Get public vault metadata (without unlocking).
   * Does NOT expose passwordSalt or kdfParams.
   */
  async getMetadata(): Promise<{
    credentialId: string;
    publicKey: string;
    algorithm: number;
    credentials: import('../types.js').VaultFileCredential[];
  } | null> {
    return this.storage.getMetadata();
  }

  /**
   * Get vault metadata including passwordSalt, kdfParams, and credentials.
   * Only call AFTER authenticating the caller (e.g., after WebAuthn verification).
   */
  async getAuthMetadata(): Promise<{
    credentialId: string;
    publicKey: string;
    algorithm: number;
    passwordSalt: string;
    kdfParams: { t: number; m: number; p: number; dkLen: number };
    credentials: import('../types.js').VaultFileCredential[];
  } | null> {
    return this.storage.getAuthMetadata();
  }

  /**
   * Create a new vault with Passkey registration
   * @param credential - Passkey credential
   * @param vek - Vault Encryption Key (derived from master password)
   * @param passwordSalt - Base64-encoded salt used for password key derivation
   * @param kdfParams - KDF parameters used to derive the VEK (stored for future decryption)
   */
  async createVault(
    credential: PasskeyCredential,
    vek: Uint8Array,
    passwordSalt?: string,
    kdfParams?: { t: number; m: number; p: number; dkLen: number }
  ): Promise<void> {
    const fullVault = await this.storage.create(credential, vek);
    if (passwordSalt) {
      await this.storage.saveWithPasswordSalt(fullVault, vek, passwordSalt, kdfParams);
    }
    this.vault = this.stripCredentials(fullVault);
    this.currentSignature = new Uint8Array(vek);
    this.resetAutoLockTimer();
  }

  /**
   * Create an unlock challenge
   * Returns the challenge and a URL for the signing page
   */
  createUnlockChallenge(baseUrl: string, agentFingerprint: string): {
    challengeId: string;
    unlockUrl: string;
    listenUrl: string;
    expiresAt: number;
  } {
    const challenge: UnlockChallenge = {
      id: generateRandomId(),
      action: 'unlock_vault',
      timestamp: Date.now(),
      nonce: generateRandomId(),
      expiresAt: Date.now() + this.challengeTimeoutMs,
    };

    const unlockCode = generateUnlockCode();
    
    this.pendingChallenges.set(challenge.id, {
      challenge,
      unlockCode,
      agentFingerprint,
    });

    // Clean up expired challenges
    this.cleanupExpiredChallenges();

    return {
      challengeId: challenge.id,
      unlockUrl: `${baseUrl}/sign?challenge=${challenge.id}`,
      listenUrl: `${baseUrl}/api/challenge/${challenge.id}/listen`,
      expiresAt: challenge.expiresAt,
    };
  }

  /**
   * Create an approval challenge for out-of-policy commands
   */
  createApprovalChallenge(
    baseUrl: string,
    agentFingerprint: string,
    host: string,
    commands: string[]
  ): {
    challengeId: string;
    approvalUrl: string;
    listenUrl: string;
    expiresAt: number;
  } {
    const challenge: UnlockChallenge = {
      id: generateRandomId(),
      action: 'approve_command',
      timestamp: Date.now(),
      nonce: generateRandomId(),
      expiresAt: Date.now() + this.challengeTimeoutMs,
      agent: agentFingerprint,
      host,
      commands,
    };

    const unlockCode = generateUnlockCode();
    
    this.pendingChallenges.set(challenge.id, {
      challenge,
      unlockCode,
      agentFingerprint,
    });

    return {
      challengeId: challenge.id,
      approvalUrl: `${baseUrl}/approve?challenge=${challenge.id}`,
      listenUrl: `${baseUrl}/api/challenge/${challenge.id}/listen`,
      expiresAt: challenge.expiresAt,
    };
  }

  /**
   * Create an access request challenge (agent requests host access)
   * Agent will be auto-enlisted if not already in vault
   */
  createAccessRequestChallenge(
    baseUrl: string,
    agentInfo: {
      name: string;
      fingerprint: string;
      publicKey: string;
      requestedHosts: string[];
    }
  ): {
    challengeId: string;
    approvalUrl: string;
    listenUrl: string;
    expiresAt: number;
  } {
    const challenge: UnlockChallenge = {
      id: generateRandomId(),
      action: 'request_access',
      timestamp: Date.now(),
      nonce: generateRandomId(),
      expiresAt: Date.now() + this.challengeTimeoutMs,
      accessRequest: agentInfo,
    };

    const unlockCode = generateUnlockCode();
    
    this.pendingChallenges.set(challenge.id, {
      challenge,
      unlockCode,
      agentFingerprint: agentInfo.fingerprint,
    });

    return {
      challengeId: challenge.id,
      approvalUrl: `${baseUrl}/request-access?challenge=${challenge.id}`,
      listenUrl: `${baseUrl}/api/challenge/${challenge.id}/listen`,
      expiresAt: challenge.expiresAt,
    };
  }

  /**
   * Get challenge details for the signing page
   */
  getChallenge(challengeId: string): UnlockChallenge | null {
    const pending = this.pendingChallenges.get(challengeId);
    if (!pending || pending.challenge.expiresAt < Date.now()) {
      return null;
    }
    return pending.challenge;
  }

  /**
   * Update allowed hosts in an access request challenge (user can edit before approving)
   */
  updateChallengeHosts(challengeId: string, allowedHosts: string[]): boolean {
    const pending = this.pendingChallenges.get(challengeId);
    if (!pending || pending.challenge.expiresAt < Date.now()) {
      return false;
    }
    if (pending.challenge.action === 'request_access' && pending.challenge.accessRequest) {
      pending.challenge.accessRequest.requestedHosts = allowedHosts;
      return true;
    }
    return false;
  }

  /**
   * Complete challenge after successful Passkey verification
   * Called by the signing page after WebAuthn verification
   * If autoUnlock is true and there are listeners, automatically unlock
   */
  async completeChallenge(
    challengeId: string,
    signature: Uint8Array,
    autoUnlock: boolean = true
  ): Promise<{ 
    unlockCode: string;
    autoUnlocked?: boolean;
    sessionId?: string;
  } | null> {
    const pending = this.pendingChallenges.get(challengeId);
    if (!pending || pending.challenge.expiresAt < Date.now()) {
      return null;
    }

    // Store signature (VEK)
    pending.signature = new Uint8Array(signature);
    
    // For access requests, always complete immediately (user just approved)
    // For other challenges, only auto-complete if there are listeners
    const shouldAutoComplete = 
      pending.challenge.action === 'request_access' ||
      (autoUnlock && this.hasListeners(challengeId));
    
    if (shouldAutoComplete) {
      const result = await this.submitUnlockCode(
        pending.unlockCode,
        pending.agentFingerprint
      );
      
      if (result.success) {
        return {
          unlockCode: pending.unlockCode,
          autoUnlocked: true,
          sessionId: result.sessionId,
        };
      }
    }
    
    return { unlockCode: pending.unlockCode };
  }

  /**
   * Verify unlock code and unlock vault / approve command
   */
  async submitUnlockCode(
    unlockCode: string,
    agentFingerprint: string
  ): Promise<{
    success: boolean;
    sessionId?: string;
    expiresAt?: number;
    error?: string;
  }> {
    // Find challenge by unlock code
    let foundChallenge: PendingChallenge | null = null;
    let foundId: string | null = null;
    
    for (const [id, pending] of this.pendingChallenges.entries()) {
      if (pending.unlockCode === unlockCode && pending.signature) {
        foundChallenge = pending;
        foundId = id;
        break;
      }
    }

    if (!foundChallenge || !foundId || !foundChallenge.signature) {
      return { success: false, error: 'Invalid or expired unlock code' };
    }

    if (foundChallenge.challenge.expiresAt < Date.now()) {
      this.pendingChallenges.delete(foundId);
      return { success: false, error: 'Unlock code expired' };
    }

    try {
      if (foundChallenge.challenge.action === 'unlock_vault') {
        // Unlock vault (strip credentials from memory)
        const fullVault = await this.storage.load(foundChallenge.signature);
        this.vault = this.stripCredentials(fullVault);
        this.currentSignature = new Uint8Array(foundChallenge.signature);
        this.resetAutoLockTimer();
        
        // Create session
        const session = this.createSession(agentFingerprint);
        
        // Emit event to listeners
        this.emitChallengeEvent(foundId, {
          type: 'approved',
          challengeId: foundId,
          sessionId: session.id,
        });
        
        // Save result for polling and cleanup
        this.saveChallengeResult(foundId, { status: 'approved', sessionId: session.id });
        this.pendingChallenges.delete(foundId);
        this.challengeListeners.delete(foundId);
        
        return {
          success: true,
          sessionId: session.id,
          expiresAt: session.expiresAt,
        };
      } else if (foundChallenge.challenge.action === 'approve_command') {
        // Add approved commands to session
        const session = this.getSessionByAgent(agentFingerprint);
        if (!session) {
          return { success: false, error: 'No active session' };
        }

        const host = foundChallenge.challenge.host!;
        const commands = foundChallenge.challenge.commands!;
        
        if (!session.approvedCommands[host]) {
          session.approvedCommands[host] = [];
        }
        session.approvedCommands[host].push(...commands);
        
        // Emit event to listeners
        this.emitChallengeEvent(foundId, {
          type: 'approved',
          challengeId: foundId,
          sessionId: session.id,
        });
        
        // Cleanup
        this.pendingChallenges.delete(foundId);
        this.challengeListeners.delete(foundId);
        
        return {
          success: true,
          sessionId: session.id,
          expiresAt: session.expiresAt,
        };
      } else if (foundChallenge.challenge.action === 'request_access') {
        // Agent requesting host access (auto-enlist if not exists)
        const req = foundChallenge.challenge.accessRequest!;
        
        // Load vault with signature to modify it
        if (!this.currentSignature) {
          this.currentSignature = new Uint8Array(foundChallenge.signature);
          this.resetAutoLockTimer();
        }
        // Load full vault for modification (will strip after save)
        const fullVaultForAccess = await this.storage.load(this.currentSignature);
        
        // Find or create agent
        let agent = fullVaultForAccess.agents.find(a => a.fingerprint === req.fingerprint);
        if (!agent) {
          // Auto-enlist new agent
          agent = {
            fingerprint: req.fingerprint,
            name: req.name,
            allowedHosts: [],
            createdAt: Date.now(),
            lastUsed: Date.now(),
          };
          fullVaultForAccess.agents.push(agent);
        }
        
        // Add requested hosts (merge with existing, avoid duplicates)
        for (const host of req.requestedHosts) {
          if (!agent.allowedHosts.includes(host)) {
            agent.allowedHosts.push(host);
          }
        }
        agent.lastUsed = Date.now();
        
        // Save vault and update in-memory (stripped)
        await this.storage.save(fullVaultForAccess, this.currentSignature!);
        this.vault = this.stripCredentials(fullVaultForAccess);
        
        // Create session for the agent with approved hosts
        const session = this.createSession(req.fingerprint);
        session.approvedHosts = [...agent.allowedHosts];
        
        // Emit event to listeners
        this.emitChallengeEvent(foundId, {
          type: 'approved',
          challengeId: foundId,
          sessionId: session.id,
        });
        
        // Save result for polling and cleanup
        this.saveChallengeResult(foundId, { status: 'approved', sessionId: session.id });
        this.pendingChallenges.delete(foundId);
        this.challengeListeners.delete(foundId);
        
        return {
          success: true,
          sessionId: session.id,
          expiresAt: session.expiresAt,
        };
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }

    return { success: false, error: 'Unknown action' };
  }

  /**
   * Create a new session
   */
  private createSession(agentFingerprint: string): Session {
    const session: Session = {
      id: randomUUID(),
      agentFingerprint,
      approvedHosts: [],
      approvedCommands: {},
      challengeId: '',
      createdAt: Date.now(),
      expiresAt: Date.now() + this.sessionTimeoutMs,
    };
    
    this.sessions.set(session.id, session);
    return session;
  }

  /**
   * Get session by agent fingerprint
   */
  getSessionByAgent(fingerprint: string): Session | null {
    for (const session of this.sessions.values()) {
      if (session.agentFingerprint === fingerprint && session.expiresAt > Date.now()) {
        return session;
      }
    }
    return null;
  }

  /**
   * Get session by ID
   */
  getSession(sessionId: string): Session | null {
    const session = this.sessions.get(sessionId);
    if (!session || session.expiresAt < Date.now()) {
      return null;
    }
    return session;
  }

  /**
   * Extend session expiration (call on successful operations)
   */
  touchSession(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session && session.expiresAt > Date.now()) {
      session.expiresAt = Date.now() + this.sessionTimeoutMs;
    }
  }

  /**
   * Get all active sessions
   */
  getActiveSessions(): Session[] {
    const now = Date.now();
    const active: Session[] = [];
    for (const session of this.sessions.values()) {
      if (session.expiresAt > now) {
        active.push(session);
      }
    }
    return active;
  }

  /**
   * Revoke a session
   */
  revokeSession(sessionId: string): boolean {
    return this.sessions.delete(sessionId);
  }

  /**
   * Lock vault (clear from memory)
   */
  lock(): void {
    if (this.autoLockTimer) {
      clearTimeout(this.autoLockTimer);
      this.autoLockTimer = null;
    }
    if (this.currentSignature) {
      secureWipe(this.currentSignature);
      this.currentSignature = null;
    }
    this.vault = null;
    this.sessions.clear();
  }

  /**
   * Get agent config
   */
  getAgent(fingerprint: string): AgentConfig | null {
    if (!this.vault) {
      throw new Error('Vault is locked');
    }
    return this.vault.agents.find(a => a.fingerprint === fingerprint) ?? null;
  }

  /**
   * Get global policy
   */
  getPolicy(): GlobalPolicy {
    if (!this.vault) {
      throw new Error('Vault is locked');
    }
    return this.vault.policy;
  }

  /**
   * Add an agent
   */
  async addAgent(agent: Omit<AgentConfig, 'createdAt' | 'lastUsed'>): Promise<AgentConfig> {
    if (!this.currentSignature) {
      throw new Error('Vault is locked');
    }
    this.resetAutoLockTimer();

    const fullVault = await this.storage.load(this.currentSignature);
    const newAgent: AgentConfig = {
      ...agent,
      createdAt: Date.now(),
      lastUsed: Date.now(),
    };

    fullVault.agents.push(newAgent);
    await this.storage.save(fullVault, this.currentSignature);
    this.vault = this.stripCredentials(fullVault);
    return newAgent;
  }

  /**
   * Remove an agent
   */
  async removeAgent(fingerprint: string): Promise<boolean> {
    if (!this.currentSignature) {
      throw new Error('Vault is locked');
    }
    this.resetAutoLockTimer();

    const fullVault = await this.storage.load(this.currentSignature);
    const index = fullVault.agents.findIndex(a => a.fingerprint === fingerprint);
    if (index === -1) {
      return false;
    }

    fullVault.agents.splice(index, 1);
    await this.storage.save(fullVault, this.currentSignature);
    this.vault = this.stripCredentials(fullVault);
    return true;
  }

  // ─── Secret CRUD ───────────────────────────────────────────

  /**
   * Get all secrets (metadata only, content stripped)
   */
  getSecrets(): Secret[] {
    if (!this.vault) throw new Error('Vault is locked');
    return this.vault.secrets || [];
  }

  /**
   * Get secret metadata by name or ID (content stripped)
   */
  getSecret(nameOrId: string): Secret | null {
    if (!this.vault) throw new Error('Vault is locked');
    return (this.vault.secrets || []).find(s => s.id === nameOrId || s.name === nameOrId) ?? null;
  }

  /**
   * Decrypt a single secret's content on-demand
   */
  async decryptSecretContent(secretNameOrId: string): Promise<string> {
    if (!this.currentSignature) throw new Error('Vault is locked');
    this.resetAutoLockTimer();
    const content = await this.storage.decryptSecretContent(secretNameOrId, this.currentSignature);
    if (content === null) throw new Error(`Secret '${secretNameOrId}' not found`);
    return content;
  }

  /**
   * List secrets (name + description only, no content)
   */
  listSecrets(): { id: string; name: string; description: string; createdAt: number; updatedAt: number }[] {
    if (!this.vault) throw new Error('Vault is locked');
    return (this.vault.secrets || []).map(s => ({
      id: s.id,
      name: s.name,
      description: s.description,
      createdAt: s.createdAt,
      updatedAt: s.updatedAt,
    }));
  }

  /**
   * Add a secret
   */
  async addSecret(secret: Omit<Secret, 'id' | 'createdAt' | 'updatedAt'>): Promise<Secret> {
    if (!this.currentSignature) throw new Error('Vault is locked');
    this.resetAutoLockTimer();
    const fullVault = await this.storage.load(this.currentSignature);
    if (!fullVault.secrets) fullVault.secrets = [];
    const newSecret: Secret = {
      ...secret,
      id: randomUUID(),
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    fullVault.secrets.push(newSecret);
    await this.storage.save(fullVault, this.currentSignature);
    this.vault = this.stripCredentials(fullVault);
    return { ...newSecret, content: '[encrypted]' };
  }

  /**
   * Update a secret
   */
  async updateSecret(id: string, updates: Partial<Pick<Secret, 'name' | 'description' | 'content'>>): Promise<Secret | null> {
    if (!this.currentSignature) throw new Error('Vault is locked');
    this.resetAutoLockTimer();
    const fullVault = await this.storage.load(this.currentSignature);
    if (!fullVault.secrets) fullVault.secrets = [];
    const secret = fullVault.secrets.find(s => s.id === id);
    if (!secret) return null;
    if (updates.name !== undefined) secret.name = updates.name;
    if (updates.description !== undefined) secret.description = updates.description;
    if (updates.content !== undefined) secret.content = updates.content;
    secret.updatedAt = Date.now();
    await this.storage.save(fullVault, this.currentSignature);
    this.vault = this.stripCredentials(fullVault);
    return { ...secret, content: '[encrypted]' };
  }

  /**
   * Delete a secret
   */
  async deleteSecret(id: string): Promise<boolean> {
    if (!this.currentSignature) throw new Error('Vault is locked');
    this.resetAutoLockTimer();
    const fullVault = await this.storage.load(this.currentSignature);
    if (!fullVault.secrets) fullVault.secrets = [];
    const index = fullVault.secrets.findIndex(s => s.id === id);
    if (index === -1) return false;
    fullVault.secrets.splice(index, 1);
    await this.storage.save(fullVault, this.currentSignature);
    this.vault = this.stripCredentials(fullVault);
    return true;
  }

  /**
   * Parse SSH connection info from a secret's markdown content
   */
  static parseSSHFromSecret(content: string): {
    host: string;
    port: number;
    user: string;
    password?: string;
    key?: string;
  } | null {
    const getField = (name: string): string | undefined => {
      const match = content.match(new RegExp(`^\\s*-\\s*${name}:\\s*(.+)`, 'mi'));
      return match?.[1]?.trim();
    };
    const host = getField('host');
    const user = getField('user');
    if (!host || !user) return null;
    return {
      host,
      port: parseInt(getField('port') || '22', 10),
      user,
      password: getField('password'),
      key: getField('key'),
    };
  }

  /**
   * Clean up expired challenges
   */
  private cleanupExpiredChallenges(): void {
    const now = Date.now();
    for (const [id, pending] of this.pendingChallenges.entries()) {
      if (pending.challenge.expiresAt < now) {
        if (pending.signature) {
          secureWipe(pending.signature);
        }
        this.pendingChallenges.delete(id);
      }
    }
  }

  /**
   * Clean up expired sessions
   */
  cleanupExpiredSessions(): void {
    const now = Date.now();
    for (const [id, session] of this.sessions.entries()) {
      if (session.expiresAt < now) {
        this.sessions.delete(id);
      }
    }
  }

  /**
   * Subscribe to challenge events (for SSE)
   */
  subscribeToChallenge(challengeId: string, listener: ChallengeEventListener): () => void {
    if (!this.challengeListeners.has(challengeId)) {
      this.challengeListeners.set(challengeId, new Set());
    }
    this.challengeListeners.get(challengeId)!.add(listener);

    // Return unsubscribe function
    return () => {
      const listeners = this.challengeListeners.get(challengeId);
      if (listeners) {
        listeners.delete(listener);
        if (listeners.size === 0) {
          this.challengeListeners.delete(challengeId);
        }
      }
    };
  }

  /**
   * Emit event to challenge listeners
   */
  private emitChallengeEvent(
    challengeId: string,
    event: Parameters<ChallengeEventListener>[0]
  ): void {
    const listeners = this.challengeListeners.get(challengeId);
    if (listeners) {
      for (const listener of listeners) {
        try {
          listener(event);
        } catch (e) {
          // Ignore listener errors
        }
      }
    }
  }

  /**
   * Check if a challenge has active listeners
   */
  hasListeners(challengeId: string): boolean {
    const listeners = this.challengeListeners.get(challengeId);
    return listeners !== undefined && listeners.size > 0;
  }

  /**
   * Save completed challenge result for polling
   */
  saveChallengeResult(challengeId: string, result: { status: string; sessionId?: string; error?: string }): void {
    this.completedChallenges.set(challengeId, {
      ...result,
      completedAt: Date.now(),
    });
    // Auto-cleanup after 10 minutes
    setTimeout(() => this.completedChallenges.delete(challengeId), 10 * 60 * 1000);
  }

  /**
   * Get challenge status (pending, approved, denied, expired)
   */
  getChallengeStatus(challengeId: string): { status: string; sessionId?: string; error?: string } {
    // Check completed first
    const completed = this.completedChallenges.get(challengeId);
    if (completed) {
      return { status: completed.status, sessionId: completed.sessionId, error: completed.error };
    }
    // Check pending
    const pending = this.pendingChallenges.get(challengeId);
    if (pending) {
      if (pending.challenge.expiresAt < Date.now()) {
        return { status: 'expired' };
      }
      return { status: 'pending' };
    }
    return { status: 'not_found' };
  }
}
