/**
 * Vault main module
 * Manages vault state, sessions, and operations
 */

import { randomUUID } from 'crypto';
import type { Vault, Host, AgentConfig, Session, UnlockChallenge, PasskeyCredential } from '../types.js';
import { VaultStorage } from './storage.js';
import { generateRandomId, generateUnlockCode, secureWipe, initSodium } from './encryption.js';

interface PendingChallenge {
  challenge: UnlockChallenge;
  unlockCode: string;
  signature?: Uint8Array;  // Stored after successful verification
}

export class VaultManager {
  private storage: VaultStorage;
  private vault: Vault | null = null;
  private sessions: Map<string, Session> = new Map();
  private pendingChallenges: Map<string, PendingChallenge> = new Map();
  private sessionTimeoutMs: number;
  private challengeTimeoutMs: number = 5 * 60 * 1000; // 5 minutes
  private currentSignature: Uint8Array | null = null;

  constructor(
    vaultPath: string,
    options: {
      sessionTimeoutMinutes?: number;
      backupEnabled?: boolean;
    } = {}
  ) {
    this.storage = new VaultStorage(vaultPath, options.backupEnabled ?? true);
    this.sessionTimeoutMs = (options.sessionTimeoutMinutes ?? 30) * 60 * 1000;
  }

  /**
   * Initialize the vault manager
   */
  async init(): Promise<void> {
    await initSodium();
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
    return this.vault !== null;
  }

  /**
   * Get vault metadata (without unlocking)
   */
  async getMetadata(): Promise<{
    credentialId: string;
    publicKey: string;
    algorithm: number;
  } | null> {
    return this.storage.getMetadata();
  }

  /**
   * Create a new vault with Passkey registration
   */
  async createVault(
    credential: PasskeyCredential,
    signature: Uint8Array
  ): Promise<void> {
    this.vault = await this.storage.create(credential, signature);
    this.currentSignature = new Uint8Array(signature);
  }

  /**
   * Create an unlock challenge
   * Returns the challenge and a URL for the signing page
   */
  createUnlockChallenge(baseUrl: string): {
    challengeId: string;
    unlockUrl: string;
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
    });

    // Clean up expired challenges
    this.cleanupExpiredChallenges();

    return {
      challengeId: challenge.id,
      unlockUrl: `${baseUrl}/sign?challenge=${challenge.id}`,
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
    });

    return {
      challengeId: challenge.id,
      approvalUrl: `${baseUrl}/approve?challenge=${challenge.id}`,
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
   * Complete challenge after successful Passkey verification
   * Called by the signing page after WebAuthn verification
   */
  completeChallenge(
    challengeId: string,
    signature: Uint8Array
  ): { unlockCode: string } | null {
    const pending = this.pendingChallenges.get(challengeId);
    if (!pending || pending.challenge.expiresAt < Date.now()) {
      return null;
    }

    // Store signature for later use
    pending.signature = new Uint8Array(signature);
    
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
        // Unlock vault
        this.vault = await this.storage.load(foundChallenge.signature);
        this.currentSignature = new Uint8Array(foundChallenge.signature);
        
        // Create session
        const session = this.createSession(agentFingerprint);
        
        // Cleanup
        this.pendingChallenges.delete(foundId);
        
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
        
        this.pendingChallenges.delete(foundId);
        
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
   * Revoke a session
   */
  revokeSession(sessionId: string): boolean {
    return this.sessions.delete(sessionId);
  }

  /**
   * Lock vault (clear from memory)
   */
  lock(): void {
    if (this.currentSignature) {
      secureWipe(this.currentSignature);
      this.currentSignature = null;
    }
    this.vault = null;
    this.sessions.clear();
  }

  /**
   * Get all hosts (requires unlocked vault)
   */
  getHosts(): Host[] {
    if (!this.vault) {
      throw new Error('Vault is locked');
    }
    return this.vault.hosts;
  }

  /**
   * Get host by name or ID
   */
  getHost(nameOrId: string): Host | null {
    if (!this.vault) {
      throw new Error('Vault is locked');
    }
    return this.vault.hosts.find(h => h.id === nameOrId || h.name === nameOrId) ?? null;
  }

  /**
   * Add a host
   */
  async addHost(host: Omit<Host, 'id' | 'createdAt' | 'updatedAt'>): Promise<Host> {
    if (!this.vault || !this.currentSignature) {
      throw new Error('Vault is locked');
    }

    const newHost: Host = {
      ...host,
      id: randomUUID(),
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };

    this.vault.hosts.push(newHost);
    await this.storage.save(this.vault, this.currentSignature);
    return newHost;
  }

  /**
   * Remove a host
   */
  async removeHost(hostId: string): Promise<boolean> {
    if (!this.vault || !this.currentSignature) {
      throw new Error('Vault is locked');
    }

    const index = this.vault.hosts.findIndex(h => h.id === hostId);
    if (index === -1) {
      return false;
    }

    this.vault.hosts.splice(index, 1);
    await this.storage.save(this.vault, this.currentSignature);
    return true;
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
   * Add an agent
   */
  async addAgent(agent: Omit<AgentConfig, 'createdAt' | 'lastUsed'>): Promise<AgentConfig> {
    if (!this.vault || !this.currentSignature) {
      throw new Error('Vault is locked');
    }

    const newAgent: AgentConfig = {
      ...agent,
      createdAt: Date.now(),
      lastUsed: Date.now(),
    };

    this.vault.agents.push(newAgent);
    await this.storage.save(this.vault, this.currentSignature);
    return newAgent;
  }

  /**
   * Remove an agent
   */
  async removeAgent(fingerprint: string): Promise<boolean> {
    if (!this.vault || !this.currentSignature) {
      throw new Error('Vault is locked');
    }

    const index = this.vault.agents.findIndex(a => a.fingerprint === fingerprint);
    if (index === -1) {
      return false;
    }

    this.vault.agents.splice(index, 1);
    await this.storage.save(this.vault, this.currentSignature);
    return true;
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
}
