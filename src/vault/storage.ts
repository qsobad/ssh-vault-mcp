/**
 * Vault file storage
 * Handles reading/writing encrypted vault files
 */

import { promises as fs } from 'fs';
import path from 'path';
import type { Vault, VaultFile, VaultFileCredential, PasskeyCredential } from '../types.js';
import {
  initSodium,
  generateSalt,
  generateNonce,
  encryptString,
  decryptString,
  toBase64,
  fromBase64,
} from './encryption.js';

export class VaultStorage {
  private vaultPath: string;
  private backupEnabled: boolean;

  constructor(vaultPath: string, backupEnabled: boolean = true) {
    this.vaultPath = vaultPath;
    this.backupEnabled = backupEnabled;
  }

  /**
   * Check if vault file exists
   */
  async exists(): Promise<boolean> {
    try {
      await fs.access(this.vaultPath);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Create a new vault with the given Passkey credential
   * @param credential - The Passkey credential from registration
   * @param vek - The Vault Encryption Key (derived from master password)
   */
  async create(
    credential: PasskeyCredential,
    vek: Uint8Array
  ): Promise<Vault> {
    await initSodium();

    const vault: Vault = {
      version: 1,
      owner: credential,
      credentials: [credential],
      hosts: [],
      agents: [],
      policy: {
        allowedCommands: ['*'],
        deniedCommands: ['rm -rf /', 'rm -rf /*', 'mkfs', 'dd if=', ':(){:|:&};:', '> /dev/sda', 'mv /* '],
      },
    };

    await this.save(vault, vek);
    return vault;
  }

  /**
   * Save vault to encrypted file
   */
  async save(vault: Vault, vek: Uint8Array): Promise<void> {
    await initSodium();

    // Create backup if enabled and file exists
    if (this.backupEnabled && await this.exists()) {
      const backupPath = `${this.vaultPath}.backup`;
      await fs.copyFile(this.vaultPath, backupPath);
    }

    const salt = generateSalt();
    const nonce = generateNonce();

    try {
      const vaultJson = JSON.stringify(vault);
      const encryptedData = encryptString(vaultJson, vek, nonce);

      // Read existing file to preserve passwordSalt
      let passwordSalt = '';
      if (await this.exists()) {
        const fileContent = await fs.readFile(this.vaultPath, 'utf-8');
        const existing: VaultFile = JSON.parse(fileContent);
        passwordSalt = existing.passwordSalt;
      }

      // Build credentials array for VaultFile
      const allCredentials = (vault.credentials || [vault.owner]);
      const vaultFileCredentials: VaultFileCredential[] = allCredentials.map(c => ({
        id: c.id,
        publicKey: c.publicKey,
        algorithm: c.algorithm,
        counter: c.counter,
      }));

      const vaultFile: VaultFile = {
        version: 1,
        credentialId: vault.owner.id,
        publicKey: vault.owner.publicKey,
        algorithm: vault.owner.algorithm,
        counter: vault.owner.counter,
        credentials: vaultFileCredentials,
        passwordSalt,
        salt: toBase64(salt),
        nonce: toBase64(nonce),
        data: encryptedData,
      };

      // Ensure directory exists
      const dir = path.dirname(this.vaultPath);
      await fs.mkdir(dir, { recursive: true });

      // Write atomically (write to temp, then rename) with restrictive permissions
      const tempPath = `${this.vaultPath}.tmp`;
      await fs.writeFile(tempPath, JSON.stringify(vaultFile, null, 2), { mode: 0o600 });
      await fs.rename(tempPath, this.vaultPath);
    } finally {
      // Don't wipe VEK here - caller manages its lifecycle
    }
  }

  /**
   * Save vault with passwordSalt (for initial creation)
   */
  async saveWithPasswordSalt(vault: Vault, vek: Uint8Array, passwordSalt: string): Promise<void> {
    await initSodium();

    if (this.backupEnabled && await this.exists()) {
      const backupPath = `${this.vaultPath}.backup`;
      await fs.copyFile(this.vaultPath, backupPath);
    }

    const salt = generateSalt();
    const nonce = generateNonce();

    const vaultJson = JSON.stringify(vault);
    const encryptedData = encryptString(vaultJson, vek, nonce);

    const allCredentials = (vault.credentials || [vault.owner]);
    const vaultFileCredentials: VaultFileCredential[] = allCredentials.map(c => ({
      id: c.id,
      publicKey: c.publicKey,
      algorithm: c.algorithm,
      counter: c.counter,
    }));

    const vaultFile: VaultFile = {
      version: 1,
      credentialId: vault.owner.id,
      publicKey: vault.owner.publicKey,
      algorithm: vault.owner.algorithm,
      counter: vault.owner.counter,
      credentials: vaultFileCredentials,
      passwordSalt,
      salt: toBase64(salt),
      nonce: toBase64(nonce),
      data: encryptedData,
    };

    const dir = path.dirname(this.vaultPath);
    await fs.mkdir(dir, { recursive: true });

    const tempPath = `${this.vaultPath}.tmp`;
    await fs.writeFile(tempPath, JSON.stringify(vaultFile, null, 2), { mode: 0o600 });
    await fs.rename(tempPath, this.vaultPath);
  }

  /**
   * Load and decrypt vault using VEK
   */
  async load(vek: Uint8Array): Promise<Vault> {
    await initSodium();

    const fileContent = await fs.readFile(this.vaultPath, 'utf-8');
    const vaultFile: VaultFile = JSON.parse(fileContent);

    if (vaultFile.version !== 1) {
      throw new Error(`Unsupported vault version: ${vaultFile.version}`);
    }

    const nonce = fromBase64(vaultFile.nonce);

    try {
      const vaultJson = decryptString(vaultFile.data, vek, nonce);
      const vault = JSON.parse(vaultJson) as Vault;
      // Backward compat: ensure credentials array exists
      if (!vault.credentials) {
        vault.credentials = [vault.owner];
      }
      return vault;
    } catch (error) {
      throw new Error('Failed to decrypt vault: invalid password or corrupted data');
    }
  }

  /**
   * Decrypt a single host's credential from the vault file on-demand
   */
  async decryptHostCredential(hostId: string, vek: Uint8Array): Promise<string | null> {
    await initSodium();

    const fileContent = await fs.readFile(this.vaultPath, 'utf-8');
    const vaultFile: VaultFile = JSON.parse(fileContent);
    const nonce = fromBase64(vaultFile.nonce);

    try {
      const vaultJson = decryptString(vaultFile.data, vek, nonce);
      const vault = JSON.parse(vaultJson) as Vault;
      const host = vault.hosts.find(h => h.id === hostId || h.name === hostId);
      return host?.credential ?? null;
    } catch {
      throw new Error('Failed to decrypt vault: invalid password or corrupted data');
    }
  }

  /**
   * Get vault metadata without decrypting
   */
  async getMetadata(): Promise<{
    credentialId: string;
    publicKey: string;
    algorithm: number;
    passwordSalt: string;
    credentials: VaultFileCredential[];
  } | null> {
    if (!await this.exists()) {
      return null;
    }

    const fileContent = await fs.readFile(this.vaultPath, 'utf-8');
    const vaultFile: VaultFile = JSON.parse(fileContent);

    // Backward compat: build credentials array if not present
    const credentials = vaultFile.credentials || [{
      id: vaultFile.credentialId,
      publicKey: vaultFile.publicKey,
      algorithm: vaultFile.algorithm,
      counter: vaultFile.counter,
    }];

    return {
      credentialId: vaultFile.credentialId,
      publicKey: vaultFile.publicKey,
      algorithm: vaultFile.algorithm,
      passwordSalt: vaultFile.passwordSalt,
      credentials,
    };
  }

  /**
   * Get stored counter for replay protection
   */
  async getCounter(): Promise<number> {
    if (!await this.exists()) {
      return 0;
    }

    const fileContent = await fs.readFile(this.vaultPath, 'utf-8');
    const vaultFile: VaultFile = JSON.parse(fileContent);
    return vaultFile.counter;
  }

  /**
   * Get password salt from vault file
   */
  async getPasswordSalt(): Promise<string | null> {
    if (!await this.exists()) {
      return null;
    }

    const fileContent = await fs.readFile(this.vaultPath, 'utf-8');
    const vaultFile: VaultFile = JSON.parse(fileContent);
    return vaultFile.passwordSalt;
  }

  /**
   * Update counter after successful authentication
   */
  async updateCounter(newCounter: number, vek: Uint8Array): Promise<void> {
    const vault = await this.load(vek);
    vault.owner.counter = newCounter;
    await this.save(vault, vek);
  }
}
