/**
 * Encryption module using tweetnacl + @noble/hashes
 * Implements encryption (XSalsa20-Poly1305) with Argon2id key derivation
 */

import nacl from 'tweetnacl';
import { argon2id } from '@noble/hashes/argon2.js';

/**
 * KDF (Key Derivation Function) parameters for Argon2id.
 * Stored in the vault file so existing vaults can always be decrypted
 * even if defaults change.
 */
export interface KdfParams {
  t: number;     // time cost (iterations)
  m: number;     // memory cost in KiB
  p: number;     // parallelism (lanes)
  dkLen: number; // derived key length in bytes
}

/**
 * Default KDF parameters for vaults.
 * t=3 iterations, m=64 MB, p=1 lane.
 * Good security/performance balance for interactive use (~2-5s on typical servers).
 */
export const DEFAULT_KDF_PARAMS: KdfParams = {
  t: 3,
  m: 65536,   // 64 MB (in KiB)
  p: 1,
  dkLen: 32,
};

/**
 * Legacy KDF parameters used by vaults created before the hardening.
 * Used when loading vaults that don't have stored kdfParams.
 */
export const LEGACY_KDF_PARAMS: KdfParams = {
  t: 3,
  m: 65536,  // 64 MB
  p: 1,
  dkLen: 32,
};

// Base64 encoding/decoding utilities
function encodeBase64(data: Uint8Array): string {
  return Buffer.from(data).toString('base64');
}

function decodeBase64(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

function encodeUTF8(data: Uint8Array): string {
  return Buffer.from(data).toString('utf8');
}

function decodeUTF8(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, 'utf8'));
}

/**
 * Initialize (no-op for tweetnacl, kept for API compatibility)
 */
export async function initSodium(): Promise<void> {
  // tweetnacl doesn't need initialization
}

/**
 * Generate a random salt for key derivation (16 bytes)
 */
export function generateSalt(): Uint8Array {
  return nacl.randomBytes(16);
}

/**
 * Generate a random nonce for encryption (24 bytes for XSalsa20)
 */
export function generateNonce(): Uint8Array {
  return nacl.randomBytes(24);
}

/**
 * Derive encryption key from Passkey signature using Argon2id
 * @deprecated Use deriveKeyFromPassword instead
 */
export function deriveKeyFromSignature(
  signature: Uint8Array,
  salt: Uint8Array
): Uint8Array {
  return argon2id(signature, salt, {
    t: LEGACY_KDF_PARAMS.t,
    m: LEGACY_KDF_PARAMS.m,
    p: LEGACY_KDF_PARAMS.p,
    dkLen: LEGACY_KDF_PARAMS.dkLen,
  });
}

/**
 * Derive encryption key from master password using Argon2id
 * @param password - The master password
 * @param salt - Random salt for key derivation
 * @param params - KDF parameters (defaults to DEFAULT_KDF_PARAMS for new vaults;
 *                 pass stored kdfParams from vault file for existing vaults)
 * @returns 32-byte encryption key (VEK)
 */
export function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS
): Uint8Array {
  const passwordBytes = new TextEncoder().encode(password);
  return argon2id(passwordBytes, salt, {
    t: params.t,
    m: params.m,
    p: params.p,
    dkLen: params.dkLen,
  });
}

/**
 * Validate master password strength.
 * Requires: >= 12 chars, uppercase, lowercase, digit, special character.
 */
export function validatePasswordStrength(password: string): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  if (password.length < 12) {
    errors.push('Password must be at least 12 characters long');
  }
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one digit');
  }
  if (!/[^a-zA-Z0-9]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Encrypt data using XSalsa20-Poly1305
 * @param plaintext - Data to encrypt
 * @param key - 32-byte encryption key
 * @param nonce - 24-byte nonce
 * @returns Encrypted ciphertext with MAC
 */
export function encrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array
): Uint8Array {
  return nacl.secretbox(plaintext, nonce, key);
}

/**
 * Decrypt data using XSalsa20-Poly1305
 * @param ciphertext - Encrypted data with MAC
 * @param key - 32-byte encryption key
 * @param nonce - 24-byte nonce
 * @returns Decrypted plaintext
 * @throws Error if decryption fails (wrong key or tampered data)
 */
export function decrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array
): Uint8Array {
  const result = nacl.secretbox.open(ciphertext, nonce, key);
  if (!result) {
    throw new Error('Decryption failed: invalid key or corrupted data');
  }
  return result;
}

/**
 * Encrypt a string (JSON data) and return base64-encoded result
 */
export function encryptString(
  plaintext: string,
  key: Uint8Array,
  nonce: Uint8Array
): string {
  const plaintextBytes = decodeUTF8(plaintext);
  const ciphertext = encrypt(plaintextBytes, key, nonce);
  return encodeBase64(ciphertext);
}

/**
 * Decrypt base64-encoded ciphertext and return string
 */
export function decryptString(
  ciphertextBase64: string,
  key: Uint8Array,
  nonce: Uint8Array
): string {
  const ciphertext = decodeBase64(ciphertextBase64);
  const plaintext = decrypt(ciphertext, key, nonce);
  return encodeUTF8(plaintext);
}

/**
 * Convert Uint8Array to base64
 */
export function toBase64(data: Uint8Array): string {
  return encodeBase64(data);
}

/**
 * Convert base64 to Uint8Array
 */
export function fromBase64(base64: string): Uint8Array {
  return decodeBase64(base64);
}

/**
 * Generate a secure random string for challenge IDs, unlock codes, etc.
 */
export function generateRandomId(length: number = 16): string {
  const bytes = nacl.randomBytes(length);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Generate a short, user-friendly unlock code
 * Format: UNLOCK-XXXXX (5 alphanumeric chars)
 */
export function generateUnlockCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // No O, 0, I, 1 for clarity
  const bytes = nacl.randomBytes(5);
  let code = '';
  for (let i = 0; i < 5; i++) {
    code += chars[bytes[i] % chars.length];
  }
  return `UNLOCK-${code}`;
}

/**
 * Securely clear a buffer (overwrite with zeros)
 */
export function secureWipe(buffer: Uint8Array): void {
  buffer.fill(0);
}
