/**
 * Encryption module using libsodium
 * Implements Termius-style encryption (Argon2id + XSalsa20-Poly1305)
 */

import sodium from 'libsodium-wrappers';

let sodiumReady = false;

export async function initSodium(): Promise<void> {
  if (!sodiumReady) {
    await sodium.ready;
    sodiumReady = true;
  }
}

/**
 * Generate a random salt for key derivation
 */
export function generateSalt(): Uint8Array {
  return sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
}

/**
 * Generate a random nonce for encryption
 */
export function generateNonce(): Uint8Array {
  return sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
}

/**
 * Derive encryption key from Passkey signature using Argon2id
 * @param signature - The WebAuthn signature bytes
 * @param salt - Salt for key derivation
 * @returns 32-byte encryption key
 */
export function deriveKeyFromSignature(
  signature: Uint8Array,
  salt: Uint8Array
): Uint8Array {
  return sodium.crypto_pwhash(
    sodium.crypto_secretbox_KEYBYTES,
    signature,
    salt,
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  );
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
  return sodium.crypto_secretbox_easy(plaintext, nonce, key);
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
  return sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
}

/**
 * Encrypt a string (JSON data) and return base64-encoded result
 */
export function encryptString(
  plaintext: string,
  key: Uint8Array,
  nonce: Uint8Array
): string {
  const plaintextBytes = sodium.from_string(plaintext);
  const ciphertext = encrypt(plaintextBytes, key, nonce);
  return sodium.to_base64(ciphertext, sodium.base64_variants.ORIGINAL);
}

/**
 * Decrypt base64-encoded ciphertext and return string
 */
export function decryptString(
  ciphertextBase64: string,
  key: Uint8Array,
  nonce: Uint8Array
): string {
  const ciphertext = sodium.from_base64(ciphertextBase64, sodium.base64_variants.ORIGINAL);
  const plaintext = decrypt(ciphertext, key, nonce);
  return sodium.to_string(plaintext);
}

/**
 * Convert Uint8Array to base64
 */
export function toBase64(data: Uint8Array): string {
  return sodium.to_base64(data, sodium.base64_variants.ORIGINAL);
}

/**
 * Convert base64 to Uint8Array
 */
export function fromBase64(base64: string): Uint8Array {
  return sodium.from_base64(base64, sodium.base64_variants.ORIGINAL);
}

/**
 * Generate a secure random string for challenge IDs, unlock codes, etc.
 */
export function generateRandomId(length: number = 16): string {
  const bytes = sodium.randombytes_buf(length);
  return sodium.to_hex(bytes);
}

/**
 * Generate a short, user-friendly unlock code
 * Format: UNLOCK-XXXXX (5 alphanumeric chars)
 */
export function generateUnlockCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // No O, 0, I, 1 for clarity
  const bytes = sodium.randombytes_buf(5);
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
  sodium.memzero(buffer);
}
