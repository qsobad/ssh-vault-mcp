/**
 * Security Breach Tests: Vault Encryption
 *
 * Tests encryption boundary conditions, key derivation attacks,
 * ciphertext tampering detection, and nonce handling.
 */

import { describe, it, expect } from 'vitest';
import nacl from 'tweetnacl';
import {
  encrypt,
  decrypt,
  encryptString,
  decryptString,
  deriveKeyFromPassword,
  deriveKeyFromSignature,
  generateSalt,
  generateNonce,
  generateRandomId,
  generateUnlockCode,
  secureWipe,
  toBase64,
  fromBase64,
  LEGACY_KDF_PARAMS,
} from '../../src/vault/encryption.js';

describe('Security Breach: Vault Encryption', () => {
  describe('Key Derivation', () => {
    it('should produce different keys for different passwords', () => {
      const salt = generateSalt();
      const key1 = deriveKeyFromPassword('password1', salt, LEGACY_KDF_PARAMS);
      const key2 = deriveKeyFromPassword('password2', salt, LEGACY_KDF_PARAMS);
      expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(false);
    });

    it('should produce different keys for different salts', () => {
      const salt1 = generateSalt();
      const salt2 = generateSalt();
      const key1 = deriveKeyFromPassword('samepassword', salt1, LEGACY_KDF_PARAMS);
      const key2 = deriveKeyFromPassword('samepassword', salt2, LEGACY_KDF_PARAMS);
      expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(false);
    });

    it('should produce consistent keys for same password+salt', () => {
      const salt = generateSalt();
      const key1 = deriveKeyFromPassword('mypassword', salt, LEGACY_KDF_PARAMS);
      const key2 = deriveKeyFromPassword('mypassword', salt, LEGACY_KDF_PARAMS);
      expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(true);
    });

    it('should always produce 32-byte keys', () => {
      const salt = generateSalt();
      const key = deriveKeyFromPassword('any-password', salt, LEGACY_KDF_PARAMS);
      expect(key.length).toBe(32);
    });

    it('should handle empty passwords', () => {
      const salt = generateSalt();
      // Should not throw, even with empty password
      const key = deriveKeyFromPassword('', salt, LEGACY_KDF_PARAMS);
      expect(key.length).toBe(32);
    });

    it('should handle very long passwords', () => {
      const salt = generateSalt();
      const longPassword = 'a'.repeat(10000);
      const key = deriveKeyFromPassword(longPassword, salt, LEGACY_KDF_PARAMS);
      expect(key.length).toBe(32);
    });

    it('should handle unicode passwords', () => {
      const salt = generateSalt();
      const key = deriveKeyFromPassword('p\u00e4ssw\u00f6rd\ud83d\udd12', salt, LEGACY_KDF_PARAMS);
      expect(key.length).toBe(32);
    });

    it('should derive different keys from signature vs password', () => {
      const salt = generateSalt();
      const signature = nacl.randomBytes(64);
      const keyFromSig = deriveKeyFromSignature(signature, salt);
      const keyFromPwd = deriveKeyFromPassword('test', salt, LEGACY_KDF_PARAMS);
      expect(Buffer.from(keyFromSig).equals(Buffer.from(keyFromPwd))).toBe(false);
    });
  });

  describe('Encryption/Decryption Integrity', () => {
    it('should encrypt and decrypt correctly', () => {
      const key = nacl.randomBytes(32);
      const nonce = generateNonce();
      const plaintext = new TextEncoder().encode('Hello, World!');

      const ciphertext = encrypt(plaintext, key, nonce);
      const decrypted = decrypt(ciphertext, key, nonce);

      expect(Buffer.from(decrypted).toString('utf8')).toBe('Hello, World!');
    });

    it('should fail decryption with wrong key', () => {
      const key1 = nacl.randomBytes(32);
      const key2 = nacl.randomBytes(32);
      const nonce = generateNonce();
      const plaintext = new TextEncoder().encode('secret data');

      const ciphertext = encrypt(plaintext, key1, nonce);
      expect(() => decrypt(ciphertext, key2, nonce)).toThrow('Decryption failed');
    });

    it('should fail decryption with wrong nonce', () => {
      const key = nacl.randomBytes(32);
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();
      const plaintext = new TextEncoder().encode('secret data');

      const ciphertext = encrypt(plaintext, key, nonce1);
      expect(() => decrypt(ciphertext, key, nonce2)).toThrow('Decryption failed');
    });

    it('should detect ciphertext tampering (single bit flip)', () => {
      const key = nacl.randomBytes(32);
      const nonce = generateNonce();
      const plaintext = new TextEncoder().encode('important data');

      const ciphertext = encrypt(plaintext, key, nonce);
      // Flip one bit in the ciphertext
      const tampered = new Uint8Array(ciphertext);
      tampered[0] ^= 0x01;

      expect(() => decrypt(tampered, key, nonce)).toThrow('Decryption failed');
    });

    it('should detect truncated ciphertext', () => {
      const key = nacl.randomBytes(32);
      const nonce = generateNonce();
      const plaintext = new TextEncoder().encode('data to truncate');

      const ciphertext = encrypt(plaintext, key, nonce);
      const truncated = ciphertext.slice(0, ciphertext.length - 4);

      expect(() => decrypt(truncated, key, nonce)).toThrow('Decryption failed');
    });

    it('should detect appended data to ciphertext', () => {
      const key = nacl.randomBytes(32);
      const nonce = generateNonce();
      const plaintext = new TextEncoder().encode('original data');

      const ciphertext = encrypt(plaintext, key, nonce);
      const extended = new Uint8Array(ciphertext.length + 16);
      extended.set(ciphertext);
      extended.set(nacl.randomBytes(16), ciphertext.length);

      expect(() => decrypt(extended, key, nonce)).toThrow('Decryption failed');
    });

    it('should handle empty plaintext', () => {
      const key = nacl.randomBytes(32);
      const nonce = generateNonce();
      const plaintext = new Uint8Array(0);

      const ciphertext = encrypt(plaintext, key, nonce);
      const decrypted = decrypt(ciphertext, key, nonce);
      expect(decrypted.length).toBe(0);
    });

    it('should handle large plaintext', () => {
      const key = nacl.randomBytes(32);
      const nonce = generateNonce();
      const plaintext = nacl.randomBytes(1024 * 1024); // 1MB

      const ciphertext = encrypt(plaintext, key, nonce);
      const decrypted = decrypt(ciphertext, key, nonce);
      expect(Buffer.from(decrypted).equals(Buffer.from(plaintext))).toBe(true);
    });
  });

  describe('String Encryption', () => {
    it('should encrypt and decrypt JSON strings correctly', () => {
      const key = nacl.randomBytes(32);
      const nonce = generateNonce();
      const data = JSON.stringify({ hosts: [], agents: [], secret: 'value' });

      const encrypted = encryptString(data, key, nonce);
      const decrypted = decryptString(encrypted, key, nonce);

      expect(JSON.parse(decrypted)).toEqual(JSON.parse(data));
    });

    it('should produce base64 output from encryptString', () => {
      const key = nacl.randomBytes(32);
      const nonce = generateNonce();
      const encrypted = encryptString('test', key, nonce);

      // Should be valid base64
      expect(() => Buffer.from(encrypted, 'base64')).not.toThrow();
    });

    it('should handle special characters in strings', () => {
      const key = nacl.randomBytes(32);
      const nonce = generateNonce();
      const data = 'Special chars: \n\t\r\0"\'\\/<>& \u00e9\u00e8\u00ea \ud83d\udd10';

      const encrypted = encryptString(data, key, nonce);
      const decrypted = decryptString(encrypted, key, nonce);
      expect(decrypted).toBe(data);
    });
  });

  describe('Nonce/Salt Generation', () => {
    it('should generate 16-byte salts', () => {
      const salt = generateSalt();
      expect(salt.length).toBe(16);
    });

    it('should generate 24-byte nonces', () => {
      const nonce = generateNonce();
      expect(nonce.length).toBe(24);
    });

    it('should generate unique salts', () => {
      const salts = new Set<string>();
      for (let i = 0; i < 100; i++) {
        salts.add(toBase64(generateSalt()));
      }
      expect(salts.size).toBe(100);
    });

    it('should generate unique nonces', () => {
      const nonces = new Set<string>();
      for (let i = 0; i < 100; i++) {
        nonces.add(toBase64(generateNonce()));
      }
      expect(nonces.size).toBe(100);
    });
  });

  describe('Nonce Reuse Vulnerability', () => {
    it('should produce different ciphertexts with different nonces (same key+plaintext)', () => {
      const key = nacl.randomBytes(32);
      const plaintext = new TextEncoder().encode('same data');

      const nonce1 = generateNonce();
      const nonce2 = generateNonce();

      const ct1 = encrypt(plaintext, key, nonce1);
      const ct2 = encrypt(plaintext, key, nonce2);

      expect(Buffer.from(ct1).equals(Buffer.from(ct2))).toBe(false);
    });

    it('should produce same ciphertext with reused nonce (vulnerability demo)', () => {
      const key = nacl.randomBytes(32);
      const nonce = generateNonce();
      const plaintext = new TextEncoder().encode('same data');

      const ct1 = encrypt(plaintext, key, nonce);
      const ct2 = encrypt(plaintext, key, nonce);

      // Same key + same nonce + same plaintext = same ciphertext (expected for XSalsa20)
      // This is dangerous if nonces are reused with different plaintexts
      expect(Buffer.from(ct1).equals(Buffer.from(ct2))).toBe(true);
    });
  });

  describe('Base64 Encoding', () => {
    it('should round-trip base64 correctly', () => {
      const data = nacl.randomBytes(32);
      const encoded = toBase64(data);
      const decoded = fromBase64(encoded);
      expect(Buffer.from(decoded).equals(Buffer.from(data))).toBe(true);
    });

    it('should handle empty data', () => {
      const data = new Uint8Array(0);
      const encoded = toBase64(data);
      const decoded = fromBase64(encoded);
      expect(decoded.length).toBe(0);
    });
  });

  describe('Random ID Generation', () => {
    it('should generate IDs of expected length', () => {
      const id = generateRandomId(16);
      expect(id.length).toBe(32); // 16 bytes = 32 hex chars
    });

    it('should generate unique IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(generateRandomId());
      }
      expect(ids.size).toBe(100);
    });

    it('should generate hex-only strings', () => {
      const id = generateRandomId();
      expect(id).toMatch(/^[0-9a-f]+$/);
    });
  });

  describe('Unlock Code Generation', () => {
    it('should generate codes in UNLOCK-XXXXX format', () => {
      const code = generateUnlockCode();
      expect(code).toMatch(/^UNLOCK-[A-Z2-9]{5}$/);
    });

    it('should not contain ambiguous characters (O, 0, I, 1)', () => {
      // Generate many codes and check none contain ambiguous chars
      for (let i = 0; i < 100; i++) {
        const code = generateUnlockCode();
        const suffix = code.replace('UNLOCK-', '');
        expect(suffix).not.toMatch(/[OI01]/);
      }
    });

    it('should generate unique codes', () => {
      const codes = new Set<string>();
      for (let i = 0; i < 100; i++) {
        codes.add(generateUnlockCode());
      }
      // With 28^5 = ~17M possibilities, 100 codes should all be unique
      expect(codes.size).toBe(100);
    });
  });

  describe('Secure Wipe', () => {
    it('should zero out buffer contents', () => {
      const buffer = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      secureWipe(buffer);
      expect(buffer.every(b => b === 0)).toBe(true);
    });

    it('should zero out a 32-byte key', () => {
      const key = nacl.randomBytes(32);
      expect(key.some(b => b !== 0)).toBe(true); // Should have non-zero bytes
      secureWipe(key);
      expect(key.every(b => b === 0)).toBe(true);
    });
  });
});
