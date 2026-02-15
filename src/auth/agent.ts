/**
 * Agent signature verification using Ed25519
 */

import nacl from 'tweetnacl';
import { sha256 } from '@noble/hashes/sha2.js';

// Request validity window (30 seconds)
const REQUEST_VALIDITY_MS = 30 * 1000;

// Used nonces for replay protection (cleared periodically)
const usedNonces = new Set<string>();

export interface SignedRequest {
  payload: string;      // Original request JSON
  signature: string;    // Ed25519 signature (base64)
  publicKey: string;    // Public key (base64)
  timestamp: number;    // Unix timestamp (ms)
  nonce: string;        // Random nonce for replay protection
}

export interface VerificationResult {
  valid: boolean;
  fingerprint?: string;
  error?: string;
}

/**
 * Generate fingerprint from Ed25519 public key
 * Format: "SHA256:<base64>"
 */
export function generateFingerprint(publicKey: Uint8Array): string {
  const hash = sha256(publicKey);
  const base64 = Buffer.from(hash).toString('base64').replace(/=+$/, '');
  return `SHA256:${base64}`;
}

/**
 * Generate fingerprint from base64 public key string
 */
export function fingerprintFromPublicKey(publicKeyBase64: string): string {
  const publicKey = Buffer.from(publicKeyBase64, 'base64');
  return generateFingerprint(new Uint8Array(publicKey));
}

/**
 * Verify a signed request from an agent
 */
export function verifySignedRequest(request: SignedRequest): VerificationResult {
  try {
    // Check timestamp validity
    const now = Date.now();
    if (Math.abs(now - request.timestamp) > REQUEST_VALIDITY_MS) {
      return { valid: false, error: 'Request expired or timestamp invalid' };
    }

    // Check nonce hasn't been used (replay protection)
    const nonceKey = `${request.publicKey}:${request.nonce}`;
    if (usedNonces.has(nonceKey)) {
      return { valid: false, error: 'Nonce already used (replay attack)' };
    }

    // Decode public key and signature
    const publicKey = Buffer.from(request.publicKey, 'base64');
    const signature = Buffer.from(request.signature, 'base64');

    // Verify public key length (Ed25519 = 32 bytes)
    if (publicKey.length !== 32) {
      return { valid: false, error: 'Invalid public key length' };
    }

    // Verify signature length (Ed25519 = 64 bytes)
    if (signature.length !== 64) {
      return { valid: false, error: 'Invalid signature length' };
    }

    // Create message to verify: payload + timestamp + nonce
    const message = `${request.payload}:${request.timestamp}:${request.nonce}`;
    const messageBytes = new TextEncoder().encode(message);

    // Verify Ed25519 signature
    const valid = nacl.sign.detached.verify(
      messageBytes,
      new Uint8Array(signature),
      new Uint8Array(publicKey)
    );

    if (!valid) {
      return { valid: false, error: 'Invalid signature' };
    }

    // Mark nonce as used
    usedNonces.add(nonceKey);

    // Generate fingerprint
    const fingerprint = generateFingerprint(new Uint8Array(publicKey));

    return { valid: true, fingerprint };
  } catch (error) {
    return { valid: false, error: `Verification failed: ${error}` };
  }
}

/**
 * Generate a new Ed25519 keypair for an agent
 * Returns base64 encoded keys and fingerprint
 */
export function generateAgentKeypair(): {
  publicKey: string;
  privateKey: string;
  fingerprint: string;
} {
  const keypair = nacl.sign.keyPair();
  const publicKey = Buffer.from(keypair.publicKey).toString('base64');
  const privateKey = Buffer.from(keypair.secretKey).toString('base64');
  const fingerprint = generateFingerprint(keypair.publicKey);

  return { publicKey, privateKey, fingerprint };
}

/**
 * Sign a request payload (for agent-side use)
 */
export function signRequest(
  payload: string,
  privateKeyBase64: string
): SignedRequest {
  const privateKey = Buffer.from(privateKeyBase64, 'base64');
  const timestamp = Date.now();
  const nonce = Buffer.from(nacl.randomBytes(16)).toString('base64');

  // Create message: payload + timestamp + nonce
  const message = `${payload}:${timestamp}:${nonce}`;
  const messageBytes = new TextEncoder().encode(message);

  // Sign with Ed25519
  const signature = nacl.sign.detached(
    messageBytes,
    new Uint8Array(privateKey)
  );

  // Extract public key from secret key (last 32 bytes of 64-byte secret key)
  const publicKey = privateKey.slice(32);

  return {
    payload,
    signature: Buffer.from(signature).toString('base64'),
    publicKey: Buffer.from(publicKey).toString('base64'),
    timestamp,
    nonce,
  };
}

/**
 * Clean up old nonces periodically
 * Call this on an interval (e.g., every 10 minutes)
 */
export function cleanupNonces(): void {
  usedNonces.clear();
}

// Auto-cleanup every 30 seconds
setInterval(cleanupNonces, 30 * 1000);
