/**
 * WebAuthn / Passkey authentication
 * Handles registration and authentication using @simplewebauthn/server
 */

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type { 
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
} from '@simplewebauthn/types';
import type { PasskeyCredential } from '../types.js';

export interface WebAuthnConfig {
  rpId: string;       // e.g., "vault.example.com"
  rpName: string;     // e.g., "SSH Vault"
  origin: string;     // e.g., "https://vault.example.com"
}

export class WebAuthnManager {
  private config: WebAuthnConfig;
  private pendingRegistrations: Map<string, {
    challenge: string;
    userId: string;
    expiresAt: number;
  }> = new Map();
  private pendingAuthentications: Map<string, {
    challenge: string;
    credentialId: string;
    expiresAt: number;
  }> = new Map();

  constructor(config: WebAuthnConfig) {
    this.config = config;
  }

  /**
   * Generate registration options for new Passkey setup
   */
  async generateRegistrationOptions(userId: string, userName: string): Promise<{
    options: PublicKeyCredentialCreationOptionsJSON;
    challengeId: string;
  }> {
    // Convert userId to Uint8Array for userID
    const userIdBytes = new TextEncoder().encode(userId);
    
    const options = await generateRegistrationOptions({
      rpName: this.config.rpName,
      rpID: this.config.rpId,
      userID: userIdBytes,
      userName: userName,
      userDisplayName: userName,
      attestationType: 'none',
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'required',
        userVerification: 'required',
      },
      supportedAlgorithmIDs: [-7, -257], // ES256, RS256
    } as any);

    const challengeId = crypto.randomUUID();
    this.pendingRegistrations.set(challengeId, {
      challenge: options.challenge,
      userId,
      expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
    });

    // Convert options to proper JSON format with base64 strings
    const jsonOptions: PublicKeyCredentialCreationOptionsJSON = {
      challenge: options.challenge,
      rp: {
        name: options.rp.name,
        id: options.rp.id || this.config.rpId,
      },
      user: {
        id: bufferToBase64(userIdBytes),
        name: options.user.name,
        displayName: options.user.displayName,
      },
      pubKeyCredParams: options.pubKeyCredParams as Array<{ type: 'public-key'; alg: number }>,
      timeout: options.timeout,
      attestation: options.attestation as string,
      authenticatorSelection: options.authenticatorSelection as any,
    };

    return { 
      options: jsonOptions, 
      challengeId 
    };
  }

  /**
   * Verify registration response and extract credential
   */
  async verifyRegistration(
    challengeId: string,
    response: RegistrationResponseJSON
  ): Promise<{
    success: boolean;
    credential?: PasskeyCredential;
    error?: string;
  }> {
    const pending = this.pendingRegistrations.get(challengeId);
    if (!pending) {
      return { success: false, error: 'Challenge not found or expired' };
    }

    if (pending.expiresAt < Date.now()) {
      this.pendingRegistrations.delete(challengeId);
      return { success: false, error: 'Challenge expired' };
    }

    try {
      const verification = await verifyRegistrationResponse({
        response,
        expectedChallenge: pending.challenge,
        expectedOrigin: this.config.origin,
        expectedRPID: this.config.rpId,
        requireUserVerification: true,
      });

      if (!verification.verified || !verification.registrationInfo) {
        return { success: false, error: 'Verification failed' };
      }

      const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
      
      const passkeyCredential: PasskeyCredential = {
        id: bufferToBase64(credentialID),
        publicKey: bufferToBase64(credentialPublicKey),
        algorithm: -7, // Default to ES256
        counter: counter,
        createdAt: Date.now(),
      };

      this.pendingRegistrations.delete(challengeId);
      return { success: true, credential: passkeyCredential };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Generate authentication options for Passkey verification
   */
  async generateAuthenticationOptions(
    credentialId: string
  ): Promise<{
    options: PublicKeyCredentialRequestOptionsJSON;
    challengeId: string;
  }> {
    const options = await generateAuthenticationOptions({
      rpID: this.config.rpId,
      allowCredentials: [{
        id: base64ToBuffer(credentialId),
        type: 'public-key',
        transports: ['internal', 'hybrid'] as AuthenticatorTransportFuture[],
      }],
      userVerification: 'required',
    });

    const challengeId = crypto.randomUUID();
    this.pendingAuthentications.set(challengeId, {
      challenge: options.challenge,
      credentialId,
      expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
    });

    return { 
      options: options as unknown as PublicKeyCredentialRequestOptionsJSON, 
      challengeId 
    };
  }

  /**
   * Verify authentication response
   */
  async verifyAuthentication(
    challengeId: string,
    response: AuthenticationResponseJSON,
    credential: PasskeyCredential
  ): Promise<{
    success: boolean;
    signature?: Uint8Array;
    newCounter?: number;
    error?: string;
  }> {
    const pending = this.pendingAuthentications.get(challengeId);
    if (!pending) {
      return { success: false, error: 'Challenge not found or expired' };
    }

    if (pending.expiresAt < Date.now()) {
      this.pendingAuthentications.delete(challengeId);
      return { success: false, error: 'Challenge expired' };
    }

    try {
      const verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: pending.challenge,
        expectedOrigin: this.config.origin,
        expectedRPID: this.config.rpId,
        authenticator: {
          credentialID: base64ToBuffer(credential.id),
          credentialPublicKey: base64ToBuffer(credential.publicKey),
          counter: credential.counter,
        },
        requireUserVerification: true,
      });

      if (!verification.verified) {
        return { success: false, error: 'Verification failed' };
      }

      this.pendingAuthentications.delete(challengeId);

      // Extract signature from response for key derivation
      const signature = base64ToBuffer(response.response.signature);

      return {
        success: true,
        signature: signature,
        newCounter: verification.authenticationInfo.newCounter,
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Clean up expired challenges
   */
  cleanup(): void {
    const now = Date.now();
    
    for (const [id, pending] of this.pendingRegistrations.entries()) {
      if (pending.expiresAt < now) {
        this.pendingRegistrations.delete(id);
      }
    }

    for (const [id, pending] of this.pendingAuthentications.entries()) {
      if (pending.expiresAt < now) {
        this.pendingAuthentications.delete(id);
      }
    }
  }
}

// Type definitions for WebAuthn JSON responses
interface PublicKeyCredentialCreationOptionsJSON {
  challenge: string;
  rp: { name: string; id: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: Array<{ type: 'public-key'; alg: number }>;
  timeout?: number;
  excludeCredentials?: Array<{ type: 'public-key'; id: string; transports?: string[] }>;
  authenticatorSelection?: {
    authenticatorAttachment?: string;
    residentKey?: string;
    requireResidentKey?: boolean;
    userVerification?: string;
  };
  attestation?: string;
}

interface PublicKeyCredentialRequestOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: Array<{ type: 'public-key'; id: string; transports?: string[] }>;
  userVerification?: string;
}

// Helper functions
function bufferToBase64(buffer: Uint8Array): string {
  return Buffer.from(buffer).toString('base64url');
}

function base64ToBuffer(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, 'base64url'));
}
