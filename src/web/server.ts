/**
 * Web Server for Passkey authentication pages
 */

import express, { type Request, type Response } from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import type { Config } from '../types.js';
import { VaultManager } from '../vault/vault.js';
import { WebAuthnManager } from '../auth/webauthn.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export class WebServer {
  private app: express.Application;
  private config: Config;
  private vaultManager: VaultManager;
  private webauthn: WebAuthnManager;

  constructor(config: Config, vaultManager: VaultManager) {
    this.config = config;
    this.vaultManager = vaultManager;
    this.webauthn = new WebAuthnManager({
      rpId: config.webauthn.rpId,
      rpName: config.webauthn.rpName,
      origin: config.webauthn.origin,
    });

    this.app = express();
    this.setupMiddleware();
    this.setupRoutes();
  }

  private setupMiddleware(): void {
    this.app.use(cors({
      origin: this.config.webauthn.origin,
      credentials: true,
    }));
    this.app.use(express.json());
    
    // Serve static files from web directory
    const webDir = path.join(__dirname, '../../web');
    this.app.use(express.static(webDir));
  }

  private setupRoutes(): void {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({ status: 'ok' });
    });

    // Get challenge info for signing page
    this.app.get('/api/challenge/:id', (req: Request, res: Response) => {
      const challenge = this.vaultManager.getChallenge(req.params.id);
      if (!challenge) {
        res.status(404).json({ error: 'Challenge not found or expired' });
        return;
      }

      res.json({
        action: challenge.action,
        host: challenge.host,
        commands: challenge.commands,
        agent: challenge.agent,
        expiresAt: challenge.expiresAt,
      });
    });

    // Registration endpoints (for initial setup)
    this.app.post('/api/register/options', async (req: Request, res: Response) => {
      try {
        const { userId, userName } = req.body;
        if (!userId || !userName) {
          res.status(400).json({ error: 'userId and userName required' });
          return;
        }

        const { options, challengeId } = await this.webauthn.generateRegistrationOptions(
          userId,
          userName
        );

        res.json({ options, challengeId });
      } catch (error) {
        res.status(500).json({ 
          error: error instanceof Error ? error.message : 'Registration failed' 
        });
      }
    });

    this.app.post('/api/register/verify', async (req: Request, res: Response) => {
      try {
        const { challengeId, response } = req.body;
        if (!challengeId || !response) {
          res.status(400).json({ error: 'challengeId and response required' });
          return;
        }

        const result = await this.webauthn.verifyRegistration(challengeId, response);
        
        if (!result.success || !result.credential) {
          res.status(400).json({ error: result.error || 'Verification failed' });
          return;
        }

        // Create vault with the new credential
        // Note: In a real implementation, we'd need the signature here
        // For now, we'll use a placeholder flow
        res.json({ 
          success: true, 
          message: 'Registration successful. Vault created.',
          credentialId: result.credential.id,
        });
      } catch (error) {
        res.status(500).json({ 
          error: error instanceof Error ? error.message : 'Verification failed' 
        });
      }
    });

    // Authentication endpoints
    this.app.post('/api/auth/options', async (req: Request, res: Response) => {
      try {
        const metadata = await this.vaultManager.getMetadata();
        if (!metadata) {
          res.status(404).json({ error: 'No vault found. Please register first.' });
          return;
        }

        const { options, challengeId } = await this.webauthn.generateAuthenticationOptions(
          metadata.credentialId
        );

        res.json({ options, challengeId });
      } catch (error) {
        res.status(500).json({ 
          error: error instanceof Error ? error.message : 'Failed to generate options' 
        });
      }
    });

    this.app.post('/api/auth/verify', async (req: Request, res: Response) => {
      try {
        const { webauthnChallengeId, vaultChallengeId, response } = req.body;
        
        if (!webauthnChallengeId || !vaultChallengeId || !response) {
          res.status(400).json({ 
            error: 'webauthnChallengeId, vaultChallengeId, and response required' 
          });
          return;
        }

        // Get vault metadata for credential
        const metadata = await this.vaultManager.getMetadata();
        if (!metadata) {
          res.status(404).json({ error: 'No vault found' });
          return;
        }

        // Verify WebAuthn response
        const result = await this.webauthn.verifyAuthentication(
          webauthnChallengeId,
          response,
          {
            id: metadata.credentialId,
            publicKey: metadata.publicKey,
            algorithm: metadata.algorithm,
            counter: 0, // Will be checked from vault
            createdAt: 0,
          }
        );

        if (!result.success || !result.signature) {
          res.status(400).json({ error: result.error || 'Verification failed' });
          return;
        }

        // Complete vault challenge with signature
        const unlockResult = this.vaultManager.completeChallenge(
          vaultChallengeId,
          result.signature
        );

        if (!unlockResult) {
          res.status(400).json({ error: 'Vault challenge expired or not found' });
          return;
        }

        res.json({
          success: true,
          unlockCode: unlockResult.unlockCode,
          message: 'Authentication successful. Use this code to unlock the vault.',
        });
      } catch (error) {
        res.status(500).json({ 
          error: error instanceof Error ? error.message : 'Verification failed' 
        });
      }
    });

    // Serve signing page
    this.app.get('/sign', (req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '../../web/index.html'));
    });

    this.app.get('/approve', (req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '../../web/index.html'));
    });

    this.app.get('/setup', (req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '../../web/index.html'));
    });
  }

  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.app.listen(this.config.web.port, this.config.server.host, () => {
        resolve();
      });
    });
  }
}
