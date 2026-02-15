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
    this.app.get('/health', (_req: Request, res: Response) => {
      res.json({ status: 'ok' });
    });

    // Create vault unlock challenge (for testing / agent use)
    this.app.post('/api/vault/unlock', (req: Request, res: Response) => {
      const agentFingerprint = req.body.agentFingerprint || 'SHA256:unknown-agent';
      
      const { challengeId, unlockUrl, listenUrl, expiresAt } = this.vaultManager.createUnlockChallenge(
        this.config.web.externalUrl,
        agentFingerprint
      );

      res.json({
        status: 'pending',
        challengeId,
        unlockUrl,
        listenUrl,
        expiresAt,
        message: 'Please visit the URL and authenticate with your Passkey.',
      });
    });

    // Check vault status
    this.app.get('/api/vault/status', async (_req: Request, res: Response) => {
      const exists = await this.vaultManager.vaultExists();
      res.json({
        locked: !this.vaultManager.isUnlocked(),
        vaultExists: exists,
      });
    });

    // Get challenge info for signing page
    this.app.get('/api/challenge/:id', (req: Request, res: Response) => {
      const challenge = this.vaultManager.getChallenge(req.params.id);
      if (!challenge) {
        res.status(404).json({ error: 'Challenge not found or expired' });
        return;
      }

      res.json({
        challenge: {
          action: challenge.action,
          host: challenge.host,
          commands: challenge.commands,
          agent: challenge.agent,
          accessRequest: challenge.accessRequest,
          expiresAt: challenge.expiresAt,
        },
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

        // Generate VEK from credential ID (deterministic for this credential)
        // For MVP, we use a fixed server secret + credential ID
        // In production, use HSM or secure key management
        const { deriveKeyFromSignature } = await import('../vault/encryption.js');
        const serverSecret = new TextEncoder().encode('ssh-vault-server-secret-' + result.credential.id);
        const salt = new TextEncoder().encode('ssh-vault-static-salt');
        const vek = deriveKeyFromSignature(serverSecret, salt.slice(0, 16));
        
        // Create vault with the credential and VEK
        await this.vaultManager.createVault(result.credential, vek);

        // Create management session so user doesn't need to auth again
        const token = crypto.randomUUID();
        manageSessions.set(token, {
          expiresAt: Date.now() + 30 * 60 * 1000, // 30 minutes
          vek,
        });

        res.json({ 
          success: true, 
          message: 'Registration successful. Vault created.',
          credentialId: result.credential.id,
          token,  // Return session token
        });
      } catch (error) {
        res.status(500).json({ 
          error: error instanceof Error ? error.message : 'Verification failed' 
        });
      }
    });

    // Agent request host access endpoint
    this.app.post('/api/agent/request-access', async (req: Request, res: Response) => {
      try {
        const { name, publicKey, requestedHosts } = req.body;
        
        if (!name || !publicKey) {
          res.status(400).json({ error: 'name and publicKey required' });
          return;
        }

        if (!requestedHosts || requestedHosts.length === 0) {
          res.status(400).json({ error: 'requestedHosts required' });
          return;
        }

        // Import fingerprint function
        const { fingerprintFromPublicKey } = await import('../auth/agent.js');
        
        let fingerprint: string;
        try {
          fingerprint = fingerprintFromPublicKey(publicKey);
        } catch {
          res.status(400).json({ error: 'Invalid public key format' });
          return;
        }

        // Create access request challenge (agent will be auto-enlisted if not exists)
        const result = this.vaultManager.createAccessRequestChallenge(
          this.config.web.externalUrl,
          {
            name,
            fingerprint,
            publicKey,
            requestedHosts,
          }
        );

        res.json({
          status: 'pending_approval',
          fingerprint,
          approvalUrl: result.approvalUrl,
          listenUrl: result.listenUrl,
          challengeId: result.challengeId,
          expiresAt: result.expiresAt,
        });
      } catch (error) {
        res.status(500).json({ 
          error: error instanceof Error ? error.message : 'Request failed' 
        });
      }
    });

    // Authentication endpoints
    this.app.post('/api/auth/options', async (_req: Request, res: Response) => {
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
        const { webauthnChallengeId, vaultChallengeId, response, allowedHosts } = req.body;
        
        if (!webauthnChallengeId || !vaultChallengeId || !response) {
          res.status(400).json({ 
            error: 'webauthnChallengeId, vaultChallengeId, and response required' 
          });
          return;
        }

        // If allowedHosts is provided, update the challenge before completing
        if (allowedHosts && Array.isArray(allowedHosts)) {
          this.vaultManager.updateChallengeHosts(vaultChallengeId, allowedHosts);
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

        if (!result.success) {
          res.status(400).json({ error: result.error || 'Verification failed' });
          return;
        }

        // Derive VEK using same method as registration
        const { deriveKeyFromSignature } = await import('../vault/encryption.js');
        const serverSecret = new TextEncoder().encode('ssh-vault-server-secret-' + metadata.credentialId);
        const salt = new TextEncoder().encode('ssh-vault-static-salt');
        const vek = deriveKeyFromSignature(serverSecret, salt.slice(0, 16));

        // Complete vault challenge with VEK (auto-unlock if agent is listening)
        const unlockResult = await this.vaultManager.completeChallenge(
          vaultChallengeId,
          vek,
          true  // autoUnlock
        );

        if (!unlockResult) {
          res.status(400).json({ error: 'Vault challenge expired or not found' });
          return;
        }

        if (unlockResult.autoUnlocked) {
          res.json({
            success: true,
            autoUnlocked: true,
            sessionId: unlockResult.sessionId,
            message: 'Authentication successful. Agent has been notified.',
          });
        } else {
          res.json({
            success: true,
            unlockCode: unlockResult.unlockCode,
            message: 'Authentication successful. Use this code to unlock the vault.',
          });
        }
      } catch (error) {
        res.status(500).json({ 
          error: error instanceof Error ? error.message : 'Verification failed' 
        });
      }
    });

    // SSE endpoint for listening to challenge completion
    this.app.get('/api/challenge/:id/listen', (req: Request, res: Response) => {
      const challengeId = req.params.id;
      
      // Check if challenge exists
      const challenge = this.vaultManager.getChallenge(challengeId);
      if (!challenge) {
        res.status(404).json({ error: 'Challenge not found or expired' });
        return;
      }

      // Set up SSE
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.setHeader('X-Accel-Buffering', 'no'); // For nginx
      
      // Send initial connection event
      res.write(`data: ${JSON.stringify({ type: 'connected', challengeId })}\n\n`);

      // Subscribe to challenge events
      const unsubscribe = this.vaultManager.subscribeToChallenge(challengeId, (event) => {
        res.write(`data: ${JSON.stringify(event)}\n\n`);
        
        // Close connection after approval
        if (event.type === 'approved' || event.type === 'error') {
          res.end();
        }
      });

      // Handle client disconnect
      req.on('close', () => {
        unsubscribe();
      });

      // Timeout after challenge expires
      const timeoutMs = challenge.expiresAt - Date.now();
      if (timeoutMs > 0) {
        setTimeout(() => {
          res.write(`data: ${JSON.stringify({ type: 'expired', challengeId })}\n\n`);
          res.end();
          unsubscribe();
        }, timeoutMs);
      }
    });

    // Management API endpoints
    const manageSessions = new Map<string, { expiresAt: number; vek: Uint8Array }>();

    // Check if management session is valid
    this.app.get('/api/manage/check', (req: Request, res: Response) => {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (token && manageSessions.has(token)) {
        const session = manageSessions.get(token)!;
        if (session.expiresAt > Date.now()) {
          res.json({ authenticated: true });
          return;
        }
        manageSessions.delete(token);
      }
      res.json({ authenticated: false });
    });

    // Authenticate for management
    this.app.post('/api/manage/auth', async (req: Request, res: Response) => {
      try {
        const { challengeId, response } = req.body;
        
        const metadata = await this.vaultManager.getMetadata();
        if (!metadata) {
          res.status(404).json({ error: 'No vault found' });
          return;
        }

        const result = await this.webauthn.verifyAuthentication(
          challengeId,
          response,
          {
            id: metadata.credentialId,
            publicKey: metadata.publicKey,
            algorithm: metadata.algorithm,
            counter: 0,
            createdAt: 0,
          }
        );

        if (!result.success) {
          res.status(401).json({ error: result.error || 'Auth failed' });
          return;
        }

        // Derive VEK and create management session
        const { deriveKeyFromSignature } = await import('../vault/encryption.js');
        const serverSecret = new TextEncoder().encode('ssh-vault-server-secret-' + metadata.credentialId);
        const salt = new TextEncoder().encode('ssh-vault-static-salt');
        const vek = deriveKeyFromSignature(serverSecret, salt.slice(0, 16));

        const token = crypto.randomUUID();
        manageSessions.set(token, {
          expiresAt: Date.now() + 30 * 60 * 1000, // 30 minutes
          vek,
        });

        res.json({ success: true, token });
      } catch (error) {
        res.status(500).json({ error: error instanceof Error ? error.message : 'Auth failed' });
      }
    });

    // Get vault data
    this.app.get('/api/manage/data', async (req: Request, res: Response) => {
      const token = req.headers.authorization?.replace('Bearer ', '');
      const session = token ? manageSessions.get(token) : null;
      
      if (!session || session.expiresAt < Date.now()) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      try {
        const { VaultStorage } = await import('../vault/storage.js');
        const storage = new VaultStorage(this.config.vault.path, false);
        const vault = await storage.load(session.vek);

        res.json({
          hosts: vault.hosts.map(h => ({ ...h, credential: '***' })), // Hide credentials
          agents: vault.agents,
          sessions: [], // TODO: get from vault manager
        });
      } catch (error) {
        res.status(500).json({ error: 'Failed to load vault' });
      }
    });

    // Add host
    this.app.post('/api/manage/hosts', async (req: Request, res: Response) => {
      const token = req.headers.authorization?.replace('Bearer ', '');
      const session = token ? manageSessions.get(token) : null;
      
      if (!session || session.expiresAt < Date.now()) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      try {
        const { VaultStorage } = await import('../vault/storage.js');
        const storage = new VaultStorage(this.config.vault.path, true);
        const vault = await storage.load(session.vek);

        const newHost = {
          id: crypto.randomUUID(),
          name: req.body.name,
          hostname: req.body.hostname,
          port: req.body.port || 22,
          username: req.body.username,
          authType: req.body.authType || 'key',
          credential: req.body.credential || '',
          tags: req.body.tags || [],
          createdAt: Date.now(),
          updatedAt: Date.now(),
        };

        vault.hosts.push(newHost);
        await storage.save(vault, session.vek);

        res.json({ success: true, host: { ...newHost, credential: '***' } });
      } catch (error) {
        res.status(500).json({ error: 'Failed to add host' });
      }
    });

    // Delete host
    this.app.delete('/api/manage/hosts/:id', async (req: Request, res: Response) => {
      const token = req.headers.authorization?.replace('Bearer ', '');
      const session = token ? manageSessions.get(token) : null;
      
      if (!session || session.expiresAt < Date.now()) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      try {
        const { VaultStorage } = await import('../vault/storage.js');
        const storage = new VaultStorage(this.config.vault.path, true);
        const vault = await storage.load(session.vek);

        vault.hosts = vault.hosts.filter(h => h.id !== req.params.id);
        await storage.save(vault, session.vek);

        res.json({ success: true });
      } catch (error) {
        res.status(500).json({ error: 'Failed to delete host' });
      }
    });

    // Add agent
    this.app.post('/api/manage/agents', async (req: Request, res: Response) => {
      const token = req.headers.authorization?.replace('Bearer ', '');
      const session = token ? manageSessions.get(token) : null;
      
      if (!session || session.expiresAt < Date.now()) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      try {
        const { VaultStorage } = await import('../vault/storage.js');
        const storage = new VaultStorage(this.config.vault.path, true);
        const vault = await storage.load(session.vek);

        const newAgent = {
          fingerprint: req.body.fingerprint,
          name: req.body.name,
          allowedHosts: req.body.allowedHosts || [],
          allowedCommands: req.body.allowedCommands || [],
          deniedCommands: req.body.deniedCommands || [],
          createdAt: Date.now(),
          lastUsed: Date.now(),
        };

        vault.agents.push(newAgent);
        await storage.save(vault, session.vek);

        res.json({ success: true, agent: newAgent });
      } catch (error) {
        res.status(500).json({ error: 'Failed to add agent' });
      }
    });

    // Delete agent
    this.app.delete('/api/manage/agents/:fingerprint', async (req: Request, res: Response) => {
      const token = req.headers.authorization?.replace('Bearer ', '');
      const session = token ? manageSessions.get(token) : null;
      
      if (!session || session.expiresAt < Date.now()) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      try {
        const { VaultStorage } = await import('../vault/storage.js');
        const storage = new VaultStorage(this.config.vault.path, true);
        const vault = await storage.load(session.vek);

        vault.agents = vault.agents.filter(a => a.fingerprint !== req.params.fingerprint);
        await storage.save(vault, session.vek);

        res.json({ success: true });
      } catch (error) {
        res.status(500).json({ error: 'Failed to delete agent' });
      }
    });

    // Lock vault (clear management session)
    this.app.post('/api/manage/lock', (req: Request, res: Response) => {
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (token) {
        manageSessions.delete(token);
      }
      res.json({ success: true });
    });

    // Main page - serve manage
    this.app.get('/', (_req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '../../web/manage.html'));
    });

    // Serve signing page
    this.app.get('/sign', (_req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '../../web/auth.html'));
    });

    this.app.get('/approve', (_req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '../../web/auth.html'));
    });

    this.app.get('/setup', (_req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '../../web/auth.html'));
    });

    // Management UI
    this.app.get('/manage', (_req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '../../web/manage.html'));
    });

    // Agent access request approval UI
    this.app.get('/request-access', (_req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '../../web/request-access.html'));
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
