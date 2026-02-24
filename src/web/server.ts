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
import { verifySignedRequest } from '../auth/agent.js';
import { PolicyEngine } from '../policy/engine.js';
import { SSHExecutor } from '../ssh/executor.js';
import { SSHProxy } from '../ssh/proxy.js';

// --- Rate Limiting ---
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW_MS = 5 * 60 * 1000;

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || entry.resetAt < now) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return true;
  }
  entry.count++;
  return entry.count <= RATE_LIMIT_MAX;
}

// Cleanup stale entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap.entries()) {
    if (entry.resetAt < now) rateLimitMap.delete(ip);
  }
}, 5 * 60 * 1000);

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export class WebServer {
  private app: express.Application;
  private config: Config;
  private vaultManager: VaultManager;
  private webauthn: WebAuthnManager;
  private policyEngine: PolicyEngine;
  private sshExecutor: SSHExecutor;
  private sshProxy: SSHProxy;

  constructor(config: Config, vaultManager: VaultManager) {
    this.config = config;
    this.vaultManager = vaultManager;
    this.policyEngine = new PolicyEngine();
    this.sshExecutor = new SSHExecutor();
    this.sshProxy = new SSHProxy(
      async (hostName: string) => {
        await this.vaultManager.reloadVault();
        const host = this.vaultManager.getHost(hostName);
        if (!host) return null;
        const credential = await this.vaultManager.decryptHostCredential(hostName);
        return {
          hostname: host.hostname,
          port: host.port || 22,
          username: host.username,
          credential,
          authType: (host.authType || (credential.includes('PRIVATE KEY') ? 'key' : 'password')) as 'key' | 'password',
        };
      },
      (_fingerprint, sessionId, targetHost) => {
        const session = this.vaultManager.getSession(sessionId);
        if (!session) return false;
        return session.approvedHosts.includes('*') || session.approvedHosts.includes(targetHost);
      },
    );
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
    this.app.use(express.json({ limit: '50mb' }));
    
    // Serve static files from web directory
    const webDir = path.join(__dirname, '../../web');
    this.app.use(express.static(webDir));
  }

  private setupRoutes(): void {
    // Health check
    this.app.get('/health', (_req: Request, res: Response) => {
      res.json({ status: 'ok' });
    });

    // Password strength check (client-side feedback)
    this.app.post('/api/password-strength', async (req: Request, res: Response) => {
      const { password } = req.body;
      if (!password) { res.json({ score: 0, warning: '', suggestions: [] }); return; }
      const { validatePasswordStrength } = await import('../vault/encryption.js');
      const result = validatePasswordStrength(password);
      res.json({ score: result.score, warning: result.warning, suggestions: result.suggestions, valid: result.valid });
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

    // Submit unlock code
    this.app.post('/api/vault/submit-unlock', async (req: Request, res: Response) => {
      if (!checkRateLimit(req.ip || 'unknown')) {
        res.status(429).json({ error: 'Too many attempts. Try again later.' });
        return;
      }
      const { unlockCode, agentFingerprint } = req.body;
      
      if (!unlockCode) {
        res.status(400).json({ error: 'unlockCode required' });
        return;
      }

      const result = await this.vaultManager.submitUnlockCode(
        unlockCode,
        agentFingerprint || 'SHA256:unknown-agent'
      );

      if (result.success) {
        res.json({
          success: true,
          sessionId: result.sessionId,
          expiresAt: result.expiresAt,
          message: 'Vault unlocked successfully',
        });
      } else {
        res.status(400).json({ error: result.error });
      }
    });

    // Check vault status
    this.app.get('/api/vault/status', async (_req: Request, res: Response) => {
      const exists = await this.vaultManager.vaultExists();
      res.json({
        locked: !this.vaultManager.isUnlocked(),
        vaultExists: exists,
      });
    });

    // List agent's approved hosts (works even when vault is locked)
    this.app.get('/api/agent/hosts', async (req: Request, res: Response) => {
      const { fingerprint, signature, timestamp, nonce, publicKey } = req.query as Record<string, string>;

      if (!fingerprint || !signature || !timestamp || !nonce || !publicKey) {
        res.status(401).json({ error: 'Agent signature required (fingerprint, publicKey, signature, timestamp, nonce)' });
        return;
      }

      try {
        const { verifySignedRequest, fingerprintFromPublicKey } = await import('../auth/agent.js');
        const verified = verifySignedRequest({
          signature, publicKey, timestamp: Number(timestamp), nonce,
          payload: `list_hosts:${timestamp}`
        });
        if (!verified) {
          res.status(401).json({ error: 'Invalid signature' });
          return;
        }

        const derivedFp = fingerprintFromPublicKey(publicKey);
        if (derivedFp !== fingerprint) {
          res.status(401).json({ error: 'Fingerprint mismatch' });
          return;
        }

        const session = this.vaultManager.getSessionByAgent(fingerprint);
        if (!session) {
          res.status(403).json({ error: 'No active session. Use /api/agent/request-access first.' });
          return;
        }

        res.json({
          hosts: session.approvedHosts,
          sessionId: session.id,
          expiresAt: session.expiresAt,
        });
      } catch (error) {
        res.status(500).json({ error: 'Internal error' });
      }
    });

    // Execute SSH command
    this.app.post('/api/vault/execute', async (req: Request, res: Response) => {
      const { host, command, sessionId, signature, publicKey, timestamp, nonce, timeout } = req.body;

      if (!host || !command) {
        res.status(400).json({ error: 'host and command required' });
        return;
      }

      // Require agent signature verification
      if (!signature || !publicKey || !timestamp || !nonce) {
        res.status(401).json({ error: 'Agent signature required (signature, publicKey, timestamp, nonce)' });
        return;
      }

      const verification = verifySignedRequest({
        payload: JSON.stringify({ host, command }),
        signature,
        publicKey,
        timestamp,
        nonce,
      });

      if (!verification.valid) {
        res.status(401).json({ error: `Signature verification failed: ${verification.error}` });
        return;
      }

      // Auto-access flow: if no session or vault locked, create approval challenge
      const needsUnlock = !this.vaultManager.isUnlocked();
      let session = sessionId ? this.vaultManager.getSession(sessionId) : null;
      const needsSession = !session || (session && session.agentFingerprint !== verification.fingerprint);

      if (needsUnlock || needsSession) {
        // Create exec-request for one-step approve-and-execute flow
        const execReqId = crypto.randomUUID();
        const expiresAt = Date.now() + 5 * 60 * 1000;
        pendingExecRequests.set(execReqId, {
          id: execReqId,
          host,
          command,
          agentFingerprint: verification.fingerprint!,
          timeout: timeout || 30,
          signature: { signature, publicKey, timestamp, nonce },
          status: 'pending',
          expiresAt,
          listeners: new Set(),
        });
        const approvalUrl = `${this.config.web.externalUrl}/approve-exec?id=${execReqId}`;
        const listenUrl = `${this.config.web.externalUrl}/api/vault/exec-request/${execReqId}/listen`;
        res.status(401).json({
          error: needsUnlock ? 'Vault is locked' : 'No valid session',
          needsApproval: true,
          execRequestId: execReqId,
          approvalUrl,
          listenUrl,
          expiresAt,
          message: 'User approval required. Present the approvalUrl to the user and listen on listenUrl for the result.',
        });
        return;
      }

      if (!session) {
        res.status(401).json({ error: 'Invalid session' });
        return;
      }

      // Validate timeout
      let execTimeout = 30;
      if (timeout !== undefined) {
        const t = Number(timeout);
        if (!Number.isFinite(t) || t <= 0) {
          execTimeout = 30;
        } else {
          execTimeout = Math.min(Math.max(t, 1), 300);
        }
      }

      // Check dangerous patterns
      const dangerCheck = this.policyEngine.checkDangerousPatterns(command);
      if (dangerCheck.dangerous) {
        res.status(403).json({ error: `Dangerous command blocked: ${dangerCheck.patterns.join(', ')}` });
        return;
      }

      // Check shell injection
      const injectionCheck = this.policyEngine.checkShellInjection(command);
      if (injectionCheck.injection) {
        res.status(403).json({ error: `Shell injection detected: ${injectionCheck.patterns.join(', ')}` });
        return;
      }

      // Policy engine check
      const agent = this.vaultManager.getAgent(verification.fingerprint!);
      if (!agent) {
        res.status(403).json({ error: 'Agent not registered in vault' });
        return;
      }

      const policy = this.vaultManager.getPolicy();
      const policyCheck = this.policyEngine.checkCommand(agent, host, command, policy, session);
      if (!policyCheck.allowed) {
        res.status(403).json({ error: `Policy denied: ${policyCheck.reason}` });
        return;
      }

      try {
        // Reload vault to get latest config (credentials stripped)
        await this.vaultManager.reloadVault();
        
        // Get host config from vault (credential will be '[encrypted]')
        const hostConfig = this.vaultManager.getHost(host);
        if (!hostConfig) {
          res.status(404).json({ error: `Host '${host}' not found` });
          return;
        }

        // Decrypt credential on-demand
        const { secureWipe: wipe } = await import('../vault/encryption.js');
        let credential: string;
        try {
          credential = await this.vaultManager.decryptHostCredential(host);
        } catch (err) {
          res.status(500).json({ error: 'Failed to decrypt credential: ' + (err instanceof Error ? err.message : String(err)) });
          return;
        }

        // Execute SSH command
        const { Client } = await import('ssh2');
        const ssh = new Client();

        try {
          const result = await new Promise<{ stdout: string; stderr: string; code: number }>((resolve, reject) => {
            ssh.on('ready', () => {
              ssh.exec(command, (err, stream) => {
                if (err) {
                  ssh.end();
                  reject(err);
                  return;
                }

                let stdout = '';
                let stderr = '';

                stream.on('data', (data: Buffer) => { stdout += data.toString(); });
                stream.stderr.on('data', (data: Buffer) => { stderr += data.toString(); });
                stream.on('close', (code: number) => {
                  ssh.end();
                  resolve({ stdout, stderr, code });
                });
              });
            });

            ssh.on('error', reject);

            const connectConfig: any = {
              host: hostConfig.hostname,
              port: hostConfig.port || 22,
              username: hostConfig.username,
            };

            console.log('[execute] authType:', hostConfig.authType);
            if (hostConfig.authType === 'key' || credential.includes('PRIVATE KEY')) {
              connectConfig.privateKey = credential;
              console.log('[execute] Using SSH key auth');
            } else if (credential) {
              connectConfig.password = credential;
              console.log('[execute] Using password auth');
            } else {
              console.log('[execute] No credential configured!');
            }

            connectConfig.readyTimeout = execTimeout * 1000;
            console.log('[execute] Connecting to:', connectConfig.host, connectConfig.port, connectConfig.username);
            ssh.connect(connectConfig);

            // Command timeout
            setTimeout(() => {
              ssh.end();
              reject(new Error(`Command timed out after ${execTimeout}s`));
            }, execTimeout * 1000);
          });

          // Prolong session on successful execution
          this.vaultManager.touchSession(sessionId);

          res.json({
            success: true,
            host,
            command,
            stdout: result.stdout,
            stderr: result.stderr,
            exitCode: result.code,
          });
        } finally {
          // Securely wipe credential from memory
          const credBuf = Buffer.from(credential);
          const credArr = new Uint8Array(credBuf.buffer, credBuf.byteOffset, credBuf.byteLength);
          wipe(credArr);
        }
      } catch (error) {
        console.error('[execute] Error:', error);
        res.status(500).json({ 
          error: 'Command execution failed: ' + (error instanceof Error ? error.message : String(error))
        });
      }
    });

    // SFTP file upload
    this.app.post('/api/vault/upload', async (req: Request, res: Response) => {
      const { host, remotePath, content, sessionId, signature, publicKey, timestamp, nonce } = req.body;

      if (!host || !remotePath || !content) {
        res.status(400).json({ error: 'host, remotePath, and content (base64) required' });
        return;
      }

      if (!signature || !publicKey || !timestamp || !nonce) {
        res.status(401).json({ error: 'Agent signature required' });
        return;
      }

      const verification = verifySignedRequest({
        payload: JSON.stringify({ host, remotePath }),
        signature, publicKey, timestamp, nonce,
      });

      if (!verification.valid) {
        res.status(401).json({ error: `Signature verification failed: ${verification.error}` });
        return;
      }

      if (!sessionId) {
        res.status(400).json({ error: 'sessionId required' });
        return;
      }

      const session = this.vaultManager.getSession(sessionId);
      if (!session || !session.approvedHosts.includes('*') && !session.approvedHosts.includes(host)) {
        res.status(403).json({ error: 'No access to this host' });
        return;
      }

      try {
        await this.vaultManager.reloadVault();
        const hostConfig = this.vaultManager.getHost(host);
        if (!hostConfig) { res.status(404).json({ error: `Host "${host}" not found` }); return; }

        const credential = await this.vaultManager.decryptHostCredential(host);
        const hostForSftp = { ...hostConfig, credential, authType: hostConfig.authType || (credential.includes('PRIVATE KEY') ? 'key' : 'password') };

        const contentBuffer = Buffer.from(content, 'base64');
        const MAX_UPLOAD_SIZE = 50 * 1024 * 1024; // 50MB
        if (contentBuffer.length > MAX_UPLOAD_SIZE) {
          res.status(413).json({ error: `File too large: ${(contentBuffer.length / 1024 / 1024).toFixed(1)}MB (max ${MAX_UPLOAD_SIZE / 1024 / 1024}MB)` });
          return;
        }
        const result = await this.sshExecutor.upload(hostForSftp as any, remotePath, contentBuffer);
        this.vaultManager.touchSession(sessionId);
        res.json({ success: result.success, bytesTransferred: result.bytesTransferred, error: result.error });
      } catch (error) {
        res.status(500).json({ error: 'Upload failed: ' + (error instanceof Error ? error.message : String(error)) });
      }
    });

    // SFTP file download
    this.app.post('/api/vault/download', async (req: Request, res: Response) => {
      const { host, remotePath, sessionId, signature, publicKey, timestamp, nonce } = req.body;

      if (!host || !remotePath) {
        res.status(400).json({ error: 'host and remotePath required' });
        return;
      }

      if (!signature || !publicKey || !timestamp || !nonce) {
        res.status(401).json({ error: 'Agent signature required' });
        return;
      }

      const verification = verifySignedRequest({
        payload: JSON.stringify({ host, remotePath }),
        signature, publicKey, timestamp, nonce,
      });

      if (!verification.valid) {
        res.status(401).json({ error: `Signature verification failed: ${verification.error}` });
        return;
      }

      if (!sessionId) {
        res.status(400).json({ error: 'sessionId required' });
        return;
      }

      const session = this.vaultManager.getSession(sessionId);
      if (!session || !session.approvedHosts.includes('*') && !session.approvedHosts.includes(host)) {
        res.status(403).json({ error: 'No access to this host' });
        return;
      }

      try {
        await this.vaultManager.reloadVault();
        const hostConfig = this.vaultManager.getHost(host);
        if (!hostConfig) { res.status(404).json({ error: `Host "${host}" not found` }); return; }

        const credential = await this.vaultManager.decryptHostCredential(host);
        const hostForSftp = { ...hostConfig, credential, authType: hostConfig.authType || (credential.includes('PRIVATE KEY') ? 'key' : 'password') };

        const result = await this.sshExecutor.download(hostForSftp as any, remotePath);
        this.vaultManager.touchSession(sessionId);
        if (result.success && result.content) {
          res.json({ success: true, content: result.content.toString('base64'), size: result.size });
        } else {
          res.status(404).json({ success: false, error: result.error });
        }
      } catch (error) {
        res.status(500).json({ error: 'Download failed: ' + (error instanceof Error ? error.message : String(error)) });
      }
    });

    // SFTP list files
    this.app.post('/api/vault/ls', async (req: Request, res: Response) => {
      const { host, remotePath, sessionId, signature, publicKey, timestamp, nonce } = req.body;

      if (!host || !remotePath) {
        res.status(400).json({ error: 'host and remotePath required' });
        return;
      }

      if (!signature || !publicKey || !timestamp || !nonce) {
        res.status(401).json({ error: 'Agent signature required' });
        return;
      }

      const verification = verifySignedRequest({
        payload: JSON.stringify({ host, remotePath }),
        signature, publicKey, timestamp, nonce,
      });

      if (!verification.valid) {
        res.status(401).json({ error: `Signature verification failed: ${verification.error}` });
        return;
      }

      if (!sessionId) {
        res.status(400).json({ error: 'sessionId required' });
        return;
      }

      const session = this.vaultManager.getSession(sessionId);
      if (!session || !session.approvedHosts.includes('*') && !session.approvedHosts.includes(host)) {
        res.status(403).json({ error: 'No access to this host' });
        return;
      }

      try {
        await this.vaultManager.reloadVault();
        const hostConfig = this.vaultManager.getHost(host);
        if (!hostConfig) { res.status(404).json({ error: `Host "${host}" not found` }); return; }

        const credential = await this.vaultManager.decryptHostCredential(host);
        const hostForSftp = { ...hostConfig, credential, authType: hostConfig.authType || (credential.includes('PRIVATE KEY') ? 'key' : 'password') };

        const result = await this.sshExecutor.listFiles(hostForSftp as any, remotePath);
        this.vaultManager.touchSession(sessionId);
        res.json(result);
      } catch (error) {
        res.status(500).json({ error: 'List failed: ' + (error instanceof Error ? error.message : String(error)) });
      }
    });

    // SSH Proxy tunnel - create
    this.app.post('/api/vault/tunnel', async (req: Request, res: Response) => {
      const { host, sessionId, signature, publicKey, timestamp, nonce } = req.body;

      if (!host) { res.status(400).json({ error: 'host required' }); return; }
      if (!signature || !publicKey || !timestamp || !nonce) {
        res.status(401).json({ error: 'Agent signature required' }); return;
      }

      const verification = verifySignedRequest({
        payload: JSON.stringify({ host, action: 'tunnel' }),
        signature, publicKey, timestamp, nonce,
      });

      if (!verification.valid) {
        res.status(401).json({ error: `Signature verification failed: ${verification.error}` }); return;
      }

      if (!sessionId) { res.status(400).json({ error: 'sessionId required' }); return; }

      const session = this.vaultManager.getSession(sessionId);
      if (!session || (!session.approvedHosts.includes('*') && !session.approvedHosts.includes(host))) {
        res.status(403).json({ error: 'No access to this host' }); return;
      }

      try {
        const { fingerprintFromPublicKey } = await import('../auth/agent.js');
        const fingerprint = fingerprintFromPublicKey(publicKey);

        const tunnel = await this.sshProxy.createTunnel({
          agentFingerprint: fingerprint,
          agentPublicKey: publicKey,
          targetHost: host,
          sessionId,
        });

        res.json({
          success: true,
          tunnelId: tunnel.id,
          port: tunnel.port,
          host: '127.0.0.1',
          expiresAt: tunnel.expiresAt,
          usage: {
            ssh: `ssh -p ${tunnel.port} -i <agent_key> any_user@127.0.0.1`,
            scp: `scp -P ${tunnel.port} -i <agent_key> file any_user@127.0.0.1:/path`,
            sftp: `sftp -P ${tunnel.port} -i <agent_key> any_user@127.0.0.1`,
          },
        });
      } catch (error) {
        res.status(500).json({ error: 'Failed to create tunnel: ' + (error instanceof Error ? error.message : String(error)) });
      }
    });

    // SSH Proxy tunnel - list
    this.app.get('/api/vault/tunnels', (_req: Request, res: Response) => {
      res.json({ tunnels: this.sshProxy.listTunnels() });
    });

    // SSH Proxy tunnel - close
    this.app.delete('/api/vault/tunnel/:id', async (req: Request, res: Response) => {
      const { signature, publicKey, timestamp, nonce } = req.body || {};
      if (!signature || !publicKey || !timestamp || !nonce) {
        res.status(401).json({ error: 'Agent signature required' }); return;
      }

      const verification = verifySignedRequest({
        payload: JSON.stringify({ tunnelId: req.params.id, action: 'close_tunnel' }),
        signature, publicKey, timestamp, nonce,
      });

      if (!verification.valid) {
        res.status(401).json({ error: `Signature verification failed: ${verification.error}` }); return;
      }

      const closed = this.sshProxy.closeTunnel(req.params.id);
      res.json({ success: closed });
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

    // Challenge status polling endpoint
    this.app.get('/api/challenge/:id/status', (req: Request, res: Response) => {
      const result = this.vaultManager.getChallengeStatus(req.params.id);
      res.json(result);
    });

    // Registration endpoints (for initial setup)
    this.app.post('/api/register/options', async (req: Request, res: Response) => {
      try {
        // CRITICAL-03: Prevent vault takeover by checking if vault already exists
        if (await this.vaultManager.vaultExists()) {
          res.status(403).json({ error: 'Vault already exists. Cannot re-register.' });
          return;
        }

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
      if (!checkRateLimit(req.ip || 'unknown')) {
        res.status(429).json({ error: 'Too many attempts. Try again later.' });
        return;
      }
      try {
        const { challengeId, response, password } = req.body;
        if (!challengeId || !response) {
          res.status(400).json({ error: 'challengeId and response required' });
          return;
        }
        if (!password) {
          res.status(400).json({ error: 'Master password required' });
          return;
        }

        const result = await this.webauthn.verifyRegistration(challengeId, response);
        
        if (!result.success || !result.credential) {
          res.status(400).json({ error: result.error || 'Verification failed' });
          return;
        }

        // Validate password strength
        const { deriveKeyFromPassword, generateSalt, toBase64, validatePasswordStrength, DEFAULT_KDF_PARAMS } = await import('../vault/encryption.js');
        const strengthCheck = validatePasswordStrength(password);
        if (!strengthCheck.valid) {
          res.status(400).json({ error: 'Weak password', details: strengthCheck.errors });
          return;
        }

        // Derive VEK from master password + random salt using strong KDF params
        const passwordSalt = generateSalt();
        const vek = deriveKeyFromPassword(password, passwordSalt, DEFAULT_KDF_PARAMS);
        console.log('[register] VEK derived from password, length:', vek.length);

        // Create vault with the credential, VEK, and KDF params
        await this.vaultManager.createVault(result.credential, vek, toBase64(passwordSalt), DEFAULT_KDF_PARAMS);

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

        const credentialIds = metadata.credentials.map(c => c.id);
        const { options, challengeId } = await this.webauthn.generateAuthenticationOptions(
          credentialIds
        );

        res.json({ options, challengeId });
      } catch (error) {
        res.status(500).json({ 
          error: error instanceof Error ? error.message : 'Failed to generate options' 
        });
      }
    });

    this.app.post('/api/auth/verify', async (req: Request, res: Response) => {
      if (!checkRateLimit(req.ip || 'unknown')) {
        res.status(429).json({ error: 'Too many attempts. Try again later.' });
        return;
      }
      try {
        const { webauthnChallengeId, vaultChallengeId, response, allowedHosts, password } = req.body;
        console.log('[auth/verify] Request received, hasPassword:', !!password, 'vaultChallengeId:', vaultChallengeId);
        
        if (!webauthnChallengeId || !vaultChallengeId || !response) {
          res.status(400).json({ 
            error: 'webauthnChallengeId, vaultChallengeId, and response required' 
          });
          return;
        }

        if (!password) {
          res.status(400).json({ error: 'Master password required' });
          return;
        }

        // If allowedHosts is provided, update the challenge before completing
        if (allowedHosts && Array.isArray(allowedHosts)) {
          this.vaultManager.updateChallengeHosts(vaultChallengeId, allowedHosts);
        }

        // Get public metadata for WebAuthn (no salt exposed yet)
        const metadata = await this.vaultManager.getMetadata();
        if (!metadata) {
          res.status(404).json({ error: 'No vault found' });
          return;
        }

        // Verify WebAuthn response FIRST against all registered credentials
        // (before accessing any sensitive data like passwordSalt)
        const allCredentials = metadata.credentials;
        let result: any = { success: false, error: 'No matching credential' };
        for (const cred of allCredentials) {
          result = await this.webauthn.verifyAuthentication(
            webauthnChallengeId,
            response,
            {
              id: cred.id,
              publicKey: cred.publicKey,
              algorithm: cred.algorithm,
              counter: 0,
              createdAt: 0,
            }
          );
          if (result.success) break;
        }

        if (!result.success) {
          res.status(400).json({ error: result.error || 'Verification failed' });
          return;
        }

        // Only AFTER WebAuthn succeeds: get salt + kdfParams for VEK derivation
        const authMeta = await this.vaultManager.getAuthMetadata();
        if (!authMeta) {
          res.status(404).json({ error: 'No vault found' });
          return;
        }
        const { deriveKeyFromPassword, fromBase64: fromB64 } = await import('../vault/encryption.js');
        const passwordSalt = fromB64(authMeta.passwordSalt);
        const vek = deriveKeyFromPassword(password, passwordSalt, authMeta.kdfParams);

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
            unlockCode: unlockResult.unlockCode, // Fallback if agent missed SSE
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
      const agentFingerprint = req.query.fingerprint as string;
      
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

      // Subscribe to challenge events, filtering sessionId unless authenticated
      const unsubscribe = this.vaultManager.subscribeToChallenge(challengeId, (event) => {
        // Only include sessionId if the listener provided the correct agent fingerprint
        const safeEvent = { ...event };
        if (safeEvent.sessionId && !agentFingerprint) {
          delete safeEvent.sessionId;
        }
        res.write(`data: ${JSON.stringify(safeEvent)}\n\n`);
        
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
    const pendingAgentRegistrations = new Map<string, {
      fingerprint: string; publicKey: string; name: string;
      expiresAt: number; status: 'pending' | 'approved' | 'rejected'; result?: any;
    }>();

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

    // Agent-initiated registration: agent requests, user approves via browser
    this.app.post('/api/agent/register', async (req: Request, res: Response) => {
      try {
        const { fingerprint, publicKey, name } = req.body;
        if (!fingerprint || !publicKey) {
          res.status(400).json({ error: 'fingerprint and publicKey required' });
          return;
        }
        const challengeId = crypto.randomUUID();
        const expiresAt = Date.now() + 5 * 60 * 1000; // 5 min

        pendingAgentRegistrations.set(challengeId, {
          fingerprint,
          publicKey,
          name: name || 'Unnamed Agent',
          expiresAt,
          status: 'pending',
        });

        // Clean up expired registrations
        for (const [id, reg] of pendingAgentRegistrations) {
          if (reg.expiresAt < Date.now()) pendingAgentRegistrations.delete(id);
        }

        const approvalUrl = `${this.config.web.externalUrl}/approve-agent?id=${challengeId}`;
        const listenUrl = `${this.config.web.externalUrl}/api/agent/register/${challengeId}/listen`;

        res.json({
          status: 'pending',
          challengeId,
          approvalUrl,
          listenUrl,
          expiresAt,
        });
      } catch (error) {
        res.status(500).json({ error: error instanceof Error ? error.message : 'Failed' });
      }
    });

    // SSE endpoint: agent polls for registration approval
    this.app.get('/api/agent/register/:id/listen', (req: Request, res: Response) => {
      const reg = pendingAgentRegistrations.get(req.params.id);
      if (!reg || reg.expiresAt < Date.now()) {
        res.status(404).json({ error: 'Registration not found or expired' });
        return;
      }

      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.flushHeaders();

      const interval = setInterval(() => {
        const current = pendingAgentRegistrations.get(req.params.id);
        if (!current || current.expiresAt < Date.now()) {
          res.write('data: {"status":"expired"}\n\n');
          clearInterval(interval);
          res.end();
          return;
        }
        if (current.status === 'approved') {
          res.write(`data: ${JSON.stringify({ status: 'approved', agent: current.result })}\n\n`);
          clearInterval(interval);
          pendingAgentRegistrations.delete(req.params.id);
          res.end();
          return;
        }
        if (current.status === 'rejected') {
          res.write('data: {"status":"rejected"}\n\n');
          clearInterval(interval);
          pendingAgentRegistrations.delete(req.params.id);
          res.end();
          return;
        }
        res.write('data: {"status":"pending"}\n\n');
      }, 2000);

      req.on('close', () => clearInterval(interval));
    });

    // User approves agent registration (requires manage auth)
    this.app.post('/api/agent/register/:id/approve', async (req: Request, res: Response) => {
      const token = req.headers.authorization?.replace('Bearer ', '');
      const session = token ? manageSessions.get(token) : null;

      if (!session || session.expiresAt < Date.now()) {
        res.status(401).json({ error: 'Unauthorized - authenticate first' });
        return;
      }

      const reg = pendingAgentRegistrations.get(req.params.id);
      if (!reg || reg.expiresAt < Date.now()) {
        res.status(404).json({ error: 'Registration not found or expired' });
        return;
      }

      try {
        const { VaultStorage } = await import('../vault/storage.js');
        const storage = new VaultStorage(this.config.vault.path, true);
        const vault = await storage.load(session.vek);

        // Check if agent already exists
        if (vault.agents.find(a => a.fingerprint === reg.fingerprint)) {
          reg.status = 'approved';
          reg.result = vault.agents.find(a => a.fingerprint === reg.fingerprint);
          res.json({ success: true, message: 'Agent already registered' });
          return;
        }

        const allowedHosts = req.body.allowedHosts || ['*'];
        const newAgent = {
          fingerprint: reg.fingerprint,
          publicKey: reg.publicKey,
          name: reg.name,
          allowedHosts,
          allowedCommands: req.body.allowedCommands || [],
          deniedCommands: req.body.deniedCommands || [],
          createdAt: Date.now(),
          lastUsed: Date.now(),
        };

        vault.agents.push(newAgent);
        await storage.save(vault, session.vek);

        reg.status = 'approved';
        reg.result = newAgent;

        console.error('[agent-register] Agent approved:', reg.fingerprint, reg.name);
        res.json({ success: true, agent: newAgent });
      } catch (error) {
        res.status(500).json({ error: error instanceof Error ? error.message : 'Failed' });
      }
    });

    // User rejects agent registration
    this.app.post('/api/agent/register/:id/reject', (req: Request, res: Response) => {
      const reg = pendingAgentRegistrations.get(req.params.id);
      if (!reg) {
        res.status(404).json({ error: 'Not found' });
        return;
      }
      reg.status = 'rejected';
      res.json({ success: true });
    });

    // Agent-initiated host addition: agent requests, user approves via browser
    const pendingHostRequests = new Map<string, {
      name: string; host: string; port: number; username: string; credential: string; authType: string;
      expiresAt: number; status: 'pending' | 'approved' | 'rejected'; result?: any;
    }>();

    this.app.post('/api/agent/request-host', (req: Request, res: Response) => {
      try {
        const { name, host, port, username, credential, authType } = req.body;
        if (!name || !host || !username) {
          res.status(400).json({ error: 'name, host, and username required' });
          return;
        }
        const challengeId = crypto.randomUUID();
        const expiresAt = Date.now() + 5 * 60 * 1000; // 5 min

        pendingHostRequests.set(challengeId, {
          name, host, port: port || 22, username, credential: credential || '', authType: authType || 'password',
          expiresAt, status: 'pending',
        });

        // Clean expired
        for (const [id, req] of pendingHostRequests) {
          if (req.expiresAt < Date.now()) pendingHostRequests.delete(id);
        }

        res.json({
          status: 'pending',
          challengeId,
          approvalUrl: `${this.config.web.externalUrl}/approve-host?id=${challengeId}`,
          listenUrl: `${this.config.web.externalUrl}/api/agent/request-host/${challengeId}/listen`,
          expiresAt,
        });
      } catch (error) {
        res.status(500).json({ error: error instanceof Error ? error.message : 'Failed' });
      }
    });

    // SSE: agent polls for host approval
    this.app.get('/api/agent/request-host/:id/listen', (req: Request, res: Response) => {
      const hr = pendingHostRequests.get(req.params.id);
      if (!hr || hr.expiresAt < Date.now()) {
        res.status(404).json({ error: 'Request not found or expired' });
        return;
      }
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.flushHeaders();

      const interval = setInterval(() => {
        const current = pendingHostRequests.get(req.params.id);
        if (!current || current.expiresAt < Date.now()) {
          res.write('data: {"status":"expired"}\n\n');
          clearInterval(interval);
          res.end();
          return;
        }
        if (current.status === 'approved') {
          res.write(`data: ${JSON.stringify({ status: 'approved', host: current.result })}\n\n`);
          clearInterval(interval);
          pendingHostRequests.delete(req.params.id);
          res.end();
          return;
        }
        if (current.status === 'rejected') {
          res.write('data: {"status":"rejected"}\n\n');
          clearInterval(interval);
          pendingHostRequests.delete(req.params.id);
          res.end();
          return;
        }
        res.write('data: {"status":"pending"}\n\n');
      }, 2000);
      req.on('close', () => clearInterval(interval));
    });

    // Get pending host request info (no sensitive data exposed)
    this.app.get('/api/agent/request-host/:id', (req: Request, res: Response) => {
      const hr = pendingHostRequests.get(req.params.id);
      if (!hr || hr.expiresAt < Date.now()) {
        res.status(404).json({ error: 'Request not found or expired' });
        return;
      }
      res.json({
        name: hr.name, host: hr.host, port: hr.port, username: hr.username,
        authType: hr.authType, status: hr.status, expiresAt: hr.expiresAt,
        hasCredential: !!hr.credential,
        // credential NOT exposed
      });
    });

    // User approves host addition (requires manage auth)
    this.app.post('/api/agent/request-host/:id/approve', async (req: Request, res: Response) => {
      const token = req.headers.authorization?.replace('Bearer ', '');
      const session = token ? manageSessions.get(token) : null;
      if (!session || session.expiresAt < Date.now()) {
        res.status(401).json({ error: 'Unauthorized - authenticate first' });
        return;
      }
      const hr = pendingHostRequests.get(req.params.id);
      if (!hr || hr.expiresAt < Date.now()) {
        res.status(404).json({ error: 'Request not found or expired' });
        return;
      }
      try {
        // User can provide/override credential and authType during approval
        const userCredential = req.body.credential;
        const userAuthType = req.body.authType;
        const finalCredential = userCredential || hr.credential;
        const finalAuthType = userAuthType || hr.authType;

        if (!finalCredential) {
          res.status(400).json({ error: 'Credential (password or key) is required. Agent did not provide one — please enter it.' });
          return;
        }

        const { VaultStorage } = await import('../vault/storage.js');
        const storage = new VaultStorage(this.config.vault.path, true);
        const vault = await storage.load(session.vek);

        const hostId = crypto.randomUUID();
        const newHost = {
          id: hostId,
          name: hr.name,
          hostname: hr.host,
          host: hr.host,
          port: hr.port,
          username: hr.username,
          credential: finalCredential,
          authType: finalAuthType as 'key' | 'password',
          tags: [] as string[],
          createdAt: Date.now(),
          updatedAt: Date.now(),
        };

        vault.hosts.push(newHost);
        await storage.save(vault, session.vek);

        hr.status = 'approved';
        hr.result = { id: hostId, name: hr.name, host: hr.host };

        console.error('[host-request] Host approved:', hr.name, hr.host);
        res.json({ success: true, host: hr.result });
      } catch (error) {
        res.status(500).json({ error: error instanceof Error ? error.message : 'Failed' });
      }
    });

    // User rejects host request
    this.app.post('/api/agent/request-host/:id/reject', (req: Request, res: Response) => {
      const hr = pendingHostRequests.get(req.params.id);
      if (!hr) { res.status(404).json({ error: 'Not found' }); return; }
      hr.status = 'rejected';
      res.json({ success: true });
    });

    // --- Exec Request (approve-and-execute in one flow) ---
    const pendingExecRequests = new Map<string, {
      id: string;
      host: string;
      command: string;
      agentFingerprint: string;
      timeout: number;
      signature: { signature: string; publicKey: string; timestamp: number; nonce: string };
      status: 'pending' | 'approved' | 'executing' | 'completed' | 'failed' | 'rejected';
      stdout?: string;
      stderr?: string;
      exitCode?: number;
      error?: string;
      sessionId?: string;
      expiresAt: number;
      listeners: Set<(event: any) => void>;
    }>();

    // Cleanup expired exec requests periodically
    setInterval(() => {
      const now = Date.now();
      for (const [id, req] of pendingExecRequests) {
        if (req.expiresAt < now) pendingExecRequests.delete(id);
      }
    }, 60 * 1000);

    // Get exec request info
    this.app.get('/api/vault/exec-request/:id', (req: Request, res: Response) => {
      const er = pendingExecRequests.get(req.params.id);
      if (!er || er.expiresAt < Date.now()) {
        res.status(404).json({ error: 'Request not found or expired' });
        return;
      }
      const result: any = {
        id: er.id,
        host: er.host,
        command: er.command,
        status: er.status,
        expiresAt: er.expiresAt,
      };
      if (er.status === 'completed' || er.status === 'failed') {
        result.stdout = er.stdout;
        result.stderr = er.stderr;
        result.exitCode = er.exitCode;
        result.error = er.error;
        result.sessionId = er.sessionId;
      }
      res.json(result);
    });

    // SSE listen for exec request status
    this.app.get('/api/vault/exec-request/:id/listen', (req: Request, res: Response) => {
      const er = pendingExecRequests.get(req.params.id);
      if (!er || er.expiresAt < Date.now()) {
        res.status(404).json({ error: 'Request not found or expired' });
        return;
      }

      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.setHeader('X-Accel-Buffering', 'no');
      res.flushHeaders();

      res.write(`data: ${JSON.stringify({ status: er.status })}\n\n`);

      // If already done, send result and close
      if (er.status === 'completed' || er.status === 'failed' || er.status === 'rejected') {
        res.write(`data: ${JSON.stringify({
          status: er.status, stdout: er.stdout, stderr: er.stderr,
          exitCode: er.exitCode, error: er.error, sessionId: er.sessionId,
        })}\n\n`);
        res.end();
        return;
      }

      const listener = (event: any) => {
        try { res.write(`data: ${JSON.stringify(event)}\n\n`); } catch {}
        if (event.status === 'completed' || event.status === 'failed' || event.status === 'rejected') {
          try { res.end(); } catch {}
        }
      };
      er.listeners.add(listener);

      req.on('close', () => { er.listeners.delete(listener); });

      // Timeout
      const timeoutMs = er.expiresAt - Date.now();
      if (timeoutMs > 0) {
        setTimeout(() => {
          try {
            res.write(`data: ${JSON.stringify({ status: 'expired' })}\n\n`);
            res.end();
          } catch {}
          er.listeners.delete(listener);
        }, timeoutMs);
      }
    });

    // Approve exec request (passkey + password, then execute)
    this.app.post('/api/vault/exec-request/:id/approve', async (req: Request, res: Response) => {
      if (!checkRateLimit(req.ip || 'unknown')) {
        res.status(429).json({ error: 'Too many attempts. Try again later.' });
        return;
      }

      const er = pendingExecRequests.get(req.params.id);
      if (!er || er.expiresAt < Date.now()) {
        res.status(404).json({ error: 'Request not found or expired' });
        return;
      }
      if (er.status !== 'pending') {
        res.status(400).json({ error: `Request already ${er.status}` });
        return;
      }

      const { password, webauthnChallengeId, webauthnResponse } = req.body;
      if (!password || !webauthnChallengeId || !webauthnResponse) {
        res.status(400).json({ error: 'password, webauthnChallengeId, and webauthnResponse required' });
        return;
      }

      try {
        // Step 1: Verify WebAuthn
        const metadata = await this.vaultManager.getMetadata();
        if (!metadata) { res.status(404).json({ error: 'No vault found' }); return; }

        let webauthnResult: any = { success: false, error: 'No matching credential' };
        for (const cred of metadata.credentials) {
          webauthnResult = await this.webauthn.verifyAuthentication(
            webauthnChallengeId, webauthnResponse,
            { id: cred.id, publicKey: cred.publicKey, algorithm: cred.algorithm, counter: 0, createdAt: 0 }
          );
          if (webauthnResult.success) break;
        }
        if (!webauthnResult.success) {
          res.status(401).json({ error: webauthnResult.error || 'Passkey verification failed' });
          return;
        }

        // Step 2: Derive VEK from password
        const authMeta = await this.vaultManager.getAuthMetadata();
        if (!authMeta) { res.status(404).json({ error: 'No vault found' }); return; }
        const { deriveKeyFromPassword, fromBase64, secureWipe: wipe } = await import('../vault/encryption.js');
        const passwordSalt = fromBase64(authMeta.passwordSalt);
        const vek = deriveKeyFromPassword(password, passwordSalt, authMeta.kdfParams);

        // Step 3: Verify VEK by loading vault
        const { VaultStorage } = await import('../vault/storage.js');
        const storageCheck = new VaultStorage(this.config.vault.path, false);
        try { await storageCheck.load(vek); } catch {
          res.status(401).json({ error: 'Invalid password' });
          return;
        }

        // Step 4: Unlock vault if needed & create session
        const emitStatus = (event: any) => {
          for (const listener of er.listeners) {
            try { listener(event); } catch {}
          }
        };

        er.status = 'approved';
        emitStatus({ status: 'approved' });

        // Unlock vault with VEK
        if (!this.vaultManager.isUnlocked()) {
          const uc = this.vaultManager.createUnlockChallenge(this.config.web.externalUrl, er.agentFingerprint);
          const completed = await this.vaultManager.completeChallenge(uc.challengeId, vek, true);
          if (completed?.unlockCode) {
            await this.vaultManager.submitUnlockCode(completed.unlockCode, er.agentFingerprint);
          }
        }

        if (!this.vaultManager.isUnlocked()) {
          er.status = 'failed';
          er.error = 'Failed to unlock vault';
          emitStatus({ status: 'failed', error: er.error });
          res.status(500).json({ error: 'Failed to unlock vault' });
          return;
        }

        // Create/get session for agent
        let session = this.vaultManager.getSessionByAgent(er.agentFingerprint);
        if (!session) {
          // Use the access request flow to create a session
          const accessChallenge = this.vaultManager.createAccessRequestChallenge(
            this.config.web.externalUrl,
            { name: 'exec-agent', fingerprint: er.agentFingerprint, publicKey: '', requestedHosts: [er.host, '*'] }
          );
          const accessCompleted = await this.vaultManager.completeChallenge(accessChallenge.challengeId, vek, true);
          if (accessCompleted?.unlockCode) {
            await this.vaultManager.submitUnlockCode(accessCompleted.unlockCode, er.agentFingerprint);
          }
          session = this.vaultManager.getSessionByAgent(er.agentFingerprint);
        }

        if (!session) {
          er.status = 'failed';
          er.error = 'Failed to create session';
          emitStatus({ status: 'failed', error: er.error });
          res.status(500).json({ error: 'Failed to create session' });
          return;
        }

        // Ensure host is in approved hosts
        if (!session.approvedHosts.includes('*') && !session.approvedHosts.includes(er.host)) {
          session.approvedHosts.push(er.host);
        }

        er.sessionId = session.id;

        // Step 5: Execute the command
        er.status = 'executing';
        emitStatus({ status: 'executing' });

        try {
          await this.vaultManager.reloadVault();
          const hostConfig = this.vaultManager.getHost(er.host);
          if (!hostConfig) {
            er.status = 'failed';
            er.error = `Host '${er.host}' not found`;
            emitStatus({ status: 'failed', error: er.error });
            res.json({ status: 'failed', error: er.error, sessionId: session.id });
            return;
          }

          let credential: string;
          try {
            credential = await this.vaultManager.decryptHostCredential(er.host);
          } catch (err) {
            er.status = 'failed';
            er.error = 'Failed to decrypt credential';
            emitStatus({ status: 'failed', error: er.error });
            res.json({ status: 'failed', error: er.error, sessionId: session.id });
            return;
          }

          const { Client: SSHClient } = await import('ssh2');
          const ssh = new SSHClient();
          const execTimeout = Math.min(Math.max(er.timeout, 1), 300);

          const result = await new Promise<{ stdout: string; stderr: string; code: number }>((resolve, reject) => {
            ssh.on('ready', () => {
              ssh.exec(er.command, (err, stream) => {
                if (err) { ssh.end(); reject(err); return; }
                let stdout = '';
                let stderr = '';
                stream.on('data', (data: Buffer) => { stdout += data.toString(); });
                stream.stderr.on('data', (data: Buffer) => { stderr += data.toString(); });
                stream.on('close', (code: number) => { ssh.end(); resolve({ stdout, stderr, code }); });
              });
            });
            ssh.on('error', reject);

            const connectConfig: any = {
              host: hostConfig.hostname,
              port: hostConfig.port || 22,
              username: hostConfig.username,
              readyTimeout: execTimeout * 1000,
            };
            if (hostConfig.authType === 'key' || credential.includes('PRIVATE KEY')) {
              connectConfig.privateKey = credential;
            } else {
              connectConfig.password = credential;
            }
            ssh.connect(connectConfig);
            setTimeout(() => { ssh.end(); reject(new Error(`Command timed out after ${execTimeout}s`)); }, execTimeout * 1000);
          });

          // Wipe credential
          const credBuf = Buffer.from(credential);
          const credArr = new Uint8Array(credBuf.buffer, credBuf.byteOffset, credBuf.byteLength);
          wipe(credArr);

          er.status = 'completed';
          er.stdout = result.stdout;
          er.stderr = result.stderr;
          er.exitCode = result.code;

          this.vaultManager.touchSession(session.id);

          const completedEvent = {
            status: 'completed', stdout: result.stdout, stderr: result.stderr,
            exitCode: result.code, sessionId: session.id,
          };
          emitStatus(completedEvent);
          res.json(completedEvent);

        } catch (execErr) {
          er.status = 'failed';
          er.error = execErr instanceof Error ? execErr.message : String(execErr);
          const failEvent = { status: 'failed', error: er.error, sessionId: session.id };
          emitStatus(failEvent);
          res.json(failEvent);
        }
      } catch (error) {
        er.status = 'failed';
        er.error = error instanceof Error ? error.message : 'Approval failed';
        for (const listener of er.listeners) {
          try { listener({ status: 'failed', error: er.error }); } catch {}
        }
        res.status(500).json({ error: er.error });
      }
    });

    // Reject exec request
    this.app.post('/api/vault/exec-request/:id/reject', (_req: Request, res: Response) => {
      const er = pendingExecRequests.get(_req.params.id);
      if (!er) { res.status(404).json({ error: 'Not found' }); return; }
      er.status = 'rejected';
      for (const listener of er.listeners) {
        try { listener({ status: 'rejected' }); } catch {}
      }
      res.json({ success: true });
    });

    // Serve exec approval page
    this.app.get('/approve-exec', (_req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '../../web/approve-exec.html'));
    });

    // Serve host approval page
    this.app.get('/approve-host', (_req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '../../web/approve-host.html'));
    });

    // Authenticate for management
    this.app.post('/api/manage/auth', async (req: Request, res: Response) => {
      if (!checkRateLimit(req.ip || 'unknown')) {
        res.status(429).json({ error: 'Too many attempts. Try again later.' });
        return;
      }
      try {
        const { challengeId, response, password } = req.body;
        
        if (!password) {
          res.status(400).json({ error: 'Master password required' });
          return;
        }

        // Get public metadata for WebAuthn (no salt exposed)
        const metadata = await this.vaultManager.getMetadata();
        if (!metadata) {
          res.status(404).json({ error: 'No vault found' });
          return;
        }

        // Verify WebAuthn FIRST against all registered credentials
        // (before accessing any sensitive data like passwordSalt)
        const allCredentials = metadata.credentials;
        let result: any = { success: false, error: 'No matching credential' };
        for (const cred of allCredentials) {
          result = await this.webauthn.verifyAuthentication(
            challengeId,
            response,
            {
              id: cred.id,
              publicKey: cred.publicKey,
              algorithm: cred.algorithm,
              counter: 0,
              createdAt: 0,
            }
          );
          if (result.success) break;
        }

        if (!result.success) {
          res.status(401).json({ error: result.error || 'Auth failed' });
          return;
        }

        // Only AFTER WebAuthn succeeds: get salt + kdfParams for VEK derivation
        const authMeta = await this.vaultManager.getAuthMetadata();
        if (!authMeta) {
          res.status(404).json({ error: 'No vault found' });
          return;
        }
        const { deriveKeyFromPassword, fromBase64 } = await import('../vault/encryption.js');
        const passwordSalt = fromBase64(authMeta.passwordSalt);
        const vek = deriveKeyFromPassword(password, passwordSalt, authMeta.kdfParams);
        console.log('[manage-auth] VEK derived from password, length:', vek.length);

        // Verify VEK by trying to decrypt vault
        try {
          const { VaultStorage } = await import('../vault/storage.js');
          const storage = new VaultStorage(this.config.vault.path, false);
          await storage.load(vek);
        } catch {
          res.status(401).json({ error: 'Invalid password' });
          return;
        }

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
          sessions: this.vaultManager.getActiveSessions().map(s => ({
            id: s.id,
            agentFingerprint: s.agentFingerprint,
            approvedHosts: s.approvedHosts,
            createdAt: s.createdAt,
            expiresAt: s.expiresAt,
          })),
          policy: vault.policy,
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
        console.log('[add-host] Loading vault with VEK...');
        const vault = await storage.load(session.vek);
        console.log('[add-host] Vault loaded, hosts:', vault.hosts.length);

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
        console.log('[add-host] Saving vault...');
        await storage.save(vault, session.vek);
        console.log('[add-host] Saved successfully');

        res.json({ success: true, host: { ...newHost, credential: '***' } });
      } catch (error) {
        console.error('[add-host] Error:', error);
        res.status(500).json({ error: 'Failed to add host: ' + (error instanceof Error ? error.message : String(error)) });
      }
    });

    // Update host
    this.app.put('/api/manage/hosts/:id', async (req: Request, res: Response) => {
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

        const hostIndex = vault.hosts.findIndex(h => h.id === req.params.id);
        if (hostIndex === -1) {
          res.status(404).json({ error: 'Host not found' });
          return;
        }

        // Update fields
        const host = vault.hosts[hostIndex];
        if (req.body.name) host.name = req.body.name;
        if (req.body.hostname) host.hostname = req.body.hostname;
        if (req.body.port) host.port = req.body.port;
        if (req.body.username) host.username = req.body.username;
        if (req.body.tags) host.tags = req.body.tags;
        if (req.body.credential) host.credential = req.body.credential;
        host.updatedAt = Date.now();

        await storage.save(vault, session.vek);
        res.json({ success: true, host: { ...host, credential: '***' } });
      } catch (error) {
        console.error('[update-host] Error:', error);
        res.status(500).json({ error: 'Failed to update host' });
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

      // Require passkey re-verification
      const { challengeId, webauthnResponse } = req.body || {};
      if (!challengeId || !webauthnResponse) {
        res.status(403).json({ error: 'Passkey verification required' });
        return;
      }

      try {
        const metadata = await this.vaultManager.getMetadata();
        if (!metadata) { res.status(404).json({ error: 'No vault' }); return; }

        let verified = false;
        for (const cred of metadata.credentials) {
          const result = await this.webauthn.verifyAuthentication(challengeId, webauthnResponse, {
            id: cred.id, publicKey: cred.publicKey, algorithm: cred.algorithm, counter: 0, createdAt: 0,
          });
          if (result.success) { verified = true; break; }
        }
        if (!verified) { res.status(403).json({ error: 'Passkey verification failed' }); return; }

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

    // Update global policy
    this.app.put('/api/manage/policy', async (req: Request, res: Response) => {
      const token = req.headers.authorization?.replace('Bearer ', '');
      const session = token ? manageSessions.get(token) : null;
      
      if (!session || session.expiresAt < Date.now()) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      try {
        const { allowedCommands, deniedCommands } = req.body;
        const { VaultStorage } = await import('../vault/storage.js');
        const storage = new VaultStorage(this.config.vault.path, true);
        const vault = await storage.load(session.vek);

        vault.policy = {
          allowedCommands: Array.isArray(allowedCommands) ? allowedCommands : [],
          deniedCommands: Array.isArray(deniedCommands) ? deniedCommands : [],
        };

        await storage.save(vault, session.vek);
        res.json({ success: true, policy: vault.policy });
      } catch (error) {
        console.error('[update-policy] Error:', error);
        res.status(500).json({ error: 'Failed to update policy' });
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

    // Update agent
    this.app.put('/api/manage/agents/:fingerprint', async (req: Request, res: Response) => {
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

        const agentIndex = vault.agents.findIndex(a => a.fingerprint === decodeURIComponent(req.params.fingerprint));
        if (agentIndex === -1) {
          res.status(404).json({ error: 'Agent not found' });
          return;
        }

        // Update fields
        const agent = vault.agents[agentIndex];
        if (req.body.name) agent.name = req.body.name;
        if (req.body.allowedHosts) agent.allowedHosts = req.body.allowedHosts;
        agent.lastUsed = Date.now();

        await storage.save(vault, session.vek);
        res.json({ success: true, agent });
      } catch (error) {
        console.error('[update-agent] Error:', error);
        res.status(500).json({ error: 'Failed to update agent' });
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

      // Require passkey re-verification
      const { challengeId, webauthnResponse } = req.body || {};
      if (!challengeId || !webauthnResponse) {
        res.status(403).json({ error: 'Passkey verification required' });
        return;
      }

      try {
        const metadata = await this.vaultManager.getMetadata();
        if (!metadata) { res.status(404).json({ error: 'No vault' }); return; }

        let verified = false;
        for (const cred of metadata.credentials) {
          const result = await this.webauthn.verifyAuthentication(challengeId, webauthnResponse, {
            id: cred.id, publicKey: cred.publicKey, algorithm: cred.algorithm, counter: 0, createdAt: 0,
          });
          if (result.success) { verified = true; break; }
        }
        if (!verified) { res.status(403).json({ error: 'Passkey verification failed' }); return; }

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

    // Get registered passkeys
    this.app.get('/api/manage/passkeys', async (req: Request, res: Response) => {
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
        const credentials = (vault.credentials || [vault.owner]).map(c => ({
          id: c.id,
          createdAt: c.createdAt,
          counter: c.counter,
        }));
        res.json({ credentials });
      } catch (error) {
        res.status(500).json({ error: 'Failed to load passkeys' });
      }
    });

    // Register additional passkey (requires active manage session)
    this.app.post('/api/manage/passkeys/register', async (req: Request, res: Response) => {
      const token = req.headers.authorization?.replace('Bearer ', '');
      const session = token ? manageSessions.get(token) : null;
      if (!session || session.expiresAt < Date.now()) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }
      try {
        const { options, challengeId } = await this.webauthn.generateRegistrationOptions(
          crypto.randomUUID(), 'Vault Owner'
        );
        res.json({ options, challengeId });
      } catch (error) {
        res.status(500).json({ error: error instanceof Error ? error.message : 'Failed' });
      }
    });

    this.app.post('/api/manage/passkeys/register/verify', async (req: Request, res: Response) => {
      const token = req.headers.authorization?.replace('Bearer ', '');
      const session = token ? manageSessions.get(token) : null;
      if (!session || session.expiresAt < Date.now()) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }
      try {
        const { challengeId, response } = req.body;
        const result = await this.webauthn.verifyRegistration(challengeId, response);
        if (!result.success || !result.credential) {
          res.status(400).json({ error: result.error || 'Verification failed' });
          return;
        }
        const { VaultStorage } = await import('../vault/storage.js');
        const storage = new VaultStorage(this.config.vault.path, true);
        const vault = await storage.load(session.vek);
        if (!vault.credentials) vault.credentials = [vault.owner];
        vault.credentials.push(result.credential);
        await storage.save(vault, session.vek);
        res.json({ success: true, credentialId: result.credential.id });
      } catch (error) {
        res.status(500).json({ error: error instanceof Error ? error.message : 'Failed' });
      }
    });

    // Delete a passkey
    this.app.delete('/api/manage/passkeys/:credentialId', async (req: Request, res: Response) => {
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
        if (!vault.credentials) vault.credentials = [vault.owner];
        if (vault.credentials.length <= 1) {
          res.status(400).json({ error: 'Cannot delete the last passkey' });
          return;
        }
        const targetId = decodeURIComponent(req.params.credentialId);
        vault.credentials = vault.credentials.filter(c => c.id !== targetId);
        // Update owner if deleted
        if (vault.owner.id === targetId) {
          vault.owner = vault.credentials[0];
        }
        await storage.save(vault, session.vek);
        res.json({ success: true });
      } catch (error) {
        res.status(500).json({ error: error instanceof Error ? error.message : 'Failed' });
      }
    });

    // Change master password (requires passkey verification)
    this.app.post('/api/manage/change-password', async (req: Request, res: Response) => {
      if (!checkRateLimit(req.ip || 'unknown')) {
        res.status(429).json({ error: 'Too many attempts. Try again later.' });
        return;
      }
      const token = req.headers.authorization?.replace('Bearer ', '');
      const session = token ? manageSessions.get(token) : null;
      if (!session || session.expiresAt < Date.now()) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }
      try {
        const { currentPassword, newPassword, challengeId, response: webauthnResponse } = req.body;
        if (!currentPassword || !newPassword) {
          res.status(400).json({ error: 'Both currentPassword and newPassword required' });
          return;
        }

        // Require passkey verification
        if (!challengeId || !webauthnResponse) {
          res.status(400).json({ error: 'Passkey verification required (challengeId and response)' });
          return;
        }

        // Verify WebAuthn FIRST
        const metadata = await this.vaultManager.getMetadata();
        if (!metadata) {
          res.status(404).json({ error: 'No vault found' });
          return;
        }
        const allCredentials = metadata.credentials;
        let webauthnResult: any = { success: false, error: 'No matching credential' };
        for (const cred of allCredentials) {
          webauthnResult = await this.webauthn.verifyAuthentication(
            challengeId,
            webauthnResponse,
            {
              id: cred.id,
              publicKey: cred.publicKey,
              algorithm: cred.algorithm,
              counter: 0,
              createdAt: 0,
            }
          );
          if (webauthnResult.success) break;
        }
        if (!webauthnResult.success) {
          res.status(401).json({ error: webauthnResult.error || 'Passkey verification failed' });
          return;
        }

        // Check new password strength with zxcvbn
        const { deriveKeyFromPassword, generateSalt, toBase64, fromBase64, secureWipe, validatePasswordStrength } = await import('../vault/encryption.js');
        const strengthCheck = validatePasswordStrength(newPassword);
        if (!strengthCheck.valid) {
          res.status(400).json({ error: 'Weak password', details: strengthCheck.errors, score: strengthCheck.score, suggestions: strengthCheck.suggestions });
          return;
        }

        // Verify current password
        const authMeta = await this.vaultManager.getAuthMetadata();
        if (!authMeta) {
          res.status(404).json({ error: 'No vault found' });
          return;
        }
        const oldSalt = fromBase64(authMeta.passwordSalt);
        const oldVek = deriveKeyFromPassword(currentPassword, oldSalt, authMeta.kdfParams);

        // Verify old password by trying to decrypt
        const { VaultStorage } = await import('../vault/storage.js');
        const storage = new VaultStorage(this.config.vault.path, true);
        let vault;
        try {
          vault = await storage.load(oldVek);
        } catch {
          res.status(401).json({ error: 'Current password is incorrect' });
          return;
        }

        // Derive new VEK with new password and fresh salt
        const newSalt = generateSalt();
        const { DEFAULT_KDF_PARAMS } = await import('../vault/encryption.js');
        const newVek = deriveKeyFromPassword(newPassword, newSalt, DEFAULT_KDF_PARAMS);

        // Re-encrypt vault with new VEK and upgraded KDF params
        await storage.saveWithPasswordSalt(vault, newVek, toBase64(newSalt), DEFAULT_KDF_PARAMS);

        // Update session VEK to new one
        session.vek = newVek;
        session.expiresAt = Date.now() + 30 * 60 * 1000;

        // Wipe old VEK
        secureWipe(oldVek);

        console.error('[manage] Master password changed successfully (with passkey verification)');
        res.json({ success: true });
      } catch (error) {
        res.status(500).json({ error: error instanceof Error ? error.message : 'Failed to change password' });
      }
    });

    // Reset passkey using master password (recovery flow)
    this.app.post('/api/manage/reset-passkey', async (req: Request, res: Response) => {
      if (!checkRateLimit(req.ip || 'unknown')) {
        res.status(429).json({ error: 'Too many attempts. Try again later.' });
        return;
      }
      try {
        const { password } = req.body;
        if (!password) {
          res.status(400).json({ error: 'Password required' });
          return;
        }
        // Recovery flow: password is the sole auth factor (passkey lost)
        const authMeta = await this.vaultManager.getAuthMetadata();
        if (!authMeta) {
          res.status(404).json({ error: 'No vault found' });
          return;
        }
        // Derive VEK and verify it can decrypt vault
        const { deriveKeyFromPassword, fromBase64 } = await import('../vault/encryption.js');
        const passwordSalt = fromBase64(authMeta.passwordSalt);
        const vek = deriveKeyFromPassword(password, passwordSalt, authMeta.kdfParams);
        const { VaultStorage } = await import('../vault/storage.js');
        const storage = new VaultStorage(this.config.vault.path, false);
        try {
          await storage.load(vek);
        } catch {
          res.status(401).json({ error: 'Invalid password' });
          return;
        }
        // Password valid - generate registration options for new passkey
        const { options, challengeId } = await this.webauthn.generateRegistrationOptions(
          crypto.randomUUID(), 'Vault Owner'
        );
        // Store VEK temporarily for the verify step
        const resetToken = crypto.randomUUID();
        manageSessions.set(`reset:${resetToken}`, {
          expiresAt: Date.now() + 5 * 60 * 1000, // 5 min
          vek,
        });
        res.json({ options, challengeId, resetToken });
      } catch (error) {
        res.status(500).json({ error: error instanceof Error ? error.message : 'Failed' });
      }
    });

    this.app.post('/api/manage/reset-passkey/verify', async (req: Request, res: Response) => {
      try {
        const { challengeId, response, resetToken } = req.body;
        if (!resetToken) {
          res.status(400).json({ error: 'resetToken required' });
          return;
        }
        const session = manageSessions.get(`reset:${resetToken}`);
        if (!session || session.expiresAt < Date.now()) {
          res.status(401).json({ error: 'Reset token expired' });
          return;
        }
        const result = await this.webauthn.verifyRegistration(challengeId, response);
        if (!result.success || !result.credential) {
          res.status(400).json({ error: result.error || 'Verification failed' });
          return;
        }
        // Clear all existing credentials and set new one
        const { VaultStorage } = await import('../vault/storage.js');
        const storage = new VaultStorage(this.config.vault.path, true);
        const vault = await storage.load(session.vek);
        vault.owner = result.credential;
        vault.credentials = [result.credential];
        await storage.save(vault, session.vek);
        // Clean up reset token, create manage session
        manageSessions.delete(`reset:${resetToken}`);
        const manageToken = crypto.randomUUID();
        manageSessions.set(manageToken, {
          expiresAt: Date.now() + 30 * 60 * 1000,
          vek: session.vek,
        });
        res.json({ success: true, token: manageToken, credentialId: result.credential.id });
      } catch (error) {
        res.status(500).json({ error: error instanceof Error ? error.message : 'Failed' });
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

    // Serve agent approval page
    this.app.get('/approve-agent', (_req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '../../web/approve-agent.html'));
    });

    // Get pending registration info (public, no auth needed)
    this.app.get('/api/agent/register/:id', (req: Request, res: Response) => {
      const reg = pendingAgentRegistrations.get(req.params.id);
      if (!reg || reg.expiresAt < Date.now()) {
        res.status(404).json({ error: 'Registration not found or expired' });
        return;
      }
      res.json({
        fingerprint: reg.fingerprint,
        name: reg.name,
        status: reg.status,
        expiresAt: reg.expiresAt,
      });
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
