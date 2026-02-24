/**
 * SSH Proxy Server
 * Agent connects with their Ed25519 key → Vault bridges to target host with stored credentials
 */

import ssh2 from 'ssh2';
const { Server, Client, utils } = ssh2;
import type { Connection, AuthContext, Session, ConnectConfig } from 'ssh2';
import net from 'net';
import crypto from 'crypto';

export interface TunnelSession {
  id: string;
  agentFingerprint: string;
  targetHost: string;
  port: number;           // Local listening port
  createdAt: number;
  expiresAt: number;
  server: InstanceType<typeof Server>;
  netServer: net.Server;
  connections: number;
}

export interface TunnelRequest {
  agentFingerprint: string;
  agentPublicKey: string;  // base64 Ed25519 public key
  targetHost: string;
  sessionId: string;       // vault session id
}

export interface HostCredentials {
  hostname: string;
  port: number;
  username: string;
  credential: string;
  authType: 'key' | 'password';
}

type GetHostCredentialsFn = (hostName: string) => Promise<HostCredentials | null>;

export class SSHProxy {
  private tunnels: Map<string, TunnelSession> = new Map();
  private hostKey: Buffer;
  private getHostCredentials: GetHostCredentialsFn;
  private portRangeStart: number;
  private portRangeEnd: number;

  constructor(
    getHostCredentials: GetHostCredentialsFn,
    _validateAgent: (fingerprint: string, sessionId: string, targetHost: string) => boolean,
    portRange: [number, number] = [9100, 9200],
  ) {
    this.getHostCredentials = getHostCredentials;
    this.portRangeStart = portRange[0];
    this.portRangeEnd = portRange[1];

    // Generate ephemeral host key for the proxy SSH server
    const keyPair = utils.generateKeyPairSync('ed25519');
    this.hostKey = Buffer.from(keyPair.private);
  }

  /**
   * Create a new tunnel for an agent to a target host
   */
  async createTunnel(request: TunnelRequest, timeoutMinutes: number = 15): Promise<TunnelSession> {
    const port = await this.findFreePort();
    const tunnelId = crypto.randomUUID();
    const agentPubKeyBuffer = Buffer.from(request.agentPublicKey, 'base64');

    // Compute fingerprint from public key to verify
    const expectedFingerprint = 'SHA256:' + crypto.createHash('sha256')
      .update(agentPubKeyBuffer).digest('base64').replace(/=+$/, '');

    if (expectedFingerprint !== request.agentFingerprint) {
      throw new Error('Agent fingerprint mismatch');
    }

    // Convert raw Ed25519 public key to SSH format for verification
    const sshPubKey = this.rawEd25519ToSSHPubKey(agentPubKeyBuffer);

    const tunnel: TunnelSession = {
      id: tunnelId,
      agentFingerprint: request.agentFingerprint,
      targetHost: request.targetHost,
      port,
      createdAt: Date.now(),
      expiresAt: Date.now() + timeoutMinutes * 60 * 1000,
      server: null as any,
      netServer: null as any,
      connections: 0,
    };

    const sshServer = new Server({
      hostKeys: [this.hostKey],
    }, (client: Connection) => {
      this.handleConnection(client, tunnel, request, sshPubKey);
    });

    const netServer = net.createServer((socket) => {
      sshServer.injectSocket(socket);
    });

    await new Promise<void>((resolve, reject) => {
      netServer.listen(port, '127.0.0.1', () => resolve());
      netServer.on('error', reject);
    });

    tunnel.server = sshServer;
    tunnel.netServer = netServer;

    this.tunnels.set(tunnelId, tunnel);

    // Auto-close on expiry
    setTimeout(() => {
      this.closeTunnel(tunnelId);
    }, timeoutMinutes * 60 * 1000);

    console.log(`[proxy] Tunnel ${tunnelId} opened on port ${port} for ${request.targetHost}`);
    return tunnel;
  }

  private handleConnection(
    client: Connection,
    tunnel: TunnelSession,
    request: TunnelRequest,
    sshPubKey: Buffer,
  ) {
    let authenticated = false;

    client.on('authentication', (ctx: AuthContext) => {
      if (ctx.method === 'publickey') {
        // Verify it's the agent's registered key
        const clientKey = (ctx as any).key;
        if (clientKey && clientKey.algo === 'ssh-ed25519') {
          const clientPubData = clientKey.data;
          if (clientPubData && sshPubKey.equals(clientPubData)) {
            if ((ctx as any).signature) {
              // Client provided a signature — verify it
              const verify = utils.parseKey(sshPubKey);
              if (verify && !(verify instanceof Error)) {
                const accepted = verify.verify(
                  (ctx as any).blob,
                  (ctx as any).signature,
                  (ctx as any).hashAlgo,
                );
                if (accepted) {
                  authenticated = true;
                  ctx.accept();
                  return;
                }
              }
            } else {
              // No signature yet — tell client this key is acceptable
              ctx.accept();
              return;
            }
          }
        }
        ctx.reject(['publickey']);
      } else {
        ctx.reject(['publickey']);
      }
    });

    client.on('ready', () => {
      if (!authenticated) { client.end(); return; }

      tunnel.connections++;
      console.log(`[proxy] Agent authenticated on tunnel ${tunnel.id}`);

      client.on('session', (accept: () => Session) => {
        const session = accept();
        this.bridgeSession(session, tunnel, request);
      });
    });

    client.on('close', () => {
      tunnel.connections = Math.max(0, tunnel.connections - 1);
    });

    client.on('error', (err) => {
      console.error(`[proxy] Client error on tunnel ${tunnel.id}:`, err.message);
    });
  }

  private async bridgeSession(
    clientSession: Session,
    tunnel: TunnelSession,
    _request: TunnelRequest,
  ) {
    clientSession.on('exec', async (accept, _reject, info) => {
      const channel = accept();
      try {
        const creds = await this.getHostCredentials(tunnel.targetHost);
        if (!creds) { 
          channel.stderr.write(`Host "${tunnel.targetHost}" not found\n`);
          channel.exit(1);
          channel.close();
          return;
        }

        const targetClient = new Client();
        const connectConfig: ConnectConfig = {
          host: creds.hostname,
          port: creds.port,
          username: creds.username,
          readyTimeout: 10000,
        };
        if (creds.authType === 'key') {
          connectConfig.privateKey = creds.credential;
        } else {
          connectConfig.password = creds.credential;
        }

        targetClient.on('ready', () => {
          targetClient.exec(info.command, (err, stream) => {
            if (err) {
              channel.stderr.write(err.message + '\n');
              channel.exit(1);
              channel.close();
              targetClient.end();
              return;
            }
            stream.pipe(channel);
            stream.stderr.pipe(channel.stderr);
            channel.pipe(stream);
            stream.on('close', (code: number) => {
              channel.exit(code || 0);
              channel.close();
              targetClient.end();
            });
          });
        });

        targetClient.on('error', (err) => {
          channel.stderr.write(`SSH error: ${err.message}\n`);
          channel.exit(1);
          channel.close();
        });

        targetClient.connect(connectConfig);
      } catch (err) {
        channel.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
        channel.exit(1);
        channel.close();
      }
    });

    // SFTP is handled via the subsystem event below

    // Handle shell sessions
    clientSession.on('shell', async (accept, reject) => {
      try {
        const creds = await this.getHostCredentials(tunnel.targetHost);
        if (!creds) { reject(); return; }

        const channel = accept();
        const targetClient = new Client();
        const connectConfig: ConnectConfig = {
          host: creds.hostname,
          port: creds.port,
          username: creds.username,
          readyTimeout: 10000,
        };
        if (creds.authType === 'key') {
          connectConfig.privateKey = creds.credential;
        } else {
          connectConfig.password = creds.credential;
        }

        targetClient.on('ready', () => {
          targetClient.shell((err, stream) => {
            if (err) { channel.close(); targetClient.end(); return; }
            stream.pipe(channel).pipe(stream);
            stream.on('close', () => { channel.close(); targetClient.end(); });
            channel.on('close', () => { stream.end(); targetClient.end(); });
          });
        });

        targetClient.on('error', (err) => {
          channel.write(`SSH error: ${err.message}\r\n`);
          channel.close();
        });

        targetClient.connect(connectConfig);
      } catch {
        reject();
      }
    });

    clientSession.on('subsystem', async (accept, reject, info) => {
      if (info.name !== 'sftp') { reject(); return; }

      try {
        const creds = await this.getHostCredentials(tunnel.targetHost);
        if (!creds) { reject(); return; }

        const targetClient = new Client();
        const connectConfig: ConnectConfig = {
          host: creds.hostname,
          port: creds.port,
          username: creds.username,
          readyTimeout: 10000,
        };
        if (creds.authType === 'key') {
          connectConfig.privateKey = creds.credential;
        } else {
          connectConfig.password = creds.credential;
        }

        targetClient.on('ready', () => {
          const clientChannel = accept();

          targetClient.subsys('sftp', (err, targetChannel) => {
            if (err) {
              clientChannel.close();
              targetClient.end();
              return;
            }
            targetChannel.pipe(clientChannel).pipe(targetChannel);
            targetChannel.on('close', () => { clientChannel.close(); targetClient.end(); });
            clientChannel.on('close', () => { targetChannel.close(); targetClient.end(); });
          });
        });

        targetClient.on('error', () => { reject(); });
        targetClient.connect(connectConfig);
      } catch {
        reject();
      }
    });
  }

  /**
   * Convert raw 32-byte Ed25519 public key to SSH wire format
   */
  private rawEd25519ToSSHPubKey(raw: Buffer): Buffer {
    const algo = Buffer.from('ssh-ed25519');
    const buf = Buffer.alloc(4 + algo.length + 4 + raw.length);
    let offset = 0;
    buf.writeUInt32BE(algo.length, offset); offset += 4;
    algo.copy(buf, offset); offset += algo.length;
    buf.writeUInt32BE(raw.length, offset); offset += 4;
    raw.copy(buf, offset);
    return buf;
  }

  /**
   * Find an available port in the configured range
   */
  private async findFreePort(): Promise<number> {
    for (let port = this.portRangeStart; port <= this.portRangeEnd; port++) {
      const inUse = Array.from(this.tunnels.values()).some(t => t.port === port);
      if (inUse) continue;

      const available = await new Promise<boolean>((resolve) => {
        const server = net.createServer();
        server.listen(port, '127.0.0.1', () => {
          server.close(() => resolve(true));
        });
        server.on('error', () => resolve(false));
      });

      if (available) return port;
    }
    throw new Error('No free ports available in range');
  }

  /**
   * Close a tunnel
   */
  closeTunnel(tunnelId: string): boolean {
    const tunnel = this.tunnels.get(tunnelId);
    if (!tunnel) return false;

    try {
      tunnel.netServer.close();
      tunnel.server.close();
    } catch {}

    this.tunnels.delete(tunnelId);
    console.log(`[proxy] Tunnel ${tunnelId} closed (port ${tunnel.port})`);
    return true;
  }

  /**
   * List active tunnels
   */
  listTunnels(): Array<{
    id: string;
    targetHost: string;
    port: number;
    agentFingerprint: string;
    connections: number;
    expiresAt: number;
  }> {
    return Array.from(this.tunnels.values()).map(t => ({
      id: t.id,
      targetHost: t.targetHost,
      port: t.port,
      agentFingerprint: t.agentFingerprint,
      connections: t.connections,
      expiresAt: t.expiresAt,
    }));
  }

  /**
   * Close all tunnels
   */
  closeAll(): void {
    for (const [id] of this.tunnels) {
      this.closeTunnel(id);
    }
  }
}
