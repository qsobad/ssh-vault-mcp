import { Client, type ClientChannel, type ConnectConfig } from 'ssh2';
import type { Host } from '../types.js';

export interface TmuxSession {
  id: string;           // "host:sessionName"
  host: string;
  sessionName: string;
  client: Client;
  channel: ClientChannel | null;
  buffer: string;       // rolling output buffer (last N chars)
  createdAt: number;
}

export class TmuxManager {
  private sessions = new Map<string, TmuxSession>();
  private readonly MAX_BUFFER = 50000; // 50KB rolling buffer

  async createSession(host: Host, sessionName?: string): Promise<{ id: string; output: string }> {
    const name = sessionName || `mcp-${Date.now()}`;
    const id = `${host.name}:${name}`;

    if (this.sessions.has(id)) {
      return { id, output: 'Session already exists' };
    }

    const client = new Client();

    await new Promise<void>((resolve, reject) => {
      const config: ConnectConfig = {
        host: host.hostname,
        port: host.port,
        username: host.username,
        readyTimeout: 10000,
      };
      if (host.authType === 'key') {
        config.privateKey = host.credential;
      } else {
        config.password = host.credential;
      }

      client.on('ready', resolve);
      client.on('error', reject);
      client.connect(config);
    });

    // Create tmux session via exec first
    await new Promise<void>((resolve, reject) => {
      client.exec(`tmux new-session -d -s ${shellEscape(name)} 2>/dev/null; echo __TMUX_READY__`, (err, stream) => {
        if (err) return reject(err);
        let out = '';
        stream.on('data', (d: Buffer) => { out += d.toString(); });
        stream.on('close', () => {
          if (out.includes('__TMUX_READY__')) resolve();
          else reject(new Error('Failed to create tmux session'));
        });
      });
    });

    // Attach with persistent PTY channel
    const channel = await new Promise<ClientChannel>((resolve, reject) => {
      client.exec(`tmux attach-session -t ${shellEscape(name)}`, { pty: true }, (err, stream) => {
        if (err) return reject(err);
        resolve(stream);
      });
    });

    const session: TmuxSession = {
      id,
      host: host.name,
      sessionName: name,
      client,
      channel,
      buffer: '',
      createdAt: Date.now(),
    };

    channel.on('data', (data: Buffer) => {
      session.buffer += data.toString();
      if (session.buffer.length > this.MAX_BUFFER) {
        session.buffer = session.buffer.slice(-this.MAX_BUFFER);
      }
    });

    channel.on('close', () => {
      this.sessions.delete(id);
      client.end();
    });

    this.sessions.set(id, session);

    await new Promise(r => setTimeout(r, 500));

    return { id, output: session.buffer };
  }

  async sendKeys(sessionId: string, keys: string): Promise<{ output: string }> {
    const session = this.sessions.get(sessionId);
    if (!session || !session.channel) {
      throw new Error(`Session not found: ${sessionId}`);
    }

    session.buffer = '';
    session.channel.write(keys);

    await new Promise(r => setTimeout(r, 1000));

    return { output: session.buffer };
  }

  async readPane(sessionId: string, lines?: number): Promise<{ output: string }> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session not found: ${sessionId}`);
    }

    return new Promise((resolve, reject) => {
      const cmd = `tmux capture-pane -t ${shellEscape(session.sessionName)} -p${lines ? ` -S -${lines}` : ''}`;
      session.client.exec(cmd, (err, stream) => {
        if (err) return reject(err);
        let out = '';
        stream.on('data', (d: Buffer) => { out += d.toString(); });
        stream.on('close', () => resolve({ output: out }));
      });
    });
  }

  listSessions(): Array<{ id: string; host: string; sessionName: string; createdAt: number }> {
    return Array.from(this.sessions.values()).map(s => ({
      id: s.id,
      host: s.host,
      sessionName: s.sessionName,
      createdAt: s.createdAt,
    }));
  }

  async killSession(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    try {
      await new Promise<void>((resolve) => {
        session.client.exec(`tmux kill-session -t ${shellEscape(session.sessionName)}`, (_err, stream) => {
          if (stream) stream.on('close', () => resolve());
          else resolve();
        });
      });
    } catch { /* ignore */ }

    session.channel?.close();
    session.client.end();
    this.sessions.delete(sessionId);
  }

  async closeAll(): Promise<void> {
    for (const id of this.sessions.keys()) {
      await this.killSession(id);
    }
  }
}

function shellEscape(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}
