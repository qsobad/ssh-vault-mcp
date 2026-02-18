/**
 * TmuxManager unit tests
 * 
 * Uses mocked ssh2 Client to test tmux session lifecycle
 * without requiring real SSH connections.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'events';
import type { Host } from '../../src/types.js';

// ── Mock ssh2 ──────────────────────────────────────────────

class MockChannel extends EventEmitter {
  writable = true;
  written: string[] = [];

  write(data: string) {
    this.written.push(data);
    // Simulate echo back after short delay
    setTimeout(() => this.emit('data', Buffer.from(`echo: ${data}`)), 50);
    return true;
  }

  close() {
    this.emit('close');
  }
}

class MockClient extends EventEmitter {
  connected = false;
  execCalls: Array<{ cmd: string; opts?: Record<string, unknown> }> = [];
  private channels: MockChannel[] = [];
  private execIndex = 0;

  connect(_config: Record<string, unknown>) {
    this.connected = true;
    setTimeout(() => this.emit('ready'), 10);
  }

  exec(
    cmd: string,
    optsOrCb: Record<string, unknown> | ((err: Error | null, stream: MockChannel) => void),
    maybeCb?: (err: Error | null, stream: MockChannel) => void
  ) {
    const cb = typeof optsOrCb === 'function' ? optsOrCb : maybeCb!;
    const opts = typeof optsOrCb === 'function' ? {} : optsOrCb;
    this.execCalls.push({ cmd, opts });

    const channel = new MockChannel();
    this.channels.push(channel);

    setTimeout(() => {
      cb(null, channel);

      // Simulate output depending on command
      if (cmd.includes('new-session') && cmd.includes('__TMUX_READY__')) {
        setTimeout(() => {
          channel.emit('data', Buffer.from('__TMUX_READY__\n'));
          channel.emit('close', 0);
        }, 20);
      } else if (cmd.includes('attach-session')) {
        // PTY channel stays open — emit initial prompt
        setTimeout(() => channel.emit('data', Buffer.from('$ ')), 50);
      } else if (cmd.includes('capture-pane')) {
        setTimeout(() => {
          channel.emit('data', Buffer.from('captured pane content\n'));
          channel.emit('close', 0);
        }, 20);
      } else if (cmd.includes('kill-session')) {
        setTimeout(() => channel.emit('close', 0), 20);
      }
    }, 10);
  }

  end() {
    this.connected = false;
  }
}

// Mock the ssh2 module
vi.mock('ssh2', () => ({
  Client: MockClient,
}));

// Import after mock
const { TmuxManager } = await import('../../src/ssh/tmux-manager.js');

// ── Test fixtures ──────────────────────────────────────────

const testHost: Host = {
  id: 'h1',
  name: 'dev-01',
  hostname: '192.168.1.100',
  port: 22,
  username: 'deploy',
  authType: 'key',
  credential: '-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----',
  tags: ['dev'],
  createdAt: Date.now(),
  updatedAt: Date.now(),
};

const passwordHost: Host = {
  ...testHost,
  id: 'h2',
  name: 'staging-01',
  authType: 'password',
  credential: 's3cret',
};

// ── Tests ──────────────────────────────────────────────────

describe('TmuxManager', () => {
  let manager: InstanceType<typeof TmuxManager>;

  beforeEach(() => {
    manager = new TmuxManager();
  });

  afterEach(async () => {
    await manager.closeAll();
  });

  // ── createSession ──

  describe('createSession', () => {
    it('should create a session and return id + output', async () => {
      const result = await manager.createSession(testHost, 'test-sess');
      expect(result.id).toBe('dev-01:test-sess');
      expect(typeof result.output).toBe('string');
    });

    it('should auto-generate session name if not provided', async () => {
      const result = await manager.createSession(testHost);
      expect(result.id).toMatch(/^dev-01:mcp-\d+$/);
    });

    it('should return existing session if duplicate', async () => {
      await manager.createSession(testHost, 'dup');
      const result2 = await manager.createSession(testHost, 'dup');
      expect(result2.output).toBe('Session already exists');
    });

    it('should work with password auth', async () => {
      const result = await manager.createSession(passwordHost, 'pw-sess');
      expect(result.id).toBe('staging-01:pw-sess');
    });
  });

  // ── sendKeys ──

  describe('sendKeys', () => {
    it('should send keys and return output', async () => {
      const { id } = await manager.createSession(testHost, 'keys-test');
      const result = await manager.sendKeys(id, 'ls -la\n');
      expect(typeof result.output).toBe('string');
    });

    it('should throw for non-existent session', async () => {
      await expect(manager.sendKeys('bogus:id', 'test')).rejects.toThrow('Session not found');
    });
  });

  // ── readPane ──

  describe('readPane', () => {
    it('should read pane content', async () => {
      const { id } = await manager.createSession(testHost, 'read-test');
      const result = await manager.readPane(id);
      expect(result.output).toContain('captured pane content');
    });

    it('should accept lines parameter', async () => {
      const { id } = await manager.createSession(testHost, 'read-lines');
      const result = await manager.readPane(id, 50);
      expect(typeof result.output).toBe('string');
    });

    it('should throw for non-existent session', async () => {
      await expect(manager.readPane('bogus:id')).rejects.toThrow('Session not found');
    });
  });

  // ── listSessions ──

  describe('listSessions', () => {
    it('should return empty array initially', () => {
      expect(manager.listSessions()).toEqual([]);
    });

    it('should list created sessions', async () => {
      await manager.createSession(testHost, 'list-1');
      await manager.createSession(passwordHost, 'list-2');
      const sessions = manager.listSessions();
      expect(sessions).toHaveLength(2);
      expect(sessions[0].host).toBe('dev-01');
      expect(sessions[1].host).toBe('staging-01');
    });
  });

  // ── killSession ──

  describe('killSession', () => {
    it('should remove session from list', async () => {
      const { id } = await manager.createSession(testHost, 'kill-me');
      expect(manager.listSessions()).toHaveLength(1);
      await manager.killSession(id);
      expect(manager.listSessions()).toHaveLength(0);
    });

    it('should be safe to kill non-existent session', async () => {
      await expect(manager.killSession('nope:nope')).resolves.toBeUndefined();
    });
  });

  // ── closeAll ──

  describe('closeAll', () => {
    it('should close all sessions', async () => {
      await manager.createSession(testHost, 'a');
      await manager.createSession(passwordHost, 'b');
      expect(manager.listSessions()).toHaveLength(2);
      await manager.closeAll();
      expect(manager.listSessions()).toHaveLength(0);
    });
  });

  // ── buffer management ──

  describe('buffer management', () => {
    it('should accumulate output in buffer', async () => {
      const { id } = await manager.createSession(testHost, 'buf-test');
      // sendKeys triggers echo which adds to buffer
      await manager.sendKeys(id, 'hello\n');
      const sessions = manager.listSessions();
      expect(sessions.find(s => s.id === id)).toBeTruthy();
    });
  });

  // ── shellEscape (indirectly) ──

  describe('shell escaping', () => {
    it('should handle session names with special chars', async () => {
      const result = await manager.createSession(testHost, "it's-a-test");
      expect(result.id).toBe("dev-01:it's-a-test");
    });
  });
});
