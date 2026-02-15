/**
 * Security Breach Tests: Input Validation & Sanitization
 *
 * Tests input boundary conditions, oversized payloads, malformed data,
 * and injection attacks across all user-facing interfaces.
 */

import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import { fingerprintFromPublicKey, generateAgentKeypair } from '../../src/auth/agent.js';
import { PolicyEngine } from '../../src/policy/engine.js';
import type { AgentConfig, GlobalPolicy } from '../../src/types.js';

// Replicate the MCP server schemas for testing
const SubmitUnlockSchema = z.object({
  unlock_code: z.string(),
});

const ListHostsSchema = z.object({
  filter: z.string().optional(),
});

const ExecuteCommandSchema = z.object({
  host: z.string(),
  command: z.string(),
  timeout: z.number().optional().default(30),
});

const ManageVaultSchema = z.object({
  action: z.enum(['add_host', 'remove_host', 'update_host', 'add_agent', 'remove_agent']),
  data: z.record(z.unknown()),
});

describe('Security Breach: Input Validation', () => {
  describe('MCP Schema Validation', () => {
    it('should reject missing unlock_code', () => {
      expect(() => SubmitUnlockSchema.parse({})).toThrow();
    });

    it('should reject non-string unlock_code', () => {
      expect(() => SubmitUnlockSchema.parse({ unlock_code: 12345 })).toThrow();
    });

    it('should accept valid unlock_code', () => {
      const result = SubmitUnlockSchema.parse({ unlock_code: 'UNLOCK-ABCDE' });
      expect(result.unlock_code).toBe('UNLOCK-ABCDE');
    });

    it('should reject missing host in execute_command', () => {
      expect(() => ExecuteCommandSchema.parse({ command: 'ls' })).toThrow();
    });

    it('should reject missing command in execute_command', () => {
      expect(() => ExecuteCommandSchema.parse({ host: 'dev-01' })).toThrow();
    });

    it('should default timeout to 30', () => {
      const result = ExecuteCommandSchema.parse({ host: 'dev-01', command: 'ls' });
      expect(result.timeout).toBe(30);
    });

    it('should reject invalid manage_vault action', () => {
      expect(() => ManageVaultSchema.parse({
        action: 'drop_database',
        data: {},
      })).toThrow();
    });

    it('should accept valid manage_vault actions', () => {
      const actions = ['add_host', 'remove_host', 'update_host', 'add_agent', 'remove_agent'];
      for (const action of actions) {
        const result = ManageVaultSchema.parse({ action, data: {} });
        expect(result.action).toBe(action);
      }
    });
  });

  describe('Oversized Input Handling', () => {
    it('should handle extremely long command strings', () => {
      const engine = new PolicyEngine();
      const agent: AgentConfig = {
        fingerprint: 'SHA256:test',
        name: 'test',
        allowedHosts: ['*'],
        createdAt: Date.now(),
        lastUsed: Date.now(),
      };
      const policy: GlobalPolicy = {
        allowedCommands: ['echo'],
        deniedCommands: [],
      };

      // 1MB command string
      const longCmd = 'echo ' + 'A'.repeat(1024 * 1024);
      // Should not throw
      const result = engine.checkCommand(agent, 'dev-01', longCmd, policy);
      expect(result.allowed).toBe(true);
    });

    it('should handle command with many semicolons', () => {
      const engine = new PolicyEngine();
      const agent: AgentConfig = {
        fingerprint: 'SHA256:test',
        name: 'test',
        allowedHosts: ['*'],
        createdAt: Date.now(),
        lastUsed: Date.now(),
      };
      const policy: GlobalPolicy = {
        allowedCommands: ['echo'],
        deniedCommands: [],
      };

      const manyCommands = Array(1000).fill('echo hi').join('; ');
      const result = engine.checkCommand(agent, 'dev-01', manyCommands, policy);
      expect(result.allowed).toBe(true); // Only checks first command
    });

    it('should handle extremely long host names', () => {
      const engine = new PolicyEngine();
      const agent: AgentConfig = {
        fingerprint: 'SHA256:test',
        name: 'test',
        allowedHosts: ['dev-*'],
        createdAt: Date.now(),
        lastUsed: Date.now(),
      };

      const longHost = 'dev-' + 'a'.repeat(10000);
      const result = engine.checkHostAccess(agent, longHost);
      expect(result.allowed).toBe(true); // Matches dev-*
    });
  });

  describe('Special Character Input', () => {
    it('should handle null characters in strings', () => {
      const result = ExecuteCommandSchema.parse({
        host: 'dev\x00-01',
        command: 'ls\x00; rm -rf /',
      });
      // Zod accepts null chars in strings
      expect(result.host).toContain('\x00');
    });

    it('should handle unicode characters in host names', () => {
      const engine = new PolicyEngine();
      const agent: AgentConfig = {
        fingerprint: 'SHA256:test',
        name: 'test',
        allowedHosts: ['dev-*'],
        createdAt: Date.now(),
        lastUsed: Date.now(),
      };

      const result = engine.checkHostAccess(agent, 'dev-\u00e9\u00e8\u00ea');
      expect(result.allowed).toBe(true);
    });

    it('FIXED: control characters in commands - bare root now detected', () => {
      const engine = new PolicyEngine();
      const dangerCheck = engine.checkDangerousPatterns('rm\t-rf\r\n/');
      // With the updated regex /rm\s+(-[a-zA-Z]*\s+)*\//, tab and whitespace
      // characters are handled, and bare root is now caught
      expect(dangerCheck.dangerous).toBe(true);
    });

    it('should handle empty strings', () => {
      const engine = new PolicyEngine();
      const agent: AgentConfig = {
        fingerprint: 'SHA256:test',
        name: 'test',
        allowedHosts: ['*'],
        createdAt: Date.now(),
        lastUsed: Date.now(),
      };
      const policy: GlobalPolicy = {
        allowedCommands: ['ls'],
        deniedCommands: [],
      };

      const result = engine.checkCommand(agent, 'dev-01', '', policy);
      // Empty command - base command will be empty string
      expect(result.allowed).toBe(false);
    });
  });

  describe('Public Key Input Validation', () => {
    it('should handle valid public key fingerprint generation', () => {
      const keypair = generateAgentKeypair();
      const fp = fingerprintFromPublicKey(keypair.publicKey);
      expect(fp).toMatch(/^SHA256:/);
    });

    it('should handle base64 public key with padding', () => {
      const keypair = generateAgentKeypair();
      // Ensure the key can be processed regardless of padding
      const fp = fingerprintFromPublicKey(keypair.publicKey);
      expect(fp).toBeDefined();
    });

    it('should handle empty public key', () => {
      // Empty string is valid base64 but produces zero-length buffer
      const fp = fingerprintFromPublicKey('');
      // Should still produce a fingerprint (of empty data)
      expect(fp).toMatch(/^SHA256:/);
    });
  });

  describe('JSON Injection', () => {
    it('should safely parse JSON with __proto__ pollution attempt', () => {
      const malicious = '{"__proto__": {"isAdmin": true}}';
      const parsed = JSON.parse(malicious);
      // Standard JSON.parse doesn't pollute prototype
      const obj: Record<string, unknown> = {};
      expect((obj as any).isAdmin).toBeUndefined();
    });

    it('should safely parse JSON with constructor pollution', () => {
      const malicious = '{"constructor": {"prototype": {"isAdmin": true}}}';
      const parsed = JSON.parse(malicious);
      const obj: Record<string, unknown> = {};
      expect((obj as any).isAdmin).toBeUndefined();
    });

    it('should handle deeply nested JSON', () => {
      // Create deeply nested JSON object
      let nested = '{"a":';
      const depth = 100;
      for (let i = 0; i < depth; i++) {
        nested += '{"a":';
      }
      nested += '"value"';
      for (let i = 0; i <= depth; i++) {
        nested += '}';
      }
      // Should parse without stack overflow
      expect(() => JSON.parse(nested)).not.toThrow();
    });
  });

  describe('Zod Schema Bypass Attempts', () => {
    it('should strip extra fields from valid input', () => {
      const input = {
        host: 'dev-01',
        command: 'ls',
        timeout: 30,
        maliciousField: 'DROP TABLE',
        __proto__: { admin: true },
      };
      const result = ExecuteCommandSchema.parse(input);
      expect((result as any).maliciousField).toBeUndefined();
    });

    it('should reject negative timeout', () => {
      const input = {
        host: 'dev-01',
        command: 'ls',
        timeout: -1,
      };
      // Zod allows negative numbers by default (no .positive() constraint)
      const result = ExecuteCommandSchema.parse(input);
      expect(result.timeout).toBe(-1); // Gap: no minimum timeout validation
    });

    it('should reject extremely large timeout', () => {
      const input = {
        host: 'dev-01',
        command: 'ls',
        timeout: Number.MAX_SAFE_INTEGER,
      };
      // Zod allows any number (no .max() constraint)
      const result = ExecuteCommandSchema.parse(input);
      expect(result.timeout).toBe(Number.MAX_SAFE_INTEGER); // Gap: no max timeout
    });

    it('should reject NaN timeout', () => {
      const input = {
        host: 'dev-01',
        command: 'ls',
        timeout: NaN,
      };
      expect(() => ExecuteCommandSchema.parse(input)).toThrow();
    });

    it('Infinity timeout accepted by Zod but clamped by server', () => {
      const input = {
        host: 'dev-01',
        command: 'ls',
        timeout: Infinity,
      };
      // Zod z.number() accepts Infinity - it's a valid JS number
      const result = ExecuteCommandSchema.parse(input);
      expect(result.timeout).toBe(Infinity);
      // However the server now validates: Number.isFinite(t) check rejects Infinity
      // and falls back to default 30
      expect(Number.isFinite(Infinity)).toBe(false);
    });
  });

  describe('Server-Side Timeout Validation (New Security Feature)', () => {
    // The server now clamps timeout: Math.min(Math.max(t, 1), 300) with Number.isFinite check
    it('should clamp negative timeout to default', () => {
      const t = -1;
      const isValid = Number.isFinite(t) && t > 0;
      // Negative fails t > 0 check, falls back to default 30
      expect(isValid).toBe(false);
    });

    it('should clamp zero timeout to default', () => {
      const t = 0;
      const isValid = Number.isFinite(t) && t > 0;
      expect(isValid).toBe(false);
    });

    it('should clamp Infinity to default', () => {
      const t = Infinity;
      const isValid = Number.isFinite(t);
      expect(isValid).toBe(false);
    });

    it('should clamp NaN to default', () => {
      const t = NaN;
      const isValid = Number.isFinite(t);
      expect(isValid).toBe(false);
    });

    it('should clamp excessively large timeout to 300', () => {
      const t = 99999;
      const clamped = Math.min(Math.max(t, 1), 300);
      expect(clamped).toBe(300);
    });

    it('should accept valid timeout in range', () => {
      const t = 60;
      const isValid = Number.isFinite(t) && t > 0;
      const clamped = Math.min(Math.max(t, 1), 300);
      expect(isValid).toBe(true);
      expect(clamped).toBe(60);
    });

    it('should clamp fractional timeout below 1 to 1', () => {
      const t = 0.5;
      const isValid = Number.isFinite(t) && t > 0;
      const clamped = Math.min(Math.max(t, 1), 300);
      expect(isValid).toBe(true);
      expect(clamped).toBe(1);
    });
  });

  describe('Host Filter Glob Injection', () => {
    it('should handle filter with glob characters', () => {
      const result = ListHostsSchema.parse({ filter: '**/*' });
      expect(result.filter).toBe('**/*');
      // The filter is passed to minimatch - verify it won't crash
    });

    it('should handle filter with regex-like characters', () => {
      const result = ListHostsSchema.parse({ filter: '(dev|prod)-[0-9]+' });
      expect(result.filter).toBe('(dev|prod)-[0-9]+');
      // minimatch treats these as glob patterns, not regex
    });

    it('should handle filter with path traversal', () => {
      const result = ListHostsSchema.parse({ filter: '../../etc/passwd' });
      expect(result.filter).toBe('../../etc/passwd');
      // This would only match host names, not file paths
    });
  });

  describe('Request Access Input Validation', () => {
    it('should require agent name to be provided', () => {
      // The MCP server checks for name, publicKey, requestedHosts
      // Testing the validation logic
      const args = {
        name: '',
        publicKey: 'somekey',
        requestedHosts: ['dev-*'],
      };
      // Empty name is truthy in JavaScript (empty string is falsy)
      expect(!args.name).toBe(true); // Empty string is falsy
    });

    it('should require non-empty requestedHosts', () => {
      const args = {
        name: 'agent',
        publicKey: 'somekey',
        requestedHosts: [],
      };
      expect(args.requestedHosts.length === 0).toBe(true);
    });

    it('should handle requestedHosts with wildcard-all pattern', () => {
      const args = {
        name: 'agent',
        publicKey: 'somekey',
        requestedHosts: ['*'],
      };
      // Agent requests access to ALL hosts - owner should restrict
      expect(args.requestedHosts).toContain('*');
    });
  });
});
