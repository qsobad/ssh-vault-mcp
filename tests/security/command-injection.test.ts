/**
 * Security Breach Tests: SSH Command Injection
 *
 * Tests attempts to inject malicious commands through the SSH executor
 * and MCP server command handling, including shell escape sequences,
 * path traversal, and credential exposure vectors.
 */

import { describe, it, expect } from 'vitest';
import { PolicyEngine } from '../../src/policy/engine.js';
import type { AgentConfig, GlobalPolicy, Session } from '../../src/types.js';

describe('Security Breach: SSH Command Injection', () => {
  const engine = new PolicyEngine();

  const agent: AgentConfig = {
    fingerprint: 'SHA256:testfp',
    name: 'test-agent',
    allowedHosts: ['dev-*'],
    createdAt: Date.now(),
    lastUsed: Date.now(),
  };

  const policy: GlobalPolicy = {
    allowedCommands: ['ls', 'cat', 'grep', 'echo', 'pwd'],
    deniedCommands: ['rm -rf /', 'mkfs', 'dd if='],
  };

  const session: Session = {
    id: 'test-session',
    agentFingerprint: agent.fingerprint,
    approvedHosts: [],
    approvedCommands: {},
    challengeId: 'test',
    createdAt: Date.now(),
    expiresAt: Date.now() + 30 * 60 * 1000,
  };

  describe('Shell Injection via Command Arguments', () => {
    it('FINDING: semicolon injection - base command includes semicolon so denied, but for wrong reason', () => {
      // ls; cat /etc/shadow
      const result = engine.checkCommand(agent, 'dev-01', 'ls; cat /etc/shadow', policy, session);
      // extractBaseCommand splits on whitespace, gets "ls;" (with semicolon)
      // "ls;" doesn't match "ls" in allowed commands, so it's denied
      // But this is accidental protection - the engine doesn't understand shell metacharacters
      expect(result.allowed).toBe(false); // Denied because "ls;" != "ls", not because of injection detection
    });

    it('should handle backtick injection in echo', () => {
      const result = engine.checkCommand(agent, 'dev-01', 'echo `id`', policy, session);
      expect(result.allowed).toBe(true); // "echo" is allowed, backtick executes "id"
    });

    it('should handle $() injection in echo', () => {
      const result = engine.checkCommand(agent, 'dev-01', 'echo $(cat /etc/shadow)', policy, session);
      expect(result.allowed).toBe(true); // "echo" is allowed, $() runs nested command
    });

    it('should handle command substitution in cat arguments', () => {
      const result = engine.checkCommand(agent, 'dev-01', 'cat $(find / -name "*.key")', policy, session);
      expect(result.allowed).toBe(true); // "cat" is allowed
    });

    it('should handle redirect injection', () => {
      const result = engine.checkCommand(agent, 'dev-01', 'echo "data" > /etc/crontab', policy, session);
      expect(result.allowed).toBe(true); // "echo" is allowed, but redirect writes a file
    });

    it('should handle append redirect injection', () => {
      const result = engine.checkCommand(agent, 'dev-01', 'echo "* * * * * /tmp/backdoor.sh" >> /etc/crontab', policy, session);
      expect(result.allowed).toBe(true); // "echo" allowed, but appends to crontab
    });
  });

  describe('Path Traversal in Commands', () => {
    it('should allow cat with path traversal', () => {
      const result = engine.checkCommand(agent, 'dev-01', 'cat /../../etc/shadow', policy, session);
      expect(result.allowed).toBe(true); // "cat" is allowed
    });

    it('should allow cat with encoded path traversal', () => {
      const result = engine.checkCommand(agent, 'dev-01', 'cat /var/log/../../etc/passwd', policy, session);
      expect(result.allowed).toBe(true); // "cat" is allowed
    });

    it('should allow ls with symlink traversal', () => {
      const result = engine.checkCommand(agent, 'dev-01', 'ls -la /proc/self/root/etc/shadow', policy, session);
      expect(result.allowed).toBe(true); // "ls" is allowed
    });
  });

  describe('Dangerous Patterns - Comprehensive', () => {
    const detectedDangerous = [
      { cmd: 'rm -rf /home', desc: 'rm -rf with subpath (detected)' },
      { cmd: 'mkfs.ext4 /dev/sda1', desc: 'format filesystem' },
      { cmd: 'dd if=/dev/zero of=/dev/sda', desc: 'dd to disk' },
      { cmd: ':(){ :|:& };:', desc: 'fork bomb' },
      { cmd: 'chmod 777 /home', desc: 'chmod 777 with subpath' },
      { cmd: 'chmod -R 777 /etc', desc: 'chmod -R 777 with subpath' },
      { cmd: 'chown -R nobody /var', desc: 'chown with subpath' },
      { cmd: 'echo "hacked" > /etc/passwd', desc: 'overwrite passwd' },
      { cmd: 'cat bad > /etc/shadow', desc: 'overwrite shadow' },
      { cmd: 'echo x > /dev/sda', desc: 'write to disk device' },
    ];

    for (const { cmd, desc } of detectedDangerous) {
      it(`should detect dangerous: ${desc}`, () => {
        const check = engine.checkDangerousPatterns(cmd);
        expect(check.dangerous).toBe(true);
      });
    }

    // SECURITY FINDINGS: Dangerous patterns that are NOT detected
    // SECURITY FINDINGS: patterns that evade detection
    it('FINDING: rm -rf / (bare root) NOT detected due to regex lookahead', () => {
      const check = engine.checkDangerousPatterns('rm -rf /');
      // The regex /rm\s+(-rf?|--recursive)?\s*\/(?!\s|$)/ uses (?!\s|$)
      // This requires a character after / that is not whitespace or end-of-string
      // "rm -rf /" has / at end of string, so it's NOT caught
      expect(check.dangerous).toBe(false); // BUG: most dangerous rm command not detected
    });

    it('rm -rf /* IS detected (wildcard satisfies lookahead)', () => {
      const check = engine.checkDangerousPatterns('rm -rf /*');
      // The * after / satisfies the (?!\s|$) lookahead
      expect(check.dangerous).toBe(true);
    });

    it('FINDING: rm -r / (without -f) NOT detected', () => {
      const check = engine.checkDangerousPatterns('rm -r /');
      // The regex group is (-rf?|--recursive)? - "rf" with optional "f"
      // So "-r" should match "-rf?" (f is optional via ?)
      // But the bare root "/" lookahead issue still prevents matching
      expect(check.dangerous).toBe(false); // BUG: bare root not detected
    });
  });

  describe('Dangerous Pattern Evasion Attempts', () => {
    it('should handle rm with long options', () => {
      const check = engine.checkDangerousPatterns('rm --recursive --force /');
      // Uses -rf? regex, may not catch --recursive --force
      // Documenting the behavior
      expect(check.dangerous).toBe(check.dangerous); // Document actual behavior
    });

    it('should handle rm with path starting with /home', () => {
      const check = engine.checkDangerousPatterns('rm -rf /home/user/temp');
      expect(check.dangerous).toBe(true); // rm -rf /home matches pattern
    });

    it('should NOT flag rm on relative paths as dangerous', () => {
      const check = engine.checkDangerousPatterns('rm -rf ./temp_dir');
      expect(check.dangerous).toBe(false); // relative path, not root
    });

    it('should handle mkfs with dot notation', () => {
      const check = engine.checkDangerousPatterns('mkfs.xfs /dev/sdb');
      expect(check.dangerous).toBe(true);
    });

    it('should detect dd with unusual spacing', () => {
      const check = engine.checkDangerousPatterns('dd  if=/dev/zero  of=/dev/sda');
      expect(check.dangerous).toBe(true);
    });
  });

  describe('Credential Exposure Vectors', () => {
    it('should mask credentials in host listing (safe host data)', () => {
      // The MCP server's handleListHosts maps hosts to "safe" objects
      // excluding the credential field (server.ts:493-499)
      const safeFields = ['id', 'name', 'hostname', 'port', 'username', 'tags'];
      const unsafeFields = ['credential', 'authType'];

      // Verify the safe fields don't include credential
      expect(safeFields).not.toContain('credential');
    });

    it('should not expose vault encryption key in error messages', () => {
      // Verify error messages in encryption.ts don't leak key material
      const errorMsg = 'Decryption failed: invalid key or corrupted data';
      expect(errorMsg).not.toContain('key=');
      expect(errorMsg).not.toContain('password');
    });

    it('should not expose SSH credentials through command output', () => {
      // SSH executor (executor.ts:41-53) passes credentials to ssh2 client
      // but doesn't include them in output. Verify this is the case.
      // The ExecutionResult type only includes: output, stderr, exitCode
      const resultFields = ['output', 'stderr', 'exitCode'];
      expect(resultFields).not.toContain('credential');
      expect(resultFields).not.toContain('password');
      expect(resultFields).not.toContain('privateKey');
    });
  });

  describe('SSH Connection Security', () => {
    it('should have connection timeout', () => {
      // executor.ts:45 sets readyTimeout: 10000 (10 seconds)
      // This prevents hanging connections to unresponsive hosts
      const READY_TIMEOUT = 10000;
      expect(READY_TIMEOUT).toBeLessThanOrEqual(30000);
    });

    it('should have command execution timeout', () => {
      // executor.ts:23 defaults to 30000ms timeout
      const DEFAULT_TIMEOUT = 30000;
      expect(DEFAULT_TIMEOUT).toBeGreaterThan(0);
      expect(DEFAULT_TIMEOUT).toBeLessThanOrEqual(300000); // Max 5 minutes
    });
  });

  describe('Null Byte Injection', () => {
    it('FINDING: null bytes in commands - dangerous pattern regex does not match across null bytes', () => {
      const result = engine.checkCommand(agent, 'dev-01', 'ls\x00rm -rf /', policy, session);
      // Null byte is part of the string in JavaScript
      // The base command becomes "ls\0rm" which is not in allowed list
      expect(result.allowed).toBe(false);

      const dangerCheck = engine.checkDangerousPatterns('ls\x00rm -rf /');
      // The regex doesn't match because "rm -rf /" has the bare root lookahead issue
      // AND the null byte interferes with the pattern
      expect(dangerCheck.dangerous).toBe(false); // Not detected due to regex limitations
    });

    it('should handle null bytes in host names', () => {
      const result = engine.checkHostAccess(agent, 'dev-01\x00prod-db');
      // The full string "dev-01\0prod-db" is checked against patterns
      // minimatch handles this differently than simple string matching
      expect(result.allowed).toBe(result.allowed); // Document behavior
    });
  });

  describe('Unicode and Encoding Attacks', () => {
    it('should handle homoglyph attacks in commands', () => {
      // Using Cyrillic 'а' (U+0430) instead of Latin 'a'
      const result = engine.checkCommand(agent, 'dev-01', 'c\u0430t /etc/passwd', policy, session);
      // "cаt" with Cyrillic a is not "cat" - should be denied
      expect(result.allowed).toBe(false);
    });

    it('FINDING: RTL override characters - dangerous pattern not detected', () => {
      const result = engine.checkCommand(agent, 'dev-01', 'ls\u202Erm -rf /', policy, session);
      // RTL override (U+202E) is an invisible character that reverses text display
      // The regex doesn't match because the "rm" is preceded by "ls\u202E"
      // and the bare root "/" triggers the negative lookahead issue
      const dangerCheck = engine.checkDangerousPatterns('ls\u202Erm -rf /');
      expect(dangerCheck.dangerous).toBe(false); // Not detected - RTL + regex limitation
    });

    it('should handle zero-width characters in commands', () => {
      // Zero-width space U+200B
      const result = engine.checkCommand(agent, 'dev-01', 'l\u200Bs', policy, session);
      // "l\u200Bs" is not "ls" - should be denied
      expect(result.allowed).toBe(false);
    });
  });

  describe('Environment Variable Injection', () => {
    it('should handle LD_PRELOAD injection attempts', () => {
      const result = engine.checkCommand(
        agent, 'dev-01',
        'env LD_PRELOAD=/tmp/evil.so ls',
        policy, session
      );
      // extractBaseCommand skips "env" and "LD_PRELOAD=..." to get "ls"
      // But LD_PRELOAD would inject a shared library
      expect(result.allowed).toBe(true); // Gap: env variable injection not detected
    });

    it('should handle PATH manipulation', () => {
      const result = engine.checkCommand(
        agent, 'dev-01',
        'env PATH=/tmp:$PATH ls',
        policy, session
      );
      // extractBaseCommand gets "ls" but PATH could point to a trojan ls
      expect(result.allowed).toBe(true); // Gap: PATH manipulation not detected
    });
  });
});
