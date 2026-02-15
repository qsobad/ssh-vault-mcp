/**
 * Policy Engine
 * Checks if an agent is allowed to execute commands based on rules
 */

import { minimatch } from 'minimatch';
import type { AgentConfig, Session } from '../types.js';

export interface PolicyCheckResult {
  allowed: boolean;
  reason: string;
  matchedRule?: string;
}

export class PolicyEngine {
  /**
   * Check if an agent can access a host
   */
  checkHostAccess(agent: AgentConfig, hostName: string): PolicyCheckResult {
    // Check if host matches any allowed pattern
    for (const pattern of agent.allowedHosts) {
      if (minimatch(hostName, pattern)) {
        return {
          allowed: true,
          reason: 'Host matches allowed pattern',
          matchedRule: pattern,
        };
      }
    }

    return {
      allowed: false,
      reason: `Host '${hostName}' not in allowed hosts: [${agent.allowedHosts.join(', ')}]`,
    };
  }

  /**
   * Check if a command is allowed for an agent on a host
   */
  checkCommand(
    agent: AgentConfig,
    hostName: string,
    command: string,
    session?: Session
  ): PolicyCheckResult {
    // First check host access
    const hostCheck = this.checkHostAccess(agent, hostName);
    if (!hostCheck.allowed) {
      return hostCheck;
    }

    // Extract the base command (first word)
    const baseCommand = this.extractBaseCommand(command);

    // Check denied commands first (explicit deny takes precedence)
    for (const pattern of agent.deniedCommands) {
      if (this.commandMatches(command, baseCommand, pattern)) {
        return {
          allowed: false,
          reason: `Command denied by rule: ${pattern}`,
          matchedRule: pattern,
        };
      }
    }

    // Check if command is in session's approved commands
    if (session) {
      const approvedForHost = session.approvedCommands[hostName] || [];
      for (const approved of approvedForHost) {
        if (this.commandMatches(command, baseCommand, approved) || approved === command) {
          return {
            allowed: true,
            reason: 'Command approved in current session',
            matchedRule: approved,
          };
        }
      }
    }

    // Check allowed commands
    if (agent.allowedCommands.length === 0) {
      // No allowed commands specified = all commands need approval
      return {
        allowed: false,
        reason: 'No commands allowed by default, requires approval',
      };
    }

    for (const pattern of agent.allowedCommands) {
      if (this.commandMatches(command, baseCommand, pattern)) {
        return {
          allowed: true,
          reason: 'Command matches allowed pattern',
          matchedRule: pattern,
        };
      }
    }

    return {
      allowed: false,
      reason: `Command '${baseCommand}' not in allowed commands`,
    };
  }

  /**
   * Extract the base command (first word) from a full command string
   * Handles common patterns like sudo, env, etc.
   */
  private extractBaseCommand(command: string): string {
    const trimmed = command.trim();
    const parts = trimmed.split(/\s+/);
    
    // Skip common wrappers
    let index = 0;
    while (index < parts.length) {
      const part = parts[index];
      if (['sudo', 'env', 'nohup', 'nice', 'ionice', 'timeout'].includes(part)) {
        index++;
        // Skip env VAR=value patterns
        while (index < parts.length && parts[index].includes('=')) {
          index++;
        }
      } else {
        break;
      }
    }

    return parts[index] || parts[0];
  }

  /**
   * Check if a command matches a pattern
   * Supports:
   * - Exact match: "ls"
   * - Wildcard: "*" (any command)
   * - Glob patterns: "git *", "docker *"
   * - Full command patterns: "cat /var/log/*"
   */
  private commandMatches(fullCommand: string, baseCommand: string, pattern: string): boolean {
    // Wildcard matches everything
    if (pattern === '*') {
      return true;
    }

    // Exact base command match
    if (pattern === baseCommand) {
      return true;
    }

    // Pattern with wildcard (e.g., "git *")
    if (pattern.includes('*')) {
      return minimatch(fullCommand, pattern) || minimatch(baseCommand, pattern);
    }

    // Exact full command match
    if (pattern === fullCommand) {
      return true;
    }

    return false;
  }

  /**
   * Check if a command contains dangerous patterns
   */
  checkDangerousPatterns(command: string): {
    dangerous: boolean;
    patterns: string[];
  } {
    const dangerousPatterns = [
      { pattern: /rm\s+(-rf?|--recursive)?\s*\/(?!\s|$)/, description: 'rm with root path' },
      { pattern: />\s*\/dev\/sd[a-z]/, description: 'write to disk device' },
      { pattern: /mkfs\./, description: 'format filesystem' },
      { pattern: /dd\s+.*of=\/dev\//, description: 'dd to device' },
      { pattern: /:\(\)\{\s*:\|:&\s*\};:/, description: 'fork bomb' },
      { pattern: /chmod\s+(-R\s+)?777\s+\//, description: 'chmod 777 on root' },
      { pattern: /chown\s+(-R\s+)?.*\s+\//, description: 'chown on root' },
      { pattern: />\s*\/etc\/passwd/, description: 'overwrite passwd' },
      { pattern: />\s*\/etc\/shadow/, description: 'overwrite shadow' },
    ];

    const found: string[] = [];
    for (const { pattern, description } of dangerousPatterns) {
      if (pattern.test(command)) {
        found.push(description);
      }
    }

    return {
      dangerous: found.length > 0,
      patterns: found,
    };
  }

  /**
   * Parse and validate agent config rules
   */
  validateAgentConfig(config: AgentConfig): {
    valid: boolean;
    errors: string[];
    warnings: string[];
  } {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check fingerprint format
    if (!config.fingerprint.startsWith('SHA256:')) {
      errors.push('Fingerprint should start with "SHA256:"');
    }

    // Check for overly permissive rules
    if (config.allowedHosts.includes('*')) {
      warnings.push('Agent has access to all hosts');
    }

    if (config.allowedCommands.includes('*')) {
      warnings.push('Agent can execute any command');
    }

    // Check for conflicting rules
    for (const allowed of config.allowedCommands) {
      for (const denied of config.deniedCommands) {
        if (allowed === denied) {
          errors.push(`Command "${allowed}" is both allowed and denied`);
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }
}
