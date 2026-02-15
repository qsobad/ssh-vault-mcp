/**
 * MCP Server implementation
 * Provides tools for SSH vault operations
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import type { Config } from '../types.js';
import { VaultManager } from '../vault/vault.js';
import { PolicyEngine } from '../policy/engine.js';
import { SSHExecutor } from '../ssh/executor.js';

// Tool input schemas
const SubmitUnlockSchema = z.object({
  unlock_code: z.string().describe('Unlock code from the signing page'),
});

const ListHostsSchema = z.object({
  filter: z.string().optional().describe('Host name filter (supports wildcards)'),
});

const ExecuteCommandSchema = z.object({
  host: z.string().describe('Host name or ID'),
  command: z.string().describe('Command to execute'),
  timeout: z.number().optional().default(30).describe('Timeout in seconds'),
});

const ManageVaultSchema = z.object({
  action: z.enum(['add_host', 'remove_host', 'update_host', 'add_agent', 'remove_agent']),
  data: z.record(z.unknown()).describe('Action-specific data'),
});

// Tool definitions
const TOOLS: Tool[] = [
  {
    name: 'vault_status',
    description: 'Check if the SSH vault is locked or unlocked, and session status',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  {
    name: 'request_unlock',
    description: 'Request to unlock the vault. Returns a URL for Passkey authentication.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  {
    name: 'submit_unlock',
    description: 'Submit the unlock code obtained from the signing page',
    inputSchema: {
      type: 'object',
      properties: {
        unlock_code: {
          type: 'string',
          description: 'The unlock code shown on the signing page after Passkey verification',
        },
      },
      required: ['unlock_code'],
    },
  },
  {
    name: 'list_hosts',
    description: 'List available SSH hosts (requires unlocked vault)',
    inputSchema: {
      type: 'object',
      properties: {
        filter: {
          type: 'string',
          description: 'Filter hosts by name pattern (supports wildcards like dev-*)',
        },
      },
      required: [],
    },
  },
  {
    name: 'execute_command',
    description: 'Execute a command on an SSH host. May require approval for commands outside policy.',
    inputSchema: {
      type: 'object',
      properties: {
        host: {
          type: 'string',
          description: 'Host name or ID',
        },
        command: {
          type: 'string',
          description: 'Shell command to execute',
        },
        timeout: {
          type: 'number',
          description: 'Command timeout in seconds (default: 30)',
        },
      },
      required: ['host', 'command'],
    },
  },
  {
    name: 'manage_vault',
    description: 'Manage vault contents (add/remove hosts and agents). Requires Passkey confirmation.',
    inputSchema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['add_host', 'remove_host', 'update_host', 'add_agent', 'remove_agent'],
          description: 'Management action to perform',
        },
        data: {
          type: 'object',
          description: 'Action-specific data',
        },
      },
      required: ['action', 'data'],
    },
  },
  {
    name: 'revoke_session',
    description: 'Revoke the current session and lock the vault',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
];

export class MCPServer {
  private server: Server;
  private vaultManager: VaultManager;
  private policyEngine: PolicyEngine;
  private sshExecutor: SSHExecutor;
  private config: Config;
  private agentFingerprint: string;

  constructor(
    config: Config,
    vaultManager: VaultManager,
    agentFingerprint: string
  ) {
    this.config = config;
    this.vaultManager = vaultManager;
    this.policyEngine = new PolicyEngine();
    this.sshExecutor = new SSHExecutor();
    this.agentFingerprint = agentFingerprint;

    this.server = new Server(
      { name: 'ssh-vault-mcp', version: '0.1.0' },
      { capabilities: { tools: {} } }
    );

    this.setupHandlers();
  }

  private setupHandlers(): void {
    // List tools handler
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return { tools: TOOLS };
    });

    // Call tool handler
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'vault_status':
            return this.handleVaultStatus();

          case 'request_unlock':
            return this.handleRequestUnlock();

          case 'submit_unlock':
            const unlockArgs = SubmitUnlockSchema.parse(args);
            return this.handleSubmitUnlock(unlockArgs.unlock_code);

          case 'list_hosts':
            const listArgs = ListHostsSchema.parse(args);
            return this.handleListHosts(listArgs.filter);

          case 'execute_command':
            const execArgs = ExecuteCommandSchema.parse(args);
            return this.handleExecuteCommand(
              execArgs.host,
              execArgs.command,
              execArgs.timeout
            );

          case 'manage_vault':
            const manageArgs = ManageVaultSchema.parse(args);
            return this.handleManageVault(manageArgs.action, manageArgs.data);

          case 'revoke_session':
            return this.handleRevokeSession();

          default:
            return {
              content: [{ type: 'text', text: `Unknown tool: ${name}` }],
              isError: true,
            };
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        return {
          content: [{ type: 'text', text: `Error: ${message}` }],
          isError: true,
        };
      }
    });
  }

  private handleVaultStatus() {
    const session = this.vaultManager.getSessionByAgent(this.agentFingerprint);
    
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          locked: !this.vaultManager.isUnlocked(),
          sessionId: session?.id,
          sessionExpires: session?.expiresAt,
        }, null, 2),
      }],
    };
  }

  private async handleRequestUnlock() {
    if (this.vaultManager.isUnlocked()) {
      const session = this.vaultManager.getSessionByAgent(this.agentFingerprint);
      if (session) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              status: 'already_unlocked',
              sessionId: session.id,
              expiresAt: session.expiresAt,
            }, null, 2),
          }],
        };
      }
    }

    const { challengeId, unlockUrl, listenUrl, expiresAt } = this.vaultManager.createUnlockChallenge(
      this.config.web.externalUrl,
      this.agentFingerprint
    );

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          status: 'pending',
          unlockUrl,
          listenUrl,
          challengeId,
          expiresAt,
          message: 'Please visit the URL and authenticate with your Passkey. You will be notified automatically when approved, or you can provide the unlock code manually.',
        }, null, 2),
      }],
    };
  }

  private async handleSubmitUnlock(unlockCode: string) {
    const result = await this.vaultManager.submitUnlockCode(
      unlockCode,
      this.agentFingerprint
    );

    return {
      content: [{
        type: 'text',
        text: JSON.stringify(result, null, 2),
      }],
    };
  }

  private handleListHosts(filter?: string) {
    if (!this.vaultManager.isUnlocked()) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            error: 'Vault is locked. Use request_unlock first.',
          }, null, 2),
        }],
        isError: true,
      };
    }

    let hosts = this.vaultManager.getHosts();
    
    // Apply filter if provided
    if (filter) {
      const { minimatch } = require('minimatch');
      hosts = hosts.filter(h => minimatch(h.name, filter));
    }

    // Return safe info (without credentials)
    const safeHosts = hosts.map(h => ({
      id: h.id,
      name: h.name,
      hostname: h.hostname,
      port: h.port,
      username: h.username,
      tags: h.tags,
    }));

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({ hosts: safeHosts }, null, 2),
      }],
    };
  }

  private async handleExecuteCommand(
    hostName: string,
    command: string,
    timeout: number
  ) {
    if (!this.vaultManager.isUnlocked()) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            error: 'Vault is locked. Use request_unlock first.',
          }, null, 2),
        }],
        isError: true,
      };
    }

    const host = this.vaultManager.getHost(hostName);
    if (!host) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ error: `Host not found: ${hostName}` }, null, 2),
        }],
        isError: true,
      };
    }

    const agent = this.vaultManager.getAgent(this.agentFingerprint);
    if (!agent) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            error: 'Agent not registered in vault',
          }, null, 2),
        }],
        isError: true,
      };
    }

    const session = this.vaultManager.getSessionByAgent(this.agentFingerprint);

    // Check policy
    const policyResult = this.policyEngine.checkCommand(
      agent,
      host.name,
      command,
      session || undefined
    );

    if (!policyResult.allowed) {
      // Need approval
      const { approvalUrl, listenUrl, challengeId, expiresAt } = this.vaultManager.createApprovalChallenge(
        this.config.web.externalUrl,
        this.agentFingerprint,
        host.name,
        [command]
      );

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            needsApproval: true,
            reason: policyResult.reason,
            approvalUrl,
            listenUrl,
            challengeId,
            expiresAt,
            message: 'This command requires approval. Please visit the URL and authenticate. You will be notified automatically when approved.',
          }, null, 2),
        }],
      };
    }

    // Check for dangerous patterns
    const dangerCheck = this.policyEngine.checkDangerousPatterns(command);
    if (dangerCheck.dangerous) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            error: 'Command contains dangerous patterns',
            patterns: dangerCheck.patterns,
            message: 'This command has been blocked for safety.',
          }, null, 2),
        }],
        isError: true,
      };
    }

    // Execute command
    try {
      const result = await this.sshExecutor.execute(host, command, timeout * 1000);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: true,
            output: result.output,
            exitCode: result.exitCode,
          }, null, 2),
        }],
      };
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            success: false,
            error: error instanceof Error ? error.message : 'Execution failed',
          }, null, 2),
        }],
        isError: true,
      };
    }
  }

  private handleManageVault(action: string, _data: Record<string, unknown>) {
    // All vault management requires Passkey approval
    const { approvalUrl, listenUrl, challengeId, expiresAt } = this.vaultManager.createApprovalChallenge(
      this.config.web.externalUrl,
      this.agentFingerprint,
      '*',
      [`manage_vault:${action}`]
    );

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          needsApproval: true,
          action,
          approvalUrl,
          listenUrl,
          challengeId,
          expiresAt,
          message: 'Vault management requires Passkey approval.',
        }, null, 2),
      }],
    };
  }

  private handleRevokeSession() {
    const session = this.vaultManager.getSessionByAgent(this.agentFingerprint);
    
    if (session) {
      this.vaultManager.revokeSession(session.id);
    }

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: true,
          message: 'Session revoked',
        }, null, 2),
      }],
    };
  }

  async start(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('SSH Vault MCP server started');
  }
}
