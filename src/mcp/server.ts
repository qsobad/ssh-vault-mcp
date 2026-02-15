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
import { verifySignedRequest, fingerprintFromPublicKey, type SignedRequest } from '../auth/agent.js';

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

// Common signature properties for authenticated tools
const SIGNATURE_PROPERTIES = {
  signature: {
    type: 'string',
    description: 'Ed25519 signature of the payload (base64)',
  },
  publicKey: {
    type: 'string',
    description: 'Agent Ed25519 public key (base64)',
  },
  timestamp: {
    type: 'number',
    description: 'Request timestamp in milliseconds',
  },
  nonce: {
    type: 'string',
    description: 'Random nonce for replay protection (base64)',
  },
};

const SIGNATURE_REQUIRED = ['signature', 'publicKey', 'timestamp', 'nonce'];

// Tool definitions
const TOOLS: Tool[] = [
  {
    name: 'vault_status',
    description: 'Check if the SSH vault is locked or unlocked, and session status. Requires signed request.',
    inputSchema: {
      type: 'object',
      properties: {
        ...SIGNATURE_PROPERTIES,
      },
      required: SIGNATURE_REQUIRED,
    },
  },
  {
    name: 'request_unlock',
    description: 'Request to unlock the vault. Returns a URL for Passkey authentication. Requires signed request.',
    inputSchema: {
      type: 'object',
      properties: {
        ...SIGNATURE_PROPERTIES,
      },
      required: SIGNATURE_REQUIRED,
    },
  },
  {
    name: 'submit_unlock',
    description: 'Submit the unlock code obtained from the signing page. Requires signed request.',
    inputSchema: {
      type: 'object',
      properties: {
        unlock_code: {
          type: 'string',
          description: 'The unlock code shown on the signing page after Passkey verification',
        },
        ...SIGNATURE_PROPERTIES,
      },
      required: ['unlock_code', ...SIGNATURE_REQUIRED],
    },
  },
  {
    name: 'list_hosts',
    description: 'List available SSH hosts (requires unlocked vault). Requires signed request.',
    inputSchema: {
      type: 'object',
      properties: {
        filter: {
          type: 'string',
          description: 'Filter hosts by name pattern (supports wildcards like dev-*)',
        },
        ...SIGNATURE_PROPERTIES,
      },
      required: SIGNATURE_REQUIRED,
    },
  },
  {
    name: 'execute_command',
    description: 'Execute a command on an SSH host. May require approval for commands outside policy. Requires signed request.',
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
        ...SIGNATURE_PROPERTIES,
      },
      required: ['host', 'command', ...SIGNATURE_REQUIRED],
    },
  },
  {
    name: 'manage_vault',
    description: 'Manage vault contents (add/remove hosts and agents). Requires Passkey confirmation. Requires signed request.',
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
        ...SIGNATURE_PROPERTIES,
      },
      required: ['action', 'data', ...SIGNATURE_REQUIRED],
    },
  },
  {
    name: 'revoke_session',
    description: 'Revoke the current session and lock the vault. Requires signed request.',
    inputSchema: {
      type: 'object',
      properties: {
        ...SIGNATURE_PROPERTIES,
      },
      required: SIGNATURE_REQUIRED,
    },
  },
  {
    name: 'generate_keypair',
    description: 'Generate a new Ed25519 keypair for agent authentication. Returns public key, private key, and fingerprint. Store the private key securely!',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  {
    name: 'request_access',
    description: 'Request access to SSH hosts. Returns a URL for user approval via Passkey. Agent will be auto-enlisted if not already registered.',
    inputSchema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          description: 'Agent name (e.g., "coding-agent")',
        },
        publicKey: {
          type: 'string',
          description: 'Agent Ed25519 public key (base64)',
        },
        requestedHosts: {
          type: 'array',
          items: { type: 'string' },
          description: 'Requested host patterns (e.g., ["dev-*", "staging-*"])',
        },
      },
      required: ['name', 'publicKey', 'requestedHosts'],
    },
  },
];

export class MCPServer {
  private server: Server;
  private vaultManager: VaultManager;
  private policyEngine: PolicyEngine;
  private sshExecutor: SSHExecutor;
  private config: Config;

  constructor(
    config: Config,
    vaultManager: VaultManager,
    _agentFingerprint?: string  // Deprecated: fingerprint now derived from signed requests
  ) {
    this.config = config;
    this.vaultManager = vaultManager;
    this.policyEngine = new PolicyEngine();
    this.sshExecutor = new SSHExecutor();

    this.server = new Server(
      { name: 'ssh-vault-mcp', version: '0.1.0' },
      { capabilities: { tools: {} } }
    );

    this.setupHandlers();
  }

  /**
   * Verify signed request and return agent fingerprint
   * Throws if verification fails
   */
  private verifyAgentSignature(args: Record<string, unknown>): string {
    // Check if signed request fields are present
    if (!args.signature || !args.publicKey || !args.timestamp || !args.nonce) {
      throw new Error('Missing signature fields. Requests must be signed with agent private key.');
    }

    // Extract payload (args without signature fields)
    const { signature, publicKey, timestamp, nonce, ...payload } = args;

    const signedRequest: SignedRequest = {
      payload: JSON.stringify(payload),
      signature: signature as string,
      publicKey: publicKey as string,
      timestamp: timestamp as number,
      nonce: nonce as string,
    };

    const result = verifySignedRequest(signedRequest);
    if (!result.valid) {
      throw new Error(`Signature verification failed: ${result.error}`);
    }

    return result.fingerprint!;
  }

  private setupHandlers(): void {
    // List tools handler
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return { tools: TOOLS };
    });

    // Call tool handler
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      const typedArgs = (args || {}) as Record<string, unknown>;

      try {
        // Tools that don't require signature (not yet registered)
        if (name === 'generate_keypair') {
          return this.handleGenerateKeypair();
        }
        if (name === 'request_access') {
          return this.handleRequestAccess(typedArgs);
        }

        // All other tools require signature verification
        const fingerprint = this.verifyAgentSignature(typedArgs);

        switch (name) {
          case 'vault_status':
            return this.handleVaultStatus(fingerprint);

          case 'request_unlock':
            return this.handleRequestUnlock(fingerprint);

          case 'submit_unlock':
            const unlockArgs = SubmitUnlockSchema.parse(typedArgs);
            return this.handleSubmitUnlock(unlockArgs.unlock_code, fingerprint);

          case 'list_hosts':
            const listArgs = ListHostsSchema.parse(typedArgs);
            return this.handleListHosts(listArgs.filter, fingerprint);

          case 'execute_command':
            const execArgs = ExecuteCommandSchema.parse(typedArgs);
            return this.handleExecuteCommand(
              execArgs.host,
              execArgs.command,
              execArgs.timeout,
              fingerprint
            );

          case 'manage_vault':
            const manageArgs = ManageVaultSchema.parse(typedArgs);
            return this.handleManageVault(manageArgs.action, manageArgs.data, fingerprint);

          case 'revoke_session':
            return this.handleRevokeSession(fingerprint);

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

  private handleGenerateKeypair() {
    const { generateAgentKeypair } = require('../auth/agent.js');
    const keypair = generateAgentKeypair();
    
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          publicKey: keypair.publicKey,
          privateKey: keypair.privateKey,
          fingerprint: keypair.fingerprint,
          warning: 'Store the private key securely! It cannot be recovered.',
        }, null, 2),
      }],
    };
  }

  private handleRequestAccess(args: Record<string, unknown>) {
    const name = args.name as string;
    const publicKey = args.publicKey as string;
    const requestedHosts = args.requestedHosts as string[];

    if (!requestedHosts || requestedHosts.length === 0) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ error: 'requestedHosts is required' }, null, 2),
        }],
        isError: true,
      };
    }

    // Validate public key and compute fingerprint
    let fingerprint: string;
    try {
      fingerprint = fingerprintFromPublicKey(publicKey);
    } catch {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ error: 'Invalid public key format' }, null, 2),
        }],
        isError: true,
      };
    }

    // Create access request challenge
    const { approvalUrl, listenUrl, challengeId, expiresAt } = this.vaultManager.createAccessRequestChallenge(
      this.config.web.externalUrl,
      {
        name,
        fingerprint,
        publicKey,
        requestedHosts,
      }
    );

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          status: 'pending_approval',
          fingerprint,
          approvalUrl,
          listenUrl,
          challengeId,
          expiresAt,
          message: 'Access request requires user approval.',
        }, null, 2),
      }],
    };
  }

  private handleVaultStatus(fingerprint: string) {
    const session = this.vaultManager.getSessionByAgent(fingerprint);
    
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          locked: !this.vaultManager.isUnlocked(),
          agentFingerprint: fingerprint,
          sessionId: session?.id,
          sessionExpires: session?.expiresAt,
        }, null, 2),
      }],
    };
  }

  private async handleRequestUnlock(fingerprint: string) {
    if (this.vaultManager.isUnlocked()) {
      const session = this.vaultManager.getSessionByAgent(fingerprint);
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
      fingerprint
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

  private async handleSubmitUnlock(unlockCode: string, fingerprint: string) {
    const result = await this.vaultManager.submitUnlockCode(
      unlockCode,
      fingerprint
    );

    return {
      content: [{
        type: 'text',
        text: JSON.stringify(result, null, 2),
      }],
    };
  }

  private handleListHosts(filter: string | undefined, _fingerprint: string) {
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
    timeout: number,
    fingerprint: string
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

    const agent = this.vaultManager.getAgent(fingerprint);
    if (!agent) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            error: `Agent not registered in vault. Fingerprint: ${fingerprint}`,
          }, null, 2),
        }],
        isError: true,
      };
    }

    const session = this.vaultManager.getSessionByAgent(fingerprint);
    const policy = this.vaultManager.getPolicy();

    // Check policy
    const policyResult = this.policyEngine.checkCommand(
      agent,
      host.name,
      command,
      policy,
      session || undefined
    );

    if (!policyResult.allowed) {
      // Need approval
      const { approvalUrl, listenUrl, challengeId, expiresAt } = this.vaultManager.createApprovalChallenge(
        this.config.web.externalUrl,
        fingerprint,
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

  private handleManageVault(action: string, _data: Record<string, unknown>, fingerprint: string) {
    // All vault management requires Passkey approval
    const { approvalUrl, listenUrl, challengeId, expiresAt } = this.vaultManager.createApprovalChallenge(
      this.config.web.externalUrl,
      fingerprint,
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

  private handleRevokeSession(fingerprint: string) {
    const session = this.vaultManager.getSessionByAgent(fingerprint);
    
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
