#!/usr/bin/env node
/**
 * SSH Vault MCP - Main Entry Point
 * 
 * A secure SSH credential vault with MCP interface and Passkey authentication.
 */

import { loadConfig, validateConfig } from './config.js';
import { VaultManager } from './vault/vault.js';
import { MCPServer } from './mcp/server.js';
import { WebServer } from './web/server.js';
import { initSodium } from './vault/encryption.js';

async function main() {
  console.error('SSH Vault MCP starting...');

  // Load configuration
  const configPath = process.env.SSH_VAULT_CONFIG;
  const config = await loadConfig(configPath);

  // Validate configuration
  const validation = validateConfig(config);
  if (!validation.valid) {
    console.error('Configuration errors:');
    for (const error of validation.errors) {
      console.error(`  - ${error}`);
    }
    process.exit(1);
  }

  // Initialize sodium
  await initSodium();
  console.error('Encryption initialized');

  // Initialize vault manager
  const vaultManager = new VaultManager(config.vault.path, {
    sessionTimeoutMinutes: config.session.timeoutMinutes,
    backupEnabled: config.vault.backup,
    autoLockMinutes: config.autoLockMinutes,
  });
  await vaultManager.init();

  // Check if vault exists
  const vaultExists = await vaultManager.vaultExists();
  if (!vaultExists) {
    console.error('No vault found. Please set up the vault using the web interface.');
  }

  // Get agent fingerprint from environment or generate placeholder
  const agentFingerprint = process.env.SSH_VAULT_AGENT_FINGERPRINT || 'SHA256:unknown';

  // Start web server for Passkey authentication
  const webServer = new WebServer(config, vaultManager);
  await webServer.start();
  console.error(`Web server started on ${config.web.externalUrl}`);

  // Start MCP server
  const mcpServer = new MCPServer(config, vaultManager, agentFingerprint);
  await mcpServer.start();

  // Handle graceful shutdown
  process.on('SIGINT', () => {
    console.error('Shutting down...');
    vaultManager.lock();
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    console.error('Shutting down...');
    vaultManager.lock();
    process.exit(0);
  });
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
