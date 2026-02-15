/**
 * Add test SSH host and agent to vault
 */

import { VaultStorage } from '../src/vault/storage.js';
import { deriveKeyFromSignature } from '../src/vault/encryption.js';

async function main() {
  const vaultPath = './data/vault.enc';
  const storage = new VaultStorage(vaultPath, false);

  // Check if vault exists
  const metadata = await storage.getMetadata();
  if (!metadata) {
    console.error('No vault found. Please register first.');
    process.exit(1);
  }

  // Derive VEK using same method as server
  const serverSecret = new TextEncoder().encode('ssh-vault-server-secret-' + metadata.credentialId);
  const salt = new TextEncoder().encode('ssh-vault-static-salt');
  const vek = deriveKeyFromSignature(serverSecret, salt.slice(0, 16));

  // Load vault
  const vault = await storage.load(vek);
  console.log('Vault loaded successfully');
  console.log('Current hosts:', vault.hosts.length);
  console.log('Current agents:', vault.agents.length);

  // Add test host (this server)
  const testHost = {
    id: 'test-server-01',
    name: 'test-server',
    hostname: '127.0.0.1',
    port: 22,
    username: 'root',
    authType: 'key' as const,
    credential: '(ssh-key-placeholder)',  // Would be actual SSH key
    tags: ['test', 'local'],
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };

  // Check if host already exists
  const existingHost = vault.hosts.find(h => h.id === testHost.id);
  if (!existingHost) {
    vault.hosts.push(testHost);
    console.log('Added test host:', testHost.name);
  } else {
    console.log('Test host already exists');
  }

  // Add test agent
  const testAgent = {
    fingerprint: 'SHA256:test-agent-fingerprint',
    name: 'demo-agent',
    allowedHosts: ['test-*', 'dev-*'],
    allowedCommands: ['ls', 'cat', 'echo', 'pwd', 'whoami'],
    deniedCommands: ['rm', 'sudo', 'reboot'],
    createdAt: Date.now(),
    lastUsed: Date.now(),
  };

  const existingAgent = vault.agents.find(a => a.fingerprint === testAgent.fingerprint);
  if (!existingAgent) {
    vault.agents.push(testAgent);
    console.log('Added test agent:', testAgent.name);
  } else {
    console.log('Test agent already exists');
  }

  // Save vault
  await storage.save(vault, vek);
  console.log('Vault saved successfully');
  
  console.log('\n--- Vault Contents ---');
  console.log('Hosts:', vault.hosts.map(h => ({ name: h.name, hostname: h.hostname })));
  console.log('Agents:', vault.agents.map(a => ({ name: a.name, fingerprint: a.fingerprint })));
}

main().catch(console.error);
