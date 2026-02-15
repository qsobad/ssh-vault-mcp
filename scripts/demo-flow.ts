/**
 * Demo: Full SSH Vault MCP Flow
 */
import { VaultManager } from '../src/vault/vault.js';
import { PolicyEngine } from '../src/policy/engine.js';
import { initSodium, deriveKeyFromSignature } from '../src/vault/encryption.js';

async function demo() {
  await initSodium();
  
  const vaultManager = new VaultManager('./data/vault.enc', {
    sessionTimeoutMinutes: 30,
  });
  await vaultManager.init();

  console.log('=== SSH Vault MCP Demo ===\n');

  // Step 1: Check status
  console.log('Step 1: Check Vault Status');
  console.log('  Vault exists:', await vaultManager.vaultExists());
  console.log('  Is unlocked:', vaultManager.isUnlocked());

  // Step 2: Unlock vault (simulating successful auth)
  console.log('\nStep 2: Unlocking Vault...');
  const metadata = await vaultManager.getMetadata();
  if (!metadata) {
    console.error('No vault found!');
    return;
  }

  // Derive VEK
  const serverSecret = new TextEncoder().encode('ssh-vault-server-secret-' + metadata.credentialId);
  const salt = new TextEncoder().encode('ssh-vault-static-salt');
  const vek = deriveKeyFromSignature(serverSecret, salt.slice(0, 16));

  // Load vault directly (simulating post-auth state)
  const { VaultStorage } = await import('../src/vault/storage.js');
  const storage = new VaultStorage('./data/vault.enc', false);
  const vault = await storage.load(vek);
  
  console.log('  Vault unlocked successfully!');

  // Step 3: List hosts
  console.log('\nStep 3: List Hosts');
  for (const host of vault.hosts) {
    console.log(`  - ${host.name} (${host.hostname}:${host.port})`);
  }

  // Step 4: Check policy for commands
  console.log('\nStep 4: Policy Check');
  const policyEngine = new PolicyEngine();
  const agent = vault.agents[0];
  
  if (!agent) {
    console.error('No agent configured!');
    return;
  }
  
  console.log(`  Agent: ${agent.name}`);
  console.log(`  Allowed hosts: ${agent.allowedHosts.join(', ')}`);
  console.log(`  Allowed commands: ${agent.allowedCommands.join(', ')}`);
  console.log(`  Denied commands: ${agent.deniedCommands.join(', ')}`);

  // Test commands
  const testCommands = [
    { host: 'test-server', cmd: 'whoami' },
    { host: 'test-server', cmd: 'ls -la' },
    { host: 'test-server', cmd: 'cat /etc/hostname' },
    { host: 'test-server', cmd: 'rm -rf /' },
    { host: 'test-server', cmd: 'sudo reboot' },
    { host: 'prod-server', cmd: 'ls' },
  ];

  console.log('\nStep 5: Command Policy Tests');
  for (const { host, cmd } of testCommands) {
    const result = policyEngine.checkCommand(agent, host, cmd);
    const status = result.allowed ? '✅ ALLOWED' : '❌ DENIED';
    console.log(`  ${host}> ${cmd}`);
    console.log(`    ${status} - ${result.reason}`);
  }

  console.log('\n=== Demo Complete ===');
}

demo().catch(console.error);
