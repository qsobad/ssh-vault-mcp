// Quick debug script to check host config
const { VaultStorage } = await import('./dist/vault/storage.js');
const { deriveKeyFromSignature } = await import('./dist/vault/encryption.js');

// Get metadata
const storage = new VaultStorage('./data/vault.enc', false);
const meta = await storage.getMetadata();
console.log('Credential ID:', meta.credentialId);

// Derive VEK (same as server)
const serverSecret = new TextEncoder().encode('ssh-vault-server-secret-' + meta.credentialId);
const salt = new TextEncoder().encode('ssh-vault-static-salt');
const vek = deriveKeyFromSignature(serverSecret, salt.slice(0, 16));

// Load vault
const vault = await storage.load(vek);
console.log('\nHosts:');
vault.hosts.forEach(h => {
  console.log(`  ${h.name}:`);
  console.log(`    hostname: ${h.hostname}`);
  console.log(`    username: ${h.username}`);
  console.log(`    authType: ${h.authType}`);
  console.log(`    credential length: ${h.credential?.length || 0}`);
  console.log(`    credential starts: ${h.credential?.substring(0, 50) || 'EMPTY'}`);
});
