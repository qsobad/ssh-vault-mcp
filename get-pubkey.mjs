import { VaultStorage } from './dist/vault/storage.js';
import { deriveKeyFromSignature } from './dist/vault/encryption.js';
import { writeFileSync } from 'fs';

const storage = new VaultStorage('./data/vault.enc', false);
const meta = await storage.getMetadata();
const serverSecret = new TextEncoder().encode('ssh-vault-server-secret-' + meta.credentialId);
const salt = new TextEncoder().encode('ssh-vault-static-salt');
const vek = deriveKeyFromSignature(serverSecret, salt.slice(0, 16));
const vault = await storage.load(vek);

const host = vault.hosts.find(h => h.name === 's1');
writeFileSync('/tmp/s1.key', host.credential);
console.log('Private key saved to /tmp/s1.key');
