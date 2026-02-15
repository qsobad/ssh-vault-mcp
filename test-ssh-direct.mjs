import { Client } from 'ssh2';
import { VaultStorage } from './dist/vault/storage.js';
import { deriveKeyFromSignature } from './dist/vault/encryption.js';

const storage = new VaultStorage('./data/vault.enc', false);
const meta = await storage.getMetadata();
const serverSecret = new TextEncoder().encode('ssh-vault-server-secret-' + meta.credentialId);
const salt = new TextEncoder().encode('ssh-vault-static-salt');
const vek = deriveKeyFromSignature(serverSecret, salt.slice(0, 16));
const vault = await storage.load(vek);

const host = vault.hosts.find(h => h.name === 's1');
console.log('Connecting to:', host.hostname, 'as', host.username);
console.log('Key preview:', host.credential.substring(0, 100));

const ssh = new Client();
ssh.on('ready', () => {
  console.log('SSH Connected!');
  ssh.exec('echo "SUCCESS"', (err, stream) => {
    if (err) { console.error(err); ssh.end(); return; }
    stream.on('data', d => console.log('Output:', d.toString()));
    stream.on('close', () => ssh.end());
  });
});
ssh.on('error', (err) => {
  console.error('SSH Error:', err.message);
  console.error('Level:', err.level);
});
ssh.connect({
  host: host.hostname,
  port: 22,
  username: host.username,
  privateKey: host.credential,
  debug: (msg) => { if (msg.includes('Auth') || msg.includes('key')) console.log('DEBUG:', msg); }
});
