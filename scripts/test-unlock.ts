/**
 * Test: Create unlock challenge and wait for user auth
 */
import { VaultManager } from '../src/vault/vault.js';
import { initSodium } from '../src/vault/encryption.js';

async function main() {
  await initSodium();
  
  const vaultManager = new VaultManager('./data/vault.enc', {
    sessionTimeoutMinutes: 30,
  });
  await vaultManager.init();

  console.log('Creating vault unlock challenge...\n');
  
  // Create unlock challenge (simulating what MCP request_unlock does)
  const { challengeId, unlockUrl, listenUrl } = vaultManager.createUnlockChallenge(
    'https://ssh.29cp.cn',
    'SHA256:test-agent-fingerprint'
  );

  console.log('=== Unlock Challenge Created ===');
  console.log('Challenge ID:', challengeId);
  console.log('');
  console.log('请打开此链接进行 Face ID 验证:');
  console.log(unlockUrl);
  console.log('');
  console.log('SSE Listen URL:', listenUrl);
  console.log('');
  console.log('等待用户认证... (5分钟超时)');

  // Wait for challenge to be completed
  const checkInterval = setInterval(async () => {
    const challenge = vaultManager.getChallenge(challengeId);
    if (!challenge) {
      console.log('\nChallenge expired or completed.');
      clearInterval(checkInterval);
      process.exit(0);
    }
  }, 5000);

  // Subscribe to events
  const unsubscribe = vaultManager.subscribeToChallenge(challengeId, (event) => {
    console.log('\n=== Event Received ===');
    console.log(JSON.stringify(event, null, 2));
    
    if (event.type === 'approved') {
      console.log('\n✅ 认证成功！Session ID:', event.sessionId);
      clearInterval(checkInterval);
      unsubscribe();
      process.exit(0);
    }
  });
}

main().catch(console.error);
