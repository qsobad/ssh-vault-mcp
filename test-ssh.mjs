import { Client } from 'ssh2';

// 先获取 host 配置
const res = await fetch('https://ssh.29cp.cn/api/vault/execute', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ host: 's1', command: 'echo test' })
});
console.log('API response:', await res.text());
