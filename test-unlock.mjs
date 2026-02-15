import nacl from 'tweetnacl';
import crypto from 'crypto';

const privateKeyB64 = '1j2Jhhh5u/yUdIS7DD7jacYte+TwxuGv83yMNm8ZVlXiLD2U2BneaZwYICiP19WbMXkjcWyYRbhL4X1VsGD2ug==';
const publicKey = '4iw9lNgZ3mmcGCAoj9fVmzF5I3FsmEW4S+F9VbBg9ro=';

const timestamp = Date.now();
const nonce = crypto.randomUUID();
const tool = 'request_unlock';

const message = JSON.stringify({ tool, timestamp, nonce });
const msgBytes = new TextEncoder().encode(message);
const secretKey = Buffer.from(privateKeyB64, 'base64'); // Full 64-byte secret key

const signature = nacl.sign.detached(msgBytes, secretKey);
const sigB64 = Buffer.from(signature).toString('base64');

console.log('Request:', { tool, timestamp, nonce });

const body = {
  publicKey,
  timestamp,
  nonce,
  signature: sigB64
};

const res = await fetch('https://ssh.29cp.cn/api/mcp/request_unlock', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body)
});

console.log('Response:', await res.json());
