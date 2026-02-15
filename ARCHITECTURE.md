# SSH Vault MCP - 架构设计

## 概述

一个安全的 SSH 凭证管理系统，允许 AI Agent 在人工授权下访问 SSH 服务器。

### 核心原则

- **三方授权**: Target（目标机器）、Vault（凭证存储）、Agent 互相验证
- **无中间人**: MCP 不代理 SSH 连接，只做策略和签名验证
- **用户主权**: 所有授权需要用户 Passkey 签名 (Face ID / 指纹)

---

## 架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                         用户 (Owner)                             │
│                    Passkey: Face ID / 指纹                       │
│                    解锁 Vault + 授权操作                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ WebAuthn 签名
                              ▼
┌──────────────────────────────────────┐
│          签名页面 (Web)               │
│   https://vault.example.com/sign     │
│                                      │
│   - 显示解锁请求                      │
│   - Passkey 验证                     │
│   - 返回解锁码 / WebSocket 回调       │
└──────────────────────────────────────┘
                              │
                              │ 解锁码 / 签名
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      SSH Vault MCP Server                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ Policy      │  │ WebAuthn    │  │ Vault       │              │
│  │ Engine      │  │ Verifier    │  │ Storage     │              │
│  │             │  │             │  │ (encrypted) │              │
│  │ - 规则匹配   │  │ - 验证签名   │  │ - 凭证加密   │              │
│  │ - 白名单    │  │ - 派生 VEK  │  │ - libsodium │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
│                                                                  │
│  MCP Tools:                                                      │
│  - list_hosts()      - request_access()                         │
│  - submit_unlock()   - execute_command()                        │
│  - manage_vault()    - revoke_session()                         │
└─────────────────────────────────────────────────────────────────┘
        │                                               │
        │ HTTP+SSE                                      │ SSH
        ▼                                               ▼
┌──────────────┐                              ┌──────────────┐
│    Agent     │                              │   Target     │
│              │                              │   Server     │
│ SSH Key:     │                              │              │
│ SHA256:xyz   │                              │ 接受连接      │
└──────────────┘                              └──────────────┘
```

---

## 三方密钥体系

```yaml
User (Owner):
  - type: Passkey (WebAuthn)
  - public: 注册时生成的公钥
  - private: 设备安全芯片 (Secure Enclave / TPM)
  - auth: Face ID / 指纹 / PIN
  - purpose: 签名解锁 Vault + 授权请求

Agent:
  - type: Ed25519 SSH Key
  - public: SHA256 fingerprint
  - private: Agent 本地保管
  - purpose: 身份证明

Vault:
  - type: X25519 + XSalsa20
  - encryption_key: 从 Passkey 签名派生 (见下文)
  - purpose: 加密存储凭证

Target:
  - type: SSH Host Key
  - purpose: 服务器身份验证
```

---

## 授权流程

### 1. 规则内操作（自动通过）

```
Agent                    MCP Server                    Target
  │                          │                           │
  │ execute_command()        │                           │
  │ host: dev-01             │                           │
  │ cmd: "ls -la"            │                           │
  │ ─────────────────────────►                           │
  │                          │                           │
  │        检查 Agent 规则    │                           │
  │        dev-* + ls ✓      │                           │
  │                          │                           │
  │                          │ SSH connect               │
  │                          │ ──────────────────────────►
  │                          │                           │
  │◄───────────────────────── │ ◄──────────────────────────
  │         结果返回          │                           │
```

### 2. 规则外操作（需要 Passkey 确认）

```
Agent              MCP Server         签名页面          User
  │                    │                 │               │
  │ execute_command()  │                 │               │
  │ host: prod-01      │                 │               │
  │ cmd: "rm file"     │                 │               │
  │ ────────────────────►                │               │
  │                    │                 │               │
  │   检查规则: 不在白名单                 │               │
  │   生成 approval challenge            │               │
  │                    │                 │               │
  │◄──────────────────── │                │               │
  │ { needs_approval }  │                │               │
  │ { approval_url }    │                │               │
  │                    │                 │               │
  │ "请访问此链接确认"   │                 │               │
  │ ──────────────────────────────────────────────────────►
  │                    │                 │               │
  │                    │                 │  打开签名页面  │
  │                    │                 │ ◄──────────────
  │                    │                 │               │
  │                    │                 │  显示操作详情  │
  │                    │                 │  "允许 rm..."  │
  │                    │                 │               │
  │                    │                 │  Passkey 验证  │
  │                    │                 │  (Face ID)    │
  │                    │                 │ ◄──────────────
  │                    │                 │               │
  │                    │  签名验证通过    │               │
  │                    │ ◄─────────────── │               │
  │                    │                 │               │
  │                    │ 返回解锁码给用户  │               │
  │                    │ ─────────────────►               │
  │                    │                 │               │
  │◄────────────────────────────────────────────────────── │
  │ "解锁码: XXXX"      │                │               │
  │                    │                 │               │
  │ submit_unlock()    │                 │               │
  │ code: "XXXX"       │                 │               │
  │ ────────────────────►                │               │
  │                    │                 │               │
  │◄──────────────────── │                │               │
  │ { approved: true }  │                │               │
  │                    │                 │               │
  │ execute_command()  │                 │               │
  │ ────────────────────►                │               │
  │        ...         │                 │               │
```

---

## 数据结构

### Vault 存储 (加密)

```typescript
interface Vault {
  version: 1;
  owner: PasskeyCredential;   // Passkey 公钥信息
  hosts: Host[];
  agents: AgentConfig[];
  sessions: Session[];
}

interface PasskeyCredential {
  id: string;                 // Credential ID (base64)
  publicKey: string;          // 公钥 (base64)
  algorithm: number;          // COSE algorithm (-7 = ES256, -257 = RS256)
  createdAt: number;
}

interface Host {
  id: string;
  name: string;               // "dev-01"
  hostname: string;           // "192.168.1.100"
  port: number;               // 22
  username: string;
  authType: "key" | "password";
  credential: string;         // 加密的私钥或密码
  tags: string[];             // ["dev", "backend"]
}

interface AgentConfig {
  fingerprint: string;        // "SHA256:abc123..."
  name: string;               // "coding-agent"
  allowedHosts: string[];     // ["dev-*", "staging-*"]
  allowedCommands: string[];  // ["ls", "cat", "grep"]
  deniedCommands: string[];   // ["rm", "sudo"]
  createdAt: number;
  lastUsed: number;
}

interface Session {
  id: string;
  agentFingerprint: string;
  approvedHosts: string[];    // 本 session 已解锁的主机
  approvedCommands: Record<string, string[]>; // host → 已批准的命令
  challengeId: string;        // WebAuthn challenge ID
  createdAt: number;
  expiresAt: number;
}
```

### WebAuthn 挑战结构

```typescript
interface UnlockChallenge {
  action: "unlock_vault" | "approve_command";
  timestamp: number;
  nonce: string;           // 随机数防重放
  
  // unlock_vault 时为空
  // approve_command 时包含操作详情
  agent?: string;          // "SHA256:abc123..."
  host?: string;           // "prod-01"
  commands?: string[];     // ["rm /tmp/file"]
}

// 服务器生成 challenge
function generateChallenge(action: string, details?: object): Uint8Array {
  const challenge: UnlockChallenge = {
    action,
    timestamp: Date.now(),
    nonce: crypto.randomUUID(),
    ...details,
  };
  return new TextEncoder().encode(JSON.stringify(challenge));
}
```

---

## 加密方案 (Passkey + libsodium)

### Vault 解锁流程

```
Agent 请求访问
      │
      ▼
MCP: "Vault 锁定，请访问签名页面"
返回: { status: "locked", unlock_url: "https://..." }
      │
      ▼
Agent 展示链接给用户
      │
      ▼
用户打开页面 → Passkey 验证 (Face ID / 指纹)
      │
      ▼
页面显示解锁码 (或自动回调)
      │
      ▼
Agent 提交解锁码到 MCP
      │
      ▼
MCP 解锁 Vault，Session 开始
```

### Passkey 签名作为密钥

```typescript
// 首次注册 (Setup)
const credential = await navigator.credentials.create({
  publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { name: "SSH Vault", id: "vault.example.com" },
    user: {
      id: userId,
      name: userEmail,
      displayName: userName,
    },
    pubKeyCredParams: [
      { alg: -7, type: "public-key" },   // ES256
      { alg: -257, type: "public-key" }, // RS256
    ],
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      residentKey: "required",
      userVerification: "required",
    },
  },
});

// 存储公钥，用于后续验证
savePublicKey(credential.response.getPublicKey());
```

```typescript
// 每次解锁 (Unlock)
const assertion = await navigator.credentials.get({
  publicKey: {
    challenge: serverChallenge,  // 服务器生成的随机挑战
    allowCredentials: [{
      id: storedCredentialId,
      type: "public-key",
    }],
    userVerification: "required",
  },
});

// 签名结果用于派生 VEK
const signature = assertion.response.signature;
const VEK = await deriveVaultKey(signature, salt);
```

### 密钥派生

```typescript
import { crypto_pwhash, crypto_secretbox } from 'libsodium-wrappers';

// Passkey signature → Vault Encryption Key
async function deriveVaultKey(signature: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
  // 使用签名作为"密码"输入 Argon2id
  const key = crypto_pwhash(
    32, // key length
    signature,
    salt,
    crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_MEMLIMIT_INTERACTIVE,
    crypto_pwhash_ALG_ARGON2ID13
  );
  return key;
}
```

### Vault 加密

```typescript
// 加密
const nonce = randombytes_buf(24);
const encrypted = crypto_secretbox_easy(
  JSON.stringify(vaultData),
  nonce,
  VEK
);

// 存储格式
const vaultFile = {
  version: 1,
  credentialId: base64(credentialId),  // Passkey ID
  publicKey: base64(publicKey),        // 用于验证签名
  salt: base64(salt),
  nonce: base64(nonce),
  data: base64(encrypted),
};
```

### 签名页面流程

```
┌─────────────────────────────────────┐
│         SSH Vault 解锁              │
│                                     │
│     Challenge: abc123...            │
│                                     │
│     ┌─────────────────────┐        │
│     │    🔐 使用 Passkey   │        │
│     │    Face ID / 指纹    │        │
│     └─────────────────────┘        │
│                                     │
│   验证成功后显示解锁码:              │
│   ┌─────────────────────┐          │
│   │     UNLOCK-X7K9P2   │          │
│   └─────────────────────┘          │
│                                     │
│   或自动通过 WebSocket 通知 MCP      │
└─────────────────────────────────────┘
```

---

## MCP Tools 定义

```typescript
const tools = [
  {
    name: "vault_status",
    description: "检查 Vault 状态",
    inputSchema: {
      type: "object",
      properties: {}
    }
    // 返回: { locked: boolean, session_expires?: number }
  },
  {
    name: "request_unlock",
    description: "请求解锁 Vault，返回签名页面 URL",
    inputSchema: {
      type: "object",
      properties: {}
    }
    // 返回: { unlock_url: string, challenge_id: string }
  },
  {
    name: "submit_unlock",
    description: "提交解锁码完成解锁",
    inputSchema: {
      type: "object",
      properties: {
        unlock_code: { type: "string", description: "用户在签名页面获取的解锁码" }
      },
      required: ["unlock_code"]
    }
    // 返回: { success: boolean, session_id: string, expires: number }
  },
  {
    name: "list_hosts",
    description: "列出可用的 SSH 主机 (需要 Vault 已解锁)",
    inputSchema: {
      type: "object",
      properties: {
        filter: { type: "string", description: "主机名过滤 (支持通配符)" }
      }
    }
  },
  {
    name: "execute_command",
    description: "在已授权的主机上执行命令",
    inputSchema: {
      type: "object",
      properties: {
        host: { type: "string" },
        command: { type: "string" },
        timeout: { type: "number", default: 30 }
      },
      required: ["host", "command"]
    }
    // 如果命令不在白名单，返回 { needs_approval: true, approval_url: string }
  },
  {
    name: "manage_vault",
    description: "管理 Vault (需要 Passkey 确认)",
    inputSchema: {
      type: "object",
      properties: {
        action: { 
          type: "string", 
          enum: ["add_host", "remove_host", "update_host", "add_agent", "remove_agent"]
        },
        data: { type: "object" }
      },
      required: ["action", "data"]
    }
    // 返回 approval_url，用户确认后生效
  },
  {
    name: "revoke_session",
    description: "撤销当前会话",
    inputSchema: {
      type: "object",
      properties: {}
    }
  }
];
```

---

## 目录结构

```
ssh-vault-mcp/
├── ARCHITECTURE.md          # 本文档
├── README.md
├── package.json
├── tsconfig.json
├── Dockerfile
├── docker-compose.yml
│
├── src/
│   ├── index.ts             # MCP Server 入口
│   ├── mcp/
│   │   ├── server.ts        # MCP Server 实现
│   │   ├── tools.ts         # Tool handlers
│   │   └── transport.ts     # HTTP+SSE transport
│   │
│   ├── vault/
│   │   ├── vault.ts         # Vault 主逻辑
│   │   ├── encryption.ts    # libsodium 加密
│   │   └── storage.ts       # 文件存储
│   │
│   ├── policy/
│   │   ├── engine.ts        # 策略引擎
│   │   ├── rules.ts         # 规则匹配
│   │   └── types.ts         # 类型定义
│   │
│   ├── auth/
│   │   ├── webauthn.ts      # WebAuthn/Passkey 验证
│   │   ├── agent.ts         # Agent 身份验证
│   │   └── session.ts       # Session 管理
│   │
│   ├── ssh/
│   │   ├── client.ts        # SSH 连接
│   │   └── executor.ts      # 命令执行
│   │
│   └── web/
│       ├── server.ts        # 签名页面 HTTP 服务
│       └── routes.ts        # API 路由
│
├── web/                      # 签名页面前端
│   ├── index.html           # 主页面
│   ├── sign.ts              # Passkey 签名逻辑
│   ├── style.css
│   └── vite.config.ts
│
├── skill/
│   └── SKILL.md             # Agent 使用指南
│
└── tests/
    ├── vault.test.ts
    ├── policy.test.ts
    └── webauthn.test.ts
```

---

## 配置文件

```yaml
# config.yml
server:
  port: 3000
  host: 0.0.0.0

vault:
  path: ./data/vault.enc
  backup: true

webauthn:
  rp_id: "vault.example.com"          # Relying Party ID
  rp_name: "SSH Vault"
  origin: "https://vault.example.com"
  
web:
  port: 3001                          # 签名页面端口
  external_url: "https://vault.example.com"

session:
  mode: session              # single | session | time_window
  timeout_minutes: 30        # Session 有效期
  
logging:
  level: info
  file: ./logs/ssh-vault.log
```

---

## 安全考虑

### 已覆盖
- ✅ 凭证本地加密 (Argon2id + XSalsa20)
- ✅ 用户主权签名 (Passkey/WebAuthn)
- ✅ Agent 身份验证 (SSH fingerprint)
- ✅ 无中间人架构
- ✅ Session 级别授权
- ✅ 硬件安全模块 (Secure Enclave / TPM)
- ✅ 生物识别 (Face ID / 指纹)

### 待实现
- ⏳ 审计日志
- ⏳ 速率限制
- ⏳ IP 白名单
- ⏳ 多 Passkey 支持 (备用设备)
- ⏳ 恢复机制 (Passkey 丢失时)

### 安全模型

```
攻击场景                        防护
─────────────────────────────────────────────
Vault 文件被偷                  Passkey 签名才能解密 ✅
MCP 服务器被攻破 (运行时)        VEK 只在 session 内存在 ✅
Agent 被劫持                    规则外操作需要 Passkey 确认 ✅
签名页面被钓鱼                   检查 origin，Passkey 绑定域名 ✅
Passkey 设备丢失                需要恢复机制 ⚠️
```

---

## 下一步

1. [ ] 初始化项目 + 依赖
2. [ ] 实现 Vault 加密存储 (libsodium)
3. [ ] 实现 Policy Engine (规则匹配)
4. [ ] 实现 WebAuthn/Passkey 验证
5. [ ] 实现 MCP Server + Tools
6. [ ] 签名页面 (Web + Passkey)
7. [ ] SSH 连接执行模块
8. [ ] Docker 打包
9. [ ] SKILL.md 编写
10. [ ] 测试

---

## 版本

- v0.1.0 - 初始架构设计
