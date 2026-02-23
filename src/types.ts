// Core type definitions for SSH Vault MCP

export interface PasskeyCredential {
  id: string;                 // Credential ID (base64)
  publicKey: string;          // Public key (base64)
  algorithm: number;          // COSE algorithm (-7 = ES256, -257 = RS256)
  counter: number;            // Signature counter for replay protection
  createdAt: number;
}

export interface Host {
  id: string;
  name: string;               // "dev-01"
  hostname: string;           // "192.168.1.100"
  port: number;               // 22
  username: string;
  authType: "key" | "password";
  credential: string;         // Encrypted private key or password
  tags: string[];             // ["dev", "backend"]
  createdAt: number;
  updatedAt: number;
}

export interface AgentConfig {
  fingerprint: string;        // "SHA256:abc123..."
  name: string;               // "coding-agent"
  allowedHosts: string[];     // ["dev-*", "staging-*"]
  createdAt: number;
  lastUsed: number;
}

export interface GlobalPolicy {
  allowedCommands: string[];  // Global whitelist: ["ls", "cat", "grep", "pwd"]
  deniedCommands: string[];   // Global blacklist: ["rm -rf", "mkfs", "dd if="]
  allowShellOperators?: boolean; // Allow pipe, redirect, etc. (default: false)
}

export interface Session {
  id: string;
  agentFingerprint: string;
  approvedHosts: string[];
  approvedCommands: Record<string, string[]>; // host -> approved commands
  challengeId: string;
  createdAt: number;
  expiresAt: number;
}

export interface Vault {
  version: 1;
  owner: PasskeyCredential;
  credentials: PasskeyCredential[];  // All registered passkeys (includes owner)
  hosts: Host[];
  agents: AgentConfig[];
  policy: GlobalPolicy;
}

export interface VaultFileCredential {
  id: string;
  publicKey: string;
  algorithm: number;
  counter: number;
}

export interface VaultFile {
  version: 1;
  credentialId: string;       // Primary Passkey ID (base64) - backward compat
  publicKey: string;          // For signature verification (base64)
  algorithm: number;
  counter: number;
  credentials?: VaultFileCredential[];  // All registered passkeys
  passwordSalt: string;       // For password-based key derivation (base64)
  salt: string;               // For encryption key derivation (base64)
  nonce: string;              // For encryption (base64)
  data: string;               // Encrypted vault data (base64)
  kdfParams?: {               // Argon2id parameters (absent in legacy vaults)
    t: number;                // time cost (iterations)
    m: number;                // memory cost (KiB)
    p: number;                // parallelism
    dkLen: number;            // derived key length
  };
}

export interface UnlockChallenge {
  id: string;
  action: "unlock_vault" | "approve_command" | "request_access";
  timestamp: number;
  nonce: string;
  expiresAt: number;
  
  // For approve_command
  agent?: string;
  host?: string;
  commands?: string[];
  
  // For request_access (agent requesting host access)
  accessRequest?: {
    name: string;
    fingerprint: string;
    publicKey: string;
    requestedHosts: string[];
  };
}

export interface Config {
  server: {
    port: number;
    host: string;
  };
  vault: {
    path: string;
    backup: boolean;
  };
  webauthn: {
    rpId: string;
    rpName: string;
    origin: string;
  };
  web: {
    port: number;
    externalUrl: string;
  };
  session: {
    mode: "single" | "session" | "time_window";
    timeoutMinutes: number;
  };
  autoLockMinutes?: number;
  logging: {
    level: string;
    file?: string;
  };
}

// MCP Tool responses
export interface VaultStatusResponse {
  locked: boolean;
  sessionId?: string;
  sessionExpires?: number;
}

export interface RequestUnlockResponse {
  unlockUrl: string;
  challengeId: string;
  expiresAt: number;
}

export interface SubmitUnlockResponse {
  success: boolean;
  sessionId?: string;
  expires?: number;
  error?: string;
}

export interface ExecuteCommandResponse {
  success: boolean;
  output?: string;
  exitCode?: number;
  needsApproval?: boolean;
  approvalUrl?: string;
  error?: string;
}
