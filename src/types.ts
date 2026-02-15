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
  allowedCommands: string[];  // ["ls", "cat", "grep"]
  deniedCommands: string[];   // ["rm", "sudo"]
  createdAt: number;
  lastUsed: number;
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
  hosts: Host[];
  agents: AgentConfig[];
}

export interface VaultFile {
  version: 1;
  credentialId: string;       // Passkey ID (base64)
  publicKey: string;          // For signature verification (base64)
  algorithm: number;
  counter: number;
  salt: string;               // For key derivation (base64)
  nonce: string;              // For encryption (base64)
  data: string;               // Encrypted vault data (base64)
}

export interface UnlockChallenge {
  id: string;
  action: "unlock_vault" | "approve_command";
  timestamp: number;
  nonce: string;
  expiresAt: number;
  
  // For approve_command
  agent?: string;
  host?: string;
  commands?: string[];
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
