/**
 * Configuration loader
 */

import { promises as fs } from 'fs';
import path from 'path';
import { parse as parseYaml } from 'yaml';
import type { Config } from './types.js';

const DEFAULT_CONFIG: Config = {
  server: {
    port: 3000,
    host: '0.0.0.0',
  },
  vault: {
    path: './data/vault.enc',
    backup: true,
  },
  webauthn: {
    rpId: 'localhost',
    rpName: 'SSH Vault',
    origin: 'http://localhost:3001',
  },
  web: {
    port: 3001,
    externalUrl: 'http://localhost:3001',
  },
  session: {
    mode: 'session',
    timeoutMinutes: 30,
  },
  logging: {
    level: 'info',
  },
};

const DEFAULT_CONFIG_PATH = '/app/config/config.yml';

const LOCALHOST_CONFIG = `server:
  port: 3000
  host: 0.0.0.0

vault:
  path: /app/data/vault.enc
  backup: true

webauthn:
  rp_id: "localhost"
  rp_name: "SSH Vault"
  origin: "http://localhost:3001"

web:
  port: 3001
  external_url: "http://localhost:3001"

session:
  mode: session
  timeout_minutes: 15

logging:
  level: info
`;

export async function loadConfig(configPath?: string): Promise<Config> {
  const searchPaths = [
    configPath,
    DEFAULT_CONFIG_PATH,
    './config.yml',
    './config.yaml',
    './ssh-vault.yml',
    './ssh-vault.yaml',
    path.join(process.env.HOME || '', '.ssh-vault/config.yml'),
  ].filter(Boolean) as string[];

  for (const p of searchPaths) {
    try {
      const content = await fs.readFile(p, 'utf-8');
      const parsed = parseYaml(content);
      return applyEnvOverrides(mergeConfig(DEFAULT_CONFIG, parsed));
    } catch {
      // Try next path
    }
  }

  // No config file found — create default localhost config
  try {
    await fs.mkdir(path.dirname(DEFAULT_CONFIG_PATH), { recursive: true });
    await fs.writeFile(DEFAULT_CONFIG_PATH, LOCALHOST_CONFIG, 'utf-8');
    console.error(`No config found. Created default localhost config at ${DEFAULT_CONFIG_PATH}`);
    const parsed = parseYaml(LOCALHOST_CONFIG);
    return applyEnvOverrides(mergeConfig(DEFAULT_CONFIG, parsed));
  } catch {
    // Fall back to env-only config
    return applyEnvOverrides(DEFAULT_CONFIG);
  }
}

/**
 * Apply environment variable overrides.
 * Supports: SSH_VAULT_ORIGIN, SSH_VAULT_PORT, SSH_VAULT_DATA_PATH, PORT
 */
function applyEnvOverrides(config: Config): Config {
  const origin = process.env.SSH_VAULT_ORIGIN;
  const port = process.env.SSH_VAULT_PORT || process.env.PORT;
  const dataPath = process.env.SSH_VAULT_DATA_PATH;

  if (origin) {
    const url = new URL(origin);
    config.webauthn.rpId = url.hostname;
    config.webauthn.origin = origin;
    config.web.externalUrl = origin;
  }

  if (port) {
    config.web.port = parseInt(port, 10);
  }

  if (dataPath) {
    config.vault.path = dataPath;
  }

  return config;
}

function mergeConfig(defaults: Config, overrides: Partial<Config>): Config {
  return {
    server: { ...defaults.server, ...overrides.server },
    vault: { ...defaults.vault, ...overrides.vault },
    webauthn: { 
      ...defaults.webauthn, 
      ...overrides.webauthn,
      // Handle snake_case from YAML
      rpId: overrides.webauthn?.rpId ?? (overrides.webauthn as any)?.rp_id ?? defaults.webauthn.rpId,
      rpName: overrides.webauthn?.rpName ?? (overrides.webauthn as any)?.rp_name ?? defaults.webauthn.rpName,
    },
    web: { 
      ...defaults.web, 
      ...overrides.web,
      externalUrl: overrides.web?.externalUrl ?? (overrides.web as any)?.external_url ?? defaults.web.externalUrl,
    },
    session: { 
      ...defaults.session, 
      ...overrides.session,
      timeoutMinutes: overrides.session?.timeoutMinutes ?? (overrides.session as any)?.timeout_minutes ?? defaults.session.timeoutMinutes,
    },
    logging: { ...defaults.logging, ...overrides.logging },
  };
}

export function validateConfig(config: Config): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!config.vault.path) {
    errors.push('vault.path is required');
  }

  if (!config.webauthn.rpId) {
    errors.push('webauthn.rpId is required');
  }

  if (!config.webauthn.origin) {
    errors.push('webauthn.origin is required');
  }

  if (!config.web.externalUrl) {
    errors.push('web.externalUrl is required');
  }

  // Validate URL format
  try {
    new URL(config.webauthn.origin);
  } catch {
    errors.push('webauthn.origin must be a valid URL');
  }

  try {
    new URL(config.web.externalUrl);
  } catch {
    errors.push('web.externalUrl must be a valid URL');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}
