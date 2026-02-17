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

export async function loadConfig(configPath?: string): Promise<Config> {
  const searchPaths = [
    configPath,
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

  // No config file found — try environment variables
  return applyEnvOverrides(DEFAULT_CONFIG);
}

/**
 * Apply environment variable overrides.
 * Supports: SSH_VAULT_DOMAIN, SSH_VAULT_PORT, SSH_VAULT_ORIGIN, SSH_VAULT_DATA_PATH, PORT
 */
function applyEnvOverrides(config: Config): Config {
  const domain = process.env.SSH_VAULT_DOMAIN;
  const port = process.env.SSH_VAULT_PORT || process.env.PORT;
  const origin = process.env.SSH_VAULT_ORIGIN;
  const dataPath = process.env.SSH_VAULT_DATA_PATH;

  if (domain) {
    const isLocal = domain === 'localhost' || domain.startsWith('127.');
    const proto = isLocal ? 'http' : 'https';
    const defaultOrigin = port && isLocal ? `${proto}://${domain}:${port}` : `${proto}://${domain}`;

    config.webauthn.rpId = domain;
    config.webauthn.origin = origin || defaultOrigin;
    config.web.externalUrl = origin || defaultOrigin;
  }

  if (port) {
    config.web.port = parseInt(port, 10);
  }

  if (origin) {
    config.webauthn.origin = origin;
    config.web.externalUrl = origin;
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
