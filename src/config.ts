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
      return mergeConfig(DEFAULT_CONFIG, parsed);
    } catch {
      // Try next path
    }
  }

  // Return default config if no file found
  return DEFAULT_CONFIG;
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
