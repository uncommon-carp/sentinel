import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadConfig } from '../src/config/load.js';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-envtest-'));
}

describe('config env interpolation', () => {
  const OLD_ENV = { ...process.env };

  beforeEach(() => {
    process.env = { ...OLD_ENV };
  });

  afterEach(() => {
    process.env = OLD_ENV;
  });

  it('expands ${VAR} placeholders in config values', async () => {
    const dir = tmpDir();
    const configPath = path.join(dir, 'sentinel.config.json');

    process.env.SENTINEL_API_KEY = 'super-secret';

    fs.writeFileSync(
      configPath,
      JSON.stringify(
        {
          target: { baseUrl: 'https://from-file.example' },
          auth: {
            type: 'apiKey',
            apiKeyHeader: 'x-api-key',
            apiKeyValue: '${SENTINEL_API_KEY}'
          }
        },
        null,
        2
      ),
      'utf-8'
    );

    const oldCwd = process.cwd();
    process.chdir(dir);
    try {
      const { config } = await loadConfig({ configPath: 'sentinel.config.json' });

      expect(config.auth.type).toBe('apiKey');
      expect(config.auth.apiKeyValue).toBe('super-secret');
    } finally {
      process.chdir(oldCwd);
    }
  });

  it('throws a readable error when env var is missing', async () => {
    const dir = tmpDir();
    const configPath = path.join(dir, 'sentinel.config.json');

    delete process.env.SENTINEL_MISSING;

    fs.writeFileSync(
      configPath,
      JSON.stringify(
        {
          target: { baseUrl: 'https://from-file.example' },
          auth: {
            type: 'apiKey',
            apiKeyHeader: 'x-api-key',
            apiKeyValue: '${SENTINEL_MISSING}'
          }
        },
        null,
        2
      ),
      'utf-8'
    );

    const oldCwd = process.cwd();
    process.chdir(dir);
    try {
      await expect(loadConfig({ configPath: 'sentinel.config.json' })).rejects.toThrow(
        /Missing required environment variable: SENTINEL_MISSING/i
      );
    } finally {
      process.chdir(oldCwd);
    }
  });

  it('does not expand partial strings (must be exact ${VAR})', async () => {
    const dir = tmpDir();
    const configPath = path.join(dir, 'sentinel.config.json');

    process.env.SENTINEL_API_KEY = 'super-secret';

    fs.writeFileSync(
      configPath,
      JSON.stringify(
        {
          target: { baseUrl: 'https://from-file.example' },
          auth: {
            type: 'apiKey',
            apiKeyHeader: 'x-api-key',
            apiKeyValue: 'token=${SENTINEL_API_KEY}'
          }
        },
        null,
        2
      ),
      'utf-8'
    );

    const oldCwd = process.cwd();
    process.chdir(dir);
    try {
      const { config } = await loadConfig({ configPath: 'sentinel.config.json' });
      expect(config.auth.apiKeyValue).toBe('token=${SENTINEL_API_KEY}');
    } finally {
      process.chdir(oldCwd);
    }
  });
});
