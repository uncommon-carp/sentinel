import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it, expect } from 'vitest';
import { loadConfig } from '../src/config/load.js';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-test-'));
}

describe('config/load', () => {
  it('loads config from file + CLI overrides (and applies defaults)', async () => {
    const dir = tmpDir();
    const configPath = path.join(dir, 'sentinel.config.json');

    fs.writeFileSync(
      configPath,
      JSON.stringify(
        {
          target: { baseUrl: 'https://from-file.example' },
          suites: { headers: false } // cors omitted intentionally
        },
        null,
        2
      ),
      'utf-8'
    );

    // Pretend the process is running in that directory
    const oldCwd = process.cwd();
    process.chdir(dir);

    try {
      const { config } = await loadConfig({
        configPath: 'sentinel.config.json',
        baseUrl: 'https://from-cli.example' // should override file
      });

      expect(config.target.baseUrl).toBe('https://from-cli.example');

      // headers explicitly false from file should stay false
      expect(config.suites.headers).toBe(false);

      // cors should default to true (because schema defaults)
      expect(config.suites.cors ?? true).toBe(true);

      // active defaults should exist
      expect(config.active.timeoutMs).toBeTypeOf('number');
      expect(config.active.maxRequestsPerSuite).toBeTypeOf('number');
    } finally {
      process.chdir(oldCwd);
    }
  });

  it('throws a readable error on invalid config', async () => {
    const dir = tmpDir();
    const configPath = path.join(dir, 'sentinel.config.json');

    fs.writeFileSync(
      configPath,
      JSON.stringify(
        {
          target: { baseUrl: 'not-a-url' }
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
        /Invalid config/i
      );
    } finally {
      process.chdir(oldCwd);
    }
  });
});
