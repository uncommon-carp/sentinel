import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it, expect } from 'vitest';
import { formatZodIssue, loadConfig } from '../src/config/load.js';
import { SentinelConfigSchema } from '../src/config/schema.js';
import type { ZodIssue } from 'zod';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-test-'));
}

const minimal = { target: { baseUrl: 'http://localhost:3000' } };

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

  it('formats a wrong type error', () => {
    const result = SentinelConfigSchema.safeParse({ ...minimal, verbose: 'yes' });
    expect(result.success).toBe(false);
    if (!result.success) {
      const formatted = result.error.issues.map(formatZodIssue);
      expect(formatted).toContainEqual('verbose: expected boolean, received string');
    }
  });

  it('formats a missing required object', () => {
    const result = SentinelConfigSchema.safeParse({});
    expect(result.success).toBe(false);
    if (!result.success) {
      const formatted = result.error.issues.map(formatZodIssue);
      expect(formatted).toContainEqual('target: expected object, received undefined');
    }
  });

  it('formats an invalid enum value', () => {
    const result = SentinelConfigSchema.safeParse({
      ...minimal,
      auth: { type: 'oauth' }
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      const formatted = result.error.issues.map(formatZodIssue);
      expect(formatted).toContainEqual(
        expect.stringMatching(/auth\.type: expected one of .+ received 'oauth'/)
      );
    }
  });

  it('formats an invalid URL', () => {
    const result = SentinelConfigSchema.safeParse({
      target: { baseUrl: 'not-a-url' }
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      const formatted = result.error.issues.map(formatZodIssue);
      expect(formatted).toContainEqual('target.baseUrl: invalid url');
    }
  });

  it('formats a range violation', () => {
    const result = SentinelConfigSchema.safeParse({
      ...minimal,
      active: { maxRequestsPerSuite: 0 }
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      const formatted = result.error.issues.map(formatZodIssue);
      expect(formatted).toContainEqual('active.maxRequestsPerSuite: must be >= 1');
    }
  });

  it('formats an invalid_string with object validation', () => {
    const issues = [
      {
        code: 'invalid_string',
        path: ['target', 'baseUrl'],
        validation: { includes: 'https' },
        message: ''
      },
      {
        code: 'invalid_string',
        path: ['target', 'baseUrl'],
        validation: { startsWith: 'https://' },
        message: ''
      },
      {
        code: 'invalid_string',
        path: ['target', 'baseUrl'],
        validation: { endsWith: '.com' },
        message: ''
      }
    ] as ZodIssue[];

    const formatted = issues.map(formatZodIssue);
    expect(formatted[0]).toBe("target.baseUrl: must include 'https'");
    expect(formatted[1]).toBe("target.baseUrl: must start with 'https://'");
    expect(formatted[2]).toBe("target.baseUrl: must end with '.com'");
  });
});
