import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { formatZodIssue, loadConfig, sanitizeConfigForReport } from '../src/config/load.js';
import { SentinelConfigSchema } from '../src/config/schema.js';
import type { ZodIssue } from 'zod';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-test-'));
}

const minimal = { target: { baseUrl: 'http://localhost:3000' } };

describe('config/load', () => {
  let savedEnv: Record<string, string | undefined> = {};

  beforeEach(() => {
    savedEnv = {
      TARGET_URL: process.env.TARGET_URL,
      RESULTS_BUCKET: process.env.RESULTS_BUCKET,
      RUN_ID: process.env.RUN_ID,
      AUTH_TOKEN_URL: process.env.AUTH_TOKEN_URL
    };
    delete process.env.TARGET_URL;
    delete process.env.RESULTS_BUCKET;
    delete process.env.RUN_ID;
    delete process.env.AUTH_TOKEN_URL;
  });

  afterEach(() => {
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

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

  it('TARGET_URL sets baseUrl when no CLI flag provided', async () => {
    process.env.TARGET_URL = 'http://from-env.example';
    const { config, pipeline, pipelineWarning } = await loadConfig({});
    expect(config.target.baseUrl).toBe('http://from-env.example');
    expect(pipeline).toBeUndefined();
    expect(pipelineWarning).toBeUndefined();
  });

  it('CLI flag wins over TARGET_URL', async () => {
    process.env.TARGET_URL = 'http://from-env.example';
    const { config } = await loadConfig({ baseUrl: 'http://from-cli.example' });
    expect(config.target.baseUrl).toBe('http://from-cli.example');
  });

  it('returns pipeline when RESULTS_BUCKET and RUN_ID are both set', async () => {
    process.env.TARGET_URL = 'http://localhost:3000';
    process.env.RESULTS_BUCKET = 'my-bucket';
    process.env.RUN_ID = 'run-123';
    const { pipeline, pipelineWarning } = await loadConfig({});
    expect(pipeline).toEqual({ resultsBucket: 'my-bucket', runId: 'run-123' });
    expect(pipelineWarning).toBeUndefined();
  });

  it('returns pipelineWarning when only RESULTS_BUCKET is set', async () => {
    process.env.TARGET_URL = 'http://localhost:3000';
    process.env.RESULTS_BUCKET = 'my-bucket';
    const { pipeline, pipelineWarning } = await loadConfig({});
    expect(pipeline).toBeUndefined();
    expect(pipelineWarning).toMatch(/RESULTS_BUCKET is set/);
    expect(pipelineWarning).toMatch(/RUN_ID is missing/);
    expect(pipelineWarning).toMatch(/S3 upload skipped/);
  });

  it('returns pipelineWarning when only RUN_ID is set', async () => {
    process.env.TARGET_URL = 'http://localhost:3000';
    process.env.RUN_ID = 'run-123';
    const { pipeline, pipelineWarning } = await loadConfig({});
    expect(pipeline).toBeUndefined();
    expect(pipelineWarning).toMatch(/RESULTS_BUCKET is missing/);
    expect(pipelineWarning).toMatch(/RUN_ID is set/);
    expect(pipelineWarning).toMatch(/S3 upload skipped/);
  });

  it('returns no pipeline when neither RESULTS_BUCKET nor RUN_ID is set', async () => {
    process.env.TARGET_URL = 'http://localhost:3000';
    const { pipeline, pipelineWarning } = await loadConfig({});
    expect(pipeline).toBeUndefined();
    expect(pipelineWarning).toBeUndefined();
  });

  it('AUTH_TOKEN_URL sets auth.tokenUrl', async () => {
    process.env.TARGET_URL = 'http://localhost:3000';
    process.env.AUTH_TOKEN_URL = 'http://localhost:3000/api/v2/auth';
    const { config } = await loadConfig({});
    expect(config.auth.tokenUrl).toBe('http://localhost:3000/api/v2/auth');
    // defaults for the other token fields still apply
    expect(config.auth.tokenMethod).toBe('GET');
    expect(config.auth.tokenField).toBe('token');
  });

  it('AUTH_TOKEN_URL env wins over file auth.tokenUrl', async () => {
    const dir = tmpDir();
    const configPath = path.join(dir, 'sentinel.config.json');
    fs.writeFileSync(
      configPath,
      JSON.stringify({
        target: { baseUrl: 'http://localhost:3000' },
        auth: { tokenUrl: 'http://from-file.example/token' }
      }),
      'utf-8'
    );
    const oldCwd = process.cwd();
    process.chdir(dir);
    try {
      process.env.AUTH_TOKEN_URL = 'http://from-env.example/token';
      const { config } = await loadConfig({ configPath: 'sentinel.config.json' });
      expect(config.auth.tokenUrl).toBe('http://from-env.example/token');
    } finally {
      process.chdir(oldCwd);
    }
  });

  it('sanitizes token-endpoint request secrets in the report config', () => {
    const parsed = SentinelConfigSchema.parse({
      target: { baseUrl: 'http://localhost:3000' },
      auth: {
        type: 'bearer',
        bearerToken: 'fetched-jwt',
        tokenUrl: 'http://localhost:3000/api/v2/auth',
        tokenRequestHeaders: { authorization: 'Basic c2VjcmV0' },
        tokenRequestBody: 'client_secret=hunter2'
      }
    });
    const sanitized = sanitizeConfigForReport(parsed) as { auth: Record<string, unknown> };
    expect(sanitized.auth.bearerToken).toBe('***');
    expect(sanitized.auth.tokenRequestBody).toBe('***');
    expect(sanitized.auth.tokenRequestHeaders).toEqual({ authorization: '***' });
    // tokenUrl is not a secret — stays visible
    expect(sanitized.auth.tokenUrl).toBe('http://localhost:3000/api/v2/auth');
  });
});
