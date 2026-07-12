import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it, expect } from 'vitest';
import { scanCommand } from '../src/cli/commands/scan.js';
import { mockFetchQueue } from './helpers/fetchMock.js';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-smoke-'));
}

describe('CLI smoke', () => {
  it('runs scanCommand and writes reports', async () => {
    mockFetchQueue([
      { status: 200, headers: { 'content-type': 'text/html' }, bodyText: 'ok' }, // headers
      {
        status: 200,
        headers: {
          'access-control-allow-origin': 'https://sentinel.invalid',
          'access-control-allow-credentials': 'true'
        },
        bodyText: 'ok'
      }, // cors
      { status: 401, headers: {} }, // auth probe
      { status: 200, headers: {} }, // ratelimit phase 1
      { status: 200, headers: {} }, // ratelimit burst 1
      { status: 200, headers: {} }, // ratelimit burst 2
      // inventory GETs: /swagger /openapi.json /api-docs /graphql /debug /actuator /metrics /v1/ /api/v1/
      { status: 404 },
      { status: 404 },
      { status: 404 },
      { status: 404 },
      { status: 404 },
      { status: 404 },
      { status: 404 },
      { status: 404 },
      { status: 404 },
      // inventory: POST /graphql introspection
      { status: 404 }
    ]);

    const out = tmpDir();

    // Pin burstCount and delayMs so the smoke test stays fast and mock count is predictable.
    const configPath = path.join(out, 'sentinel.config.json');
    fs.writeFileSync(
      configPath,
      JSON.stringify({ ratelimit: { burstCount: 2, delayMs: 0 } }),
      'utf-8'
    );

    const { exitCode, outputDir } = await scanCommand({
      version: '0.0.0-test',
      url: 'https://api.example.com',
      config: configPath,
      out,
      verbose: true
    });

    expect(outputDir).toBe(out);
    expect([0, 2]).toContain(exitCode);

    const jsonPath = path.join(out, 'sentinel-report.json');
    const mdPath = path.join(out, 'sentinel-report.md');

    expect(fs.existsSync(jsonPath)).toBe(true);
    expect(fs.existsSync(mdPath)).toBe(true);

    const json = JSON.parse(fs.readFileSync(jsonPath, 'utf-8'));
    expect(json.meta.targetBaseUrl).toBe('https://api.example.com');
    expect(Array.isArray(json.findings)).toBe(true);

    const md = fs.readFileSync(mdPath, 'utf-8');
    expect(md).toContain('# Sentinel Report');
  });

  it('writes to output.dir from the config file when --out is not passed', async () => {
    // Regression: the CLI used to give --out a hardcoded default, so opts.out was
    // never undefined and `opts.out ?? config.output.dir` always ignored the
    // config. Here no `out` is passed (as commander now yields when the flag is
    // absent), so the config's output.dir must win. All suites off ⇒ no HTTP.
    const cfgDir = tmpDir();
    const reportDir = path.join(cfgDir, 'from-config-out');
    const configPath = path.join(cfgDir, 'sentinel.config.json');
    fs.writeFileSync(
      configPath,
      JSON.stringify({
        suites: {
          headers: false,
          cors: false,
          auth: false,
          ratelimit: false,
          inventory: false,
          injection: false
        },
        output: { dir: reportDir, json: true, markdown: false }
      }),
      'utf-8'
    );

    const { outputDir } = await scanCommand({
      version: '0.0.0-test',
      url: 'https://api.example.com',
      config: configPath
    });

    expect(outputDir).toBe(reportDir);
    expect(fs.existsSync(path.join(reportDir, 'sentinel-report.json'))).toBe(true);
  });

  it('warns and continues when --openapi points at a nonexistent file', async () => {
    const out = tmpDir();
    const configPath = path.join(out, 'sentinel.config.json');
    fs.writeFileSync(
      configPath,
      JSON.stringify({ ratelimit: { burstCount: 2, delayMs: 0 } }),
      'utf-8'
    );

    mockFetchQueue([
      { status: 200, headers: { 'content-type': 'text/html' }, bodyText: 'ok' }, // headers
      {
        status: 200,
        headers: {
          'access-control-allow-origin': 'https://sentinel.invalid',
          'access-control-allow-credentials': 'true'
        },
        bodyText: 'ok'
      }, // cors
      { status: 401, headers: {} }, // auth probe
      { status: 200, headers: {} }, // ratelimit phase 1
      { status: 200, headers: {} }, // ratelimit burst 1
      { status: 200, headers: {} }, // ratelimit burst 2
      // inventory GETs
      { status: 404 },
      { status: 404 },
      { status: 404 },
      { status: 404 },
      { status: 404 },
      { status: 404 },
      { status: 404 },
      { status: 404 },
      { status: 404 },
      // inventory: POST /graphql introspection
      { status: 404 }
    ]);

    const { exitCode } = await scanCommand({
      version: '0.0.0',
      url: 'http://localhost:9999',
      config: configPath,
      openapi: '../definitely-does-not-exist.json',
      out
    });

    expect(exitCode).toBe(0);
  });
});
