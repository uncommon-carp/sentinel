import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it, expect, vi } from 'vitest';
import { runScan } from '../src/core/runner.js';
import type { Suite } from '../src/core/types.js';
import { jsonReporter } from '../src/reporters/json.js';
import { markdownReporter } from '../src/reporters/markdown.js';
import { makeSuiteCtx } from './helpers/makeConfig.js';

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-test-'));
}

describe('runner', () => {
  it('writes json + markdown report files', async () => {
    const out = tmpDir();
    const ctx = makeSuiteCtx();

    const suite: Suite = {
      name: 'test-suite',
      description: 'Deterministic suite for runner test',
      async run() {
        return [
          {
            id: 'test.finding',
            title: 'Test Finding',
            severity: 'low',
            description: 'This is a test finding',
            suite: 'test-suite'
          }
        ];
      }
    };

    const result = await runScan({
      suites: [suite],
      reporters: [jsonReporter(), markdownReporter()],
      ctx,
      sanitizedConfig: { target: { baseUrl: ctx.config.target.baseUrl } },
      outputDir: out,
      meta: {
        startedAt: new Date().toISOString(),
        targetBaseUrl: ctx.config.target.baseUrl,
        version: '0.1.0'
      }
    });

    expect(result.findings).toHaveLength(1);

    const jsonPath = path.join(out, 'sentinel-report.json');
    const mdPath = path.join(out, 'sentinel-report.md');

    expect(fs.existsSync(jsonPath)).toBe(true);
    expect(fs.existsSync(mdPath)).toBe(true);

    const json = JSON.parse(fs.readFileSync(jsonPath, 'utf-8'));
    expect(json.findings).toHaveLength(1);

    const md = fs.readFileSync(mdPath, 'utf-8');
    expect(md).toContain('# Sentinel Report');
    expect(md).toContain('Test Finding');
  });

  it('isolates a throwing suite and still runs the others', async () => {
    const ctx = makeSuiteCtx();
    const errSpy = vi.spyOn(ctx.logger, 'error');

    const bad: Suite = {
      name: 'bad-suite',
      description: 'throws',
      async run() {
        throw new Error('network exploded');
      }
    };
    const good: Suite = {
      name: 'good-suite',
      description: 'returns a finding',
      async run() {
        return [
          {
            id: 'good.finding',
            title: 'Good',
            severity: 'low',
            description: 'ok',
            suite: 'good-suite'
          }
        ];
      }
    };

    const result = await runScan({
      suites: [bad, good],
      reporters: [jsonReporter(), markdownReporter()],
      ctx,
      sanitizedConfig: { target: { baseUrl: ctx.config.target.baseUrl } },
      outputDir: tmpDir(),
      meta: {
        startedAt: new Date().toISOString(),
        targetBaseUrl: ctx.config.target.baseUrl,
        version: '0.1.0'
      }
    });

    expect(result.findings.map((f) => f.id)).toContain('good.finding'); // good suite ran
    expect(result.suiteErrors).toHaveLength(1);
    expect(result.suiteErrors[0]).toMatchObject({
      suite: 'bad-suite',
      message: 'network exploded'
    });
    expect(errSpy).toHaveBeenCalled();
  });
});
