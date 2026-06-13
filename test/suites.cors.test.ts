import { describe, it, expect } from 'vitest';
import { corsSuite } from '../src/suites/cors.js';
import { mockFetchQueue } from './helpers/fetchMock.js';
import { makeSuiteCtx } from './helpers/makeConfig.js';

describe('cors suite', () => {
  it('emits nothing for a happy path', async () => {
    mockFetchQueue([
      { status: 200, headers: { 'access-control-allow-origin': 'https://example.com' } }
    ]);

    const findings = await corsSuite().run(makeSuiteCtx());

    expect(findings.length).toBe(0);
  });

  it('emits a finding when ACAO reflects an arbitrary Origin', async () => {
    mockFetchQueue([
      {
        status: 200,
        headers: { 'access-control-allow-origin': 'https://sentinel.invalid' },
        bodyText: 'ok'
      }
    ]);

    const findings = await corsSuite().run(makeSuiteCtx());

    const reflection = findings.find((f) => f.id === 'cors.origin_reflection');
    expect(reflection).toBeDefined();
    expect(reflection?.suite).toBe('cors');
    expect(reflection?.severity).toBe('medium');
  });

  it('emits a finding when ACAO is * and ACC is true', async () => {
    mockFetchQueue([
      {
        status: 200,
        headers: { 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' },
        bodyText: 'ok'
      }
    ]);

    const findings = await corsSuite().run(makeSuiteCtx());

    const finding = findings.find((f) => f.id === 'cors.wildcard_with_credentials');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.suite).toBe('cors');
    expect(finding?.evidence).toMatchObject({ acao: '*', acc: 'true' });
  });
});
