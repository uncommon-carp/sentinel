import { describe, it, expect } from 'vitest';
import { corsSuite } from '../src/suites/cors.js';
import { HttpClient } from '../src/http/client.js';
import { createLogger } from '../src/core/logger.js';
import { mockFetchQueue } from './helpers/fetchMock.js';
import { makeConfig } from './helpers/makeConfig.js';

describe('cors suite', () => {
  it('emits nothing for a happy path', async () => {
    const origin = 'https://example.com';

    mockFetchQueue([
      {
        status: 200,
        headers: {
          'access-control-allow-origin': origin
        }
      }
    ]);

    const config = makeConfig('https://api.example.com');
    const http = new HttpClient({
      baseUrl: config.target.baseUrl,
      timeoutMs: config.active.timeoutMs
    });

    const findings = await corsSuite().run({
      http,
      config,
      logger: createLogger({ verbose: false })
    });

    expect(findings.length).toBe(0);
  });
  it('emits a finding when ACAO reflects an arbitrary Origin', async () => {
    const origin = 'https://sentinel.invalid';

    mockFetchQueue([
      {
        status: 200,
        headers: {
          'access-control-allow-origin': origin
        },
        bodyText: 'ok'
      }
    ]);

    const config = makeConfig('https://api.example.com');
    const http = new HttpClient({
      baseUrl: config.target.baseUrl,
      timeoutMs: config.active.timeoutMs
    });

    const findings = await corsSuite().run({
      http,
      config,
      logger: createLogger({ verbose: false })
    });

    expect(findings.some((f) => f.id === 'cors.origin_reflection')).toBe(true);

    const reflection = findings.find((f) => f.id === 'cors.origin_reflection');
    expect(reflection?.suite).toBe('cors');
    expect(reflection?.severity).toBe('medium');
  });
  it('emits a finding when ACAO is * or ACC is true', async () => {
    mockFetchQueue([
      {
        status: 200,
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-credentials': 'true'
        },
        bodyText: 'ok'
      }
    ]);
    const config = makeConfig('https://api.example.com');
    const http = new HttpClient({
      baseUrl: config.target.baseUrl,
      timeoutMs: config.active.timeoutMs
    });

    // Act
    const findings = await corsSuite().run({
      http,
      config,
      logger: createLogger({ verbose: false })
    });

    // Assert
    const finding = findings.find((f) => f.id === 'cors.wildcard_with_credentials');

    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.suite).toBe('cors');
    expect(finding?.evidence).toMatchObject({
      acao: '*',
      acc: 'true'
    });
  });
});
