import { describe, it, expect } from 'vitest';
import { inventorySuite } from '../src/suites/inventory.js';
import { HttpClient } from '../src/http/client.js';
import { createLogger } from '../src/core/logger.js';
import { mockFetchQueue } from './helpers/fetchMock.js';
import { makeConfig } from './helpers/makeConfig.js';
import type { LoadedApiSpec } from '../src/openapi/types.js';

// Probe order: /swagger, /openapi.json, /api-docs, /graphql, /debug, /actuator, /metrics,
//              /v1/, /api/v1/, /health, then POST /graphql (introspection)
function makeQueue(
  overrides: Record<number, { status: number; bodyText?: string }> = {}
) {
  return Array.from({ length: 11 }, (_, i) => ({
    status: overrides[i]?.status ?? 404,
    bodyText: overrides[i]?.bodyText ?? ''
  }));
}

function makeApiSpec(serverUrl: string): LoadedApiSpec {
  return {
    source: 'test',
    spec: { servers: [{ url: serverUrl }], paths: {} },
    endpoints: []
  };
}

describe('inventory suite', () => {
  it('groups multiple sensitive paths into a single finding', async () => {
    // /swagger (index 0) and /debug (index 4) return 200; rest 404
    mockFetchQueue(makeQueue({ 0: { status: 200 }, 4: { status: 200 } }));

    const config = makeConfig('https://api.example.com');
    const http = new HttpClient({ baseUrl: config.target.baseUrl, timeoutMs: config.active.timeoutMs });

    const findings = await inventorySuite().run({ http, config, logger: createLogger({ verbose: false }) });

    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.id).toBe('inventory.sensitive_endpoint_exposed');
    expect(f.severity).toBe('medium');
    expect(f.suite).toBe('inventory');
    expect(f.tags).toContain('api9');
    const paths = f.evidence?.paths as Array<{ path: string }>;
    expect(paths).toHaveLength(2);
    expect(paths.map((p) => p.path)).toContain('/swagger');
    expect(paths.map((p) => p.path)).toContain('/debug');
  });

  it('emits no finding when all sensitive paths return 4xx', async () => {
    mockFetchQueue(makeQueue());

    const config = makeConfig('https://api.example.com');
    const http = new HttpClient({ baseUrl: config.target.baseUrl, timeoutMs: config.active.timeoutMs });

    const findings = await inventorySuite().run({ http, config, logger: createLogger({ verbose: false }) });

    expect(findings).toHaveLength(0);
  });

  it('emits stale version finding when spec declares newer version and old version responds', async () => {
    // /v1/ is index 7
    mockFetchQueue(makeQueue({ 7: { status: 200 } }));

    const config = makeConfig('https://api.example.com');
    const http = new HttpClient({ baseUrl: config.target.baseUrl, timeoutMs: config.active.timeoutMs });
    const api = makeApiSpec('https://api.example.com/v2');

    const findings = await inventorySuite().run({
      http,
      config,
      logger: createLogger({ verbose: false }),
      api
    });

    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.id).toBe('inventory.stale_version_responding');
    expect(f.severity).toBe('medium');
    expect(f.suite).toBe('inventory');
    expect(f.tags).toContain('api9');
    expect(f.evidence?.declaredVersion).toBe('v2');
    const stale = f.evidence?.stale as Array<{ path: string }>;
    expect(stale).toHaveLength(1);
    expect(stale[0].path).toBe('/v1/');
  });

  it('groups multiple stale version paths into one finding', async () => {
    // /v1/ (index 7) and /api/v1/ (index 8) both respond
    mockFetchQueue(makeQueue({ 7: { status: 200 }, 8: { status: 200 } }));

    const config = makeConfig('https://api.example.com');
    const http = new HttpClient({ baseUrl: config.target.baseUrl, timeoutMs: config.active.timeoutMs });
    const api = makeApiSpec('/v3');

    const findings = await inventorySuite().run({
      http,
      config,
      logger: createLogger({ verbose: false }),
      api
    });

    const f = findings.find((x) => x.id === 'inventory.stale_version_responding');
    expect(f).toBeDefined();
    const stale = f!.evidence?.stale as Array<{ path: string }>;
    expect(stale).toHaveLength(2);
  });

  it('does not emit stale version finding without a loaded spec', async () => {
    mockFetchQueue(makeQueue({ 7: { status: 200 } }));

    const config = makeConfig('https://api.example.com');
    const http = new HttpClient({ baseUrl: config.target.baseUrl, timeoutMs: config.active.timeoutMs });

    const findings = await inventorySuite().run({ http, config, logger: createLogger({ verbose: false }) });

    expect(findings.every((f) => f.id !== 'inventory.stale_version_responding')).toBe(true);
  });

  it('does not flag a version path when it matches the declared version', async () => {
    // /v1/ responds (index 7) but spec also declares v1 — not stale
    mockFetchQueue(makeQueue({ 7: { status: 200 } }));

    const config = makeConfig('https://api.example.com');
    const http = new HttpClient({ baseUrl: config.target.baseUrl, timeoutMs: config.active.timeoutMs });
    const api = makeApiSpec('/v1');

    const findings = await inventorySuite().run({
      http,
      config,
      logger: createLogger({ verbose: false }),
      api
    });

    expect(findings.every((f) => f.id !== 'inventory.stale_version_responding')).toBe(true);
  });

  it('health endpoint responding does not produce a finding', async () => {
    // /health is index 9
    mockFetchQueue(makeQueue({ 9: { status: 200 } }));

    const config = makeConfig('https://api.example.com');
    const http = new HttpClient({ baseUrl: config.target.baseUrl, timeoutMs: config.active.timeoutMs });

    const findings = await inventorySuite().run({ http, config, logger: createLogger({ verbose: false }) });

    expect(findings).toHaveLength(0);
  });

  it('emits graphql introspection finding when schema data is returned', async () => {
    // index 10 = POST /graphql introspection
    const introspectionBody = JSON.stringify({ data: { __schema: { queryType: { name: 'Query' } } } });
    mockFetchQueue(makeQueue({ 10: { status: 200, bodyText: introspectionBody } }));

    const config = makeConfig('https://api.example.com');
    const http = new HttpClient({ baseUrl: config.target.baseUrl, timeoutMs: config.active.timeoutMs });

    const findings = await inventorySuite().run({ http, config, logger: createLogger({ verbose: false }) });

    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.id).toBe('inventory.graphql_introspection_enabled');
    expect(f.severity).toBe('low');
    expect(f.suite).toBe('inventory');
    expect(f.tags).toContain('graphql');
    expect(f.tags).toContain('api9');
  });

  it('does not emit introspection finding when server disables introspection', async () => {
    // Server returns 200 but with an errors array (introspection disabled)
    const errorBody = JSON.stringify({ errors: [{ message: 'GraphQL introspection is not allowed' }] });
    mockFetchQueue(makeQueue({ 10: { status: 200, bodyText: errorBody } }));

    const config = makeConfig('https://api.example.com');
    const http = new HttpClient({ baseUrl: config.target.baseUrl, timeoutMs: config.active.timeoutMs });

    const findings = await inventorySuite().run({ http, config, logger: createLogger({ verbose: false }) });

    expect(findings.every((f) => f.id !== 'inventory.graphql_introspection_enabled')).toBe(true);
  });
});
