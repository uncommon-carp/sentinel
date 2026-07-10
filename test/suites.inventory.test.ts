import { describe, it, expect } from 'vitest';
import { inventorySuite } from '../src/suites/inventory.js';
import { mockFetchQueue } from './helpers/fetchMock.js';
import { makeSuiteCtx } from './helpers/makeConfig.js';
import type { LoadedApiSpec } from '../src/openapi/types.js';

// Probe order: /swagger, /openapi.json, /api-docs, /graphql, /debug, /actuator, /metrics,
//              /v1/, /api/v1/, then POST /graphql (introspection)
function makeQueue(overrides: Record<number, { status: number; bodyText?: string }> = {}) {
  return Array.from({ length: 10 }, (_, i) => ({
    status: overrides[i]?.status ?? 404,
    bodyText: overrides[i]?.bodyText ?? ''
  }));
}

function makeApiSpec(serverUrl: string, paths: Record<string, unknown> = {}): LoadedApiSpec {
  return {
    source: 'test',
    spec: { servers: [{ url: serverUrl }], paths },
    endpoints: []
  };
}

// The probe URL the SSRF check sends; the vulnerable fixture reflects it back.
const SSRF_PROBE_URL = 'http://ssrf-probe.sentinel.invalid/';

// A spec exposing one URL-accepting query parameter (GET /fetch?url=).
const SSRF_SPEC_PATHS = {
  '/fetch': {
    get: {
      parameters: [{ name: 'url', in: 'query', schema: { type: 'string', format: 'uri' } }]
    }
  }
};

describe('inventory suite', () => {
  it('groups multiple sensitive paths into a single finding', async () => {
    // /swagger (index 0) and /debug (index 4) return 200; rest 404
    mockFetchQueue(makeQueue({ 0: { status: 200 }, 4: { status: 200 } }));

    const findings = await inventorySuite().run(makeSuiteCtx());

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

    const findings = await inventorySuite().run(makeSuiteCtx());

    expect(findings).toHaveLength(0);
  });

  it('emits stale version finding when spec declares newer version and old version responds', async () => {
    // /v1/ is index 7
    mockFetchQueue(makeQueue({ 7: { status: 200 } }));

    const api = makeApiSpec('https://api.example.com/v2');
    const findings = await inventorySuite().run({ ...makeSuiteCtx(), api });

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

    const api = makeApiSpec('/v3');
    const findings = await inventorySuite().run({ ...makeSuiteCtx(), api });

    const f = findings.find((x) => x.id === 'inventory.stale_version_responding');
    expect(f).toBeDefined();
    const stale = f!.evidence?.stale as Array<{ path: string }>;
    expect(stale).toHaveLength(2);
  });

  it('does not emit stale version finding without a loaded spec', async () => {
    mockFetchQueue(makeQueue({ 7: { status: 200 } }));

    const findings = await inventorySuite().run(makeSuiteCtx());

    expect(findings.every((f) => f.id !== 'inventory.stale_version_responding')).toBe(true);
  });

  it('does not flag a version path when it matches the declared version', async () => {
    // /v1/ responds (index 7) but spec also declares v1 — not stale
    mockFetchQueue(makeQueue({ 7: { status: 200 } }));

    const api = makeApiSpec('/v1');
    const findings = await inventorySuite().run({ ...makeSuiteCtx(), api });

    expect(findings.every((f) => f.id !== 'inventory.stale_version_responding')).toBe(true);
  });

  it('emits graphql introspection finding when schema data is returned', async () => {
    // index 9 = POST /graphql introspection
    const introspectionBody = JSON.stringify({
      data: { __schema: { queryType: { name: 'Query' } } }
    });
    mockFetchQueue(makeQueue({ 9: { status: 200, bodyText: introspectionBody } }));

    const findings = await inventorySuite().run(makeSuiteCtx());

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
    const errorBody = JSON.stringify({
      errors: [{ message: 'GraphQL introspection is not allowed' }]
    });
    mockFetchQueue(makeQueue({ 9: { status: 200, bodyText: errorBody } }));

    const findings = await inventorySuite().run(makeSuiteCtx());

    expect(findings.every((f) => f.id !== 'inventory.graphql_introspection_enabled')).toBe(true);
  });

  it('emits ssrf_surface when a URL param is accepted without validation', async () => {
    // Base 10 requests all 404; the SSRF probe (index 10) reflects the probe URL with 200.
    const queue = makeQueue();
    queue.push({ status: 200, bodyText: JSON.stringify({ requestedUrl: SSRF_PROBE_URL }) });
    mockFetchQueue(queue);

    const api = makeApiSpec('https://api.example.com/api/v2', SSRF_SPEC_PATHS);
    const findings = await inventorySuite().run({ ...makeSuiteCtx(), api });

    const f = findings.find((x) => x.id === 'inventory.ssrf_surface');
    expect(f).toBeDefined();
    expect(f!.severity).toBe('medium');
    expect(f!.suite).toBe('inventory');
    expect(f!.tags).toContain('ssrf');
    expect(f!.tags).toContain('api7');
    const params = f!.evidence?.parameters as Array<{ parameter: string; reflected: boolean }>;
    expect(params).toHaveLength(1);
    expect(params[0].parameter).toBe('url');
    expect(params[0].reflected).toBe(true);
  });

  it('does not emit ssrf_surface when the URL param is validated (400)', async () => {
    const queue = makeQueue();
    queue.push({ status: 400, bodyText: JSON.stringify({ error: 'url not allowed' }) });
    mockFetchQueue(queue);

    const api = makeApiSpec('https://api.example.com/api/v2', SSRF_SPEC_PATHS);
    const findings = await inventorySuite().run({ ...makeSuiteCtx(), api });

    expect(findings.every((f) => f.id !== 'inventory.ssrf_surface')).toBe(true);
  });

  it('does not emit ssrf_surface when a 2xx body carries a rejection signal', async () => {
    const queue = makeQueue();
    queue.push({ status: 200, bodyText: JSON.stringify({ error: 'URL blocked by SSRF filter' }) });
    mockFetchQueue(queue);

    const api = makeApiSpec('https://api.example.com/api/v2', SSRF_SPEC_PATHS);
    const findings = await inventorySuite().run({ ...makeSuiteCtx(), api });

    expect(findings.every((f) => f.id !== 'inventory.ssrf_surface')).toBe(true);
  });

  it('issues no SSRF probe and emits no finding when the spec has no URL-like params', async () => {
    // Only the 10 base requests are queued; a stray SSRF probe would throw "no more mocked responses".
    mockFetchQueue(makeQueue());

    const nonUrlPaths = {
      '/search': {
        get: { parameters: [{ name: 'q', in: 'query', schema: { type: 'string' } }] }
      }
    };
    const api = makeApiSpec('https://api.example.com/api/v2', nonUrlPaths);
    const findings = await inventorySuite().run({ ...makeSuiteCtx(), api });

    expect(findings.every((f) => f.id !== 'inventory.ssrf_surface')).toBe(true);
  });
});
