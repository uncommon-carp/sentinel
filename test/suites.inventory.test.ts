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

  it('detects a URL param declared at the path-item level (applies to all operations)', async () => {
    const queue = makeQueue();
    queue.push({ status: 200, bodyText: JSON.stringify({ requestedUrl: SSRF_PROBE_URL }) });
    mockFetchQueue(queue);

    const pathLevelParamPaths = {
      '/proxy': {
        // Path-level parameters (not under a specific verb) apply to every operation.
        parameters: [{ name: 'target_url', in: 'query', schema: { type: 'string' } }],
        get: { summary: 'Proxy a request' }
      }
    };
    const api = makeApiSpec('https://api.example.com/api/v2', pathLevelParamPaths);
    const findings = await inventorySuite().run({ ...makeSuiteCtx(), api });

    const f = findings.find((x) => x.id === 'inventory.ssrf_surface');
    expect(f).toBeDefined();
    const params = f!.evidence?.parameters as Array<{ endpoint: string; parameter: string }>;
    expect(params[0].parameter).toBe('target_url');
    expect(params[0].endpoint).toBe('GET /api/v2/proxy');
  });

  it('probes a POST body URL param when ssrfActiveProbe is on', async () => {
    const queue = makeQueue();
    queue.push({ status: 200, bodyText: JSON.stringify({ registeredUrl: SSRF_PROBE_URL }) });
    mockFetchQueue(queue);

    const webhookPaths = {
      '/webhooks': {
        post: {
          requestBody: {
            content: {
              'application/json': {
                schema: { type: 'object', properties: { url: { type: 'string', format: 'uri' } } }
              }
            }
          }
        }
      }
    };
    const ctx = {
      ...makeSuiteCtx(),
      api: makeApiSpec('https://api.example.com/api/v2', webhookPaths)
    };
    ctx.config.inventory.ssrfActiveProbe = true;

    const findings = await inventorySuite().run(ctx);

    const f = findings.find((x) => x.id === 'inventory.ssrf_surface');
    expect(f).toBeDefined();
    const params = f!.evidence?.parameters as Array<{
      method: string;
      paramType: string;
      parameter: string;
      endpoint: string;
    }>;
    expect(params).toHaveLength(1);
    expect(params[0]).toMatchObject({
      method: 'POST',
      paramType: 'body',
      parameter: 'url',
      endpoint: 'POST /api/v2/webhooks'
    });
  });

  it('probes a query URL param on a PUT operation when ssrfActiveProbe is on', async () => {
    const queue = makeQueue();
    queue.push({ status: 200, bodyText: JSON.stringify({ requestedUrl: SSRF_PROBE_URL }) });
    mockFetchQueue(queue);

    const putPaths = {
      '/settings': {
        put: {
          parameters: [{ name: 'redirect_uri', in: 'query', schema: { type: 'string' } }]
        }
      }
    };
    const ctx = { ...makeSuiteCtx(), api: makeApiSpec('https://api.example.com/api/v2', putPaths) };
    ctx.config.inventory.ssrfActiveProbe = true;

    const findings = await inventorySuite().run(ctx);

    const f = findings.find((x) => x.id === 'inventory.ssrf_surface');
    expect(f).toBeDefined();
    const params = f!.evidence?.parameters as Array<{ method: string; paramType: string }>;
    expect(params[0]).toMatchObject({ method: 'PUT', paramType: 'query' });
  });

  it('does not probe a POST body URL param when ssrfActiveProbe is off (default)', async () => {
    // Only the 10 base requests are queued; an active body probe would throw.
    mockFetchQueue(makeQueue());

    const webhookPaths = {
      '/webhooks': {
        post: {
          requestBody: {
            content: {
              'application/json': {
                schema: { type: 'object', properties: { url: { type: 'string', format: 'uri' } } }
              }
            }
          }
        }
      }
    };
    const api = makeApiSpec('https://api.example.com/api/v2', webhookPaths);
    const findings = await inventorySuite().run({ ...makeSuiteCtx(), api });

    expect(findings.every((f) => f.id !== 'inventory.ssrf_surface')).toBe(true);
  });

  it('does not probe a URL param on a non-GET-only endpoint', async () => {
    // Only the 10 base requests are queued; probing the POST param would throw
    // "no more mocked responses" — asserting we never issue a state-changing probe.
    mockFetchQueue(makeQueue());

    const postOnlyPaths = {
      '/webhooks': {
        post: {
          parameters: [{ name: 'url', in: 'query', schema: { type: 'string', format: 'uri' } }]
        }
      }
    };
    const api = makeApiSpec('https://api.example.com/api/v2', postOnlyPaths);
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

  // ── Excessive data exposure (API3) ──────────────────────────────────────────

  const responseSchema = (properties: Record<string, unknown>) => ({
    responses: {
      200: { content: { 'application/json': { schema: { type: 'object', properties } } } }
    }
  });

  it('emits excessive_data_exposure when a sensitive field is present in a live response', async () => {
    const queue = makeQueue();
    queue.push({
      status: 200,
      bodyText: JSON.stringify({ name: 'Alice', apiKey: 'sk_live_abc' })
    });
    mockFetchQueue(queue);

    const paths = {
      '/profile': {
        get: responseSchema({ name: { type: 'string' }, apiKey: { type: 'string' } })
      }
    };
    const api = makeApiSpec('https://api.example.com/api/v2', paths);
    const findings = await inventorySuite().run({ ...makeSuiteCtx(), api });

    const f = findings.find((x) => x.id === 'inventory.excessive_data_exposure');
    expect(f).toBeDefined();
    expect(f!.severity).toBe('medium');
    expect(f!.suite).toBe('inventory');
    expect(f!.tags).toContain('api3');
    const endpoints = f!.evidence?.endpoints as Array<{ endpoint: string; fields: string[] }>;
    expect(endpoints).toHaveLength(1);
    expect(endpoints[0].endpoint).toBe('GET /api/v2/profile');
    expect(endpoints[0].fields).toEqual(['apiKey']);
    // Evidence names the field, not its value.
    expect(JSON.stringify(f!.evidence)).not.toContain('sk_live_abc');
  });

  it('does not flag a schema-declared sensitive field that is absent from the live response', async () => {
    const queue = makeQueue();
    queue.push({ status: 200, bodyText: JSON.stringify({ name: 'Alice' }) });
    mockFetchQueue(queue);

    const paths = {
      '/profile': {
        get: responseSchema({ name: { type: 'string' }, apiKey: { type: 'string' } })
      }
    };
    const api = makeApiSpec('https://api.example.com/api/v2', paths);
    const findings = await inventorySuite().run({ ...makeSuiteCtx(), api });

    expect(findings.every((f) => f.id !== 'inventory.excessive_data_exposure')).toBe(true);
  });

  it('does not flag a schema-declared sensitive field that is null in the live response', async () => {
    const queue = makeQueue();
    queue.push({ status: 200, bodyText: JSON.stringify({ name: 'Alice', apiKey: null }) });
    mockFetchQueue(queue);

    const paths = {
      '/profile': {
        get: responseSchema({ name: { type: 'string' }, apiKey: { type: 'string' } })
      }
    };
    const api = makeApiSpec('https://api.example.com/api/v2', paths);
    const findings = await inventorySuite().run({ ...makeSuiteCtx(), api });

    expect(findings.every((f) => f.id !== 'inventory.excessive_data_exposure')).toBe(true);
  });

  it('flags a field declared via format: password even without a sensitive name', async () => {
    const queue = makeQueue();
    queue.push({ status: 200, bodyText: JSON.stringify({ credential: 'hunter2' }) });
    mockFetchQueue(queue);

    const paths = {
      '/profile': { get: responseSchema({ credential: { type: 'string', format: 'password' } }) }
    };
    const api = makeApiSpec('https://api.example.com/api/v2', paths);
    const findings = await inventorySuite().run({ ...makeSuiteCtx(), api });

    const f = findings.find((x) => x.id === 'inventory.excessive_data_exposure');
    expect(f).toBeDefined();
    const endpoints = f!.evidence?.endpoints as Array<{ fields: string[] }>;
    expect(endpoints[0].fields).toEqual(['credential']);
  });

  it('sweeps candidate ids for an integer path param and flags once a live read succeeds', async () => {
    // First candidate id (1) 404s; second (2) succeeds and carries the field.
    const queue = makeQueue();
    queue.push({ status: 404 });
    queue.push({ status: 200, bodyText: JSON.stringify({ id: 2, apiKey: 'sk_live_bob' }) });
    mockFetchQueue(queue);

    const paths = {
      '/users/{id}': {
        get: {
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
          ...responseSchema({ id: { type: 'integer' }, apiKey: { type: 'string' } })
        }
      }
    };
    const api = makeApiSpec('https://api.example.com/api/v2', paths);
    const findings = await inventorySuite().run({ ...makeSuiteCtx(), api });

    const f = findings.find((x) => x.id === 'inventory.excessive_data_exposure');
    expect(f).toBeDefined();
    const endpoints = f!.evidence?.endpoints as Array<{ endpoint: string; fields: string[] }>;
    expect(endpoints[0].endpoint).toBe('GET /api/v2/users/{id}');
    expect(endpoints[0].fields).toEqual(['apiKey']);
  });

  it('does not probe a path with a non-integer path param', async () => {
    // Only the 10 base requests are queued; probing would throw "no more mocked responses".
    mockFetchQueue(makeQueue());

    const paths = {
      '/users/{slug}': {
        get: {
          parameters: [{ name: 'slug', in: 'path', required: true, schema: { type: 'string' } }],
          ...responseSchema({ apiKey: { type: 'string' } })
        }
      }
    };
    const api = makeApiSpec('https://api.example.com/api/v2', paths);
    const findings = await inventorySuite().run({ ...makeSuiteCtx(), api });

    expect(findings.every((f) => f.id !== 'inventory.excessive_data_exposure')).toBe(true);
  });

  it('does not probe a path with more than one path param', async () => {
    // Only the 10 base requests are queued; probing would throw "no more mocked responses".
    mockFetchQueue(makeQueue());

    const paths = {
      '/orgs/{orgId}/users/{id}': {
        get: {
          parameters: [
            { name: 'orgId', in: 'path', required: true, schema: { type: 'integer' } },
            { name: 'id', in: 'path', required: true, schema: { type: 'integer' } }
          ],
          ...responseSchema({ apiKey: { type: 'string' } })
        }
      }
    };
    const api = makeApiSpec('https://api.example.com/api/v2', paths);
    const findings = await inventorySuite().run({ ...makeSuiteCtx(), api });

    expect(findings.every((f) => f.id !== 'inventory.excessive_data_exposure')).toBe(true);
  });

  it('issues no probe and emits no finding when no response field looks sensitive', async () => {
    // Only the 10 base requests are queued; a stray probe would throw "no more mocked responses".
    mockFetchQueue(makeQueue());

    const paths = {
      '/profile': { get: responseSchema({ name: { type: 'string' }, bio: { type: 'string' } }) }
    };
    const api = makeApiSpec('https://api.example.com/api/v2', paths);
    const findings = await inventorySuite().run({ ...makeSuiteCtx(), api });

    expect(findings.every((f) => f.id !== 'inventory.excessive_data_exposure')).toBe(true);
  });

  it('does not probe for excessive data exposure without a loaded spec', async () => {
    // Only the 10 base requests are queued; a stray probe would throw "no more mocked responses".
    mockFetchQueue(makeQueue());

    const findings = await inventorySuite().run(makeSuiteCtx());

    expect(findings.every((f) => f.id !== 'inventory.excessive_data_exposure')).toBe(true);
  });
});
