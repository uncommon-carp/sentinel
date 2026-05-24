import { describe, it, expect } from 'vitest';
import { injectionSuite } from '../src/suites/injection.js';
import { mockFetchQueue } from './helpers/fetchMock.js';
import { makeSuiteCtx } from './helpers/makeConfig.js';
import type { LoadedApiSpec } from '../src/openapi/types.js';

function makeSpecWithQueryParam(path: string, paramName: string): LoadedApiSpec {
  return {
    source: 'test',
    spec: {
      paths: {
        [path]: {
          get: { parameters: [{ in: 'query', name: paramName }] }
        }
      }
    },
    endpoints: [{ method: 'get', path }]
  };
}

function makeSpecWithBodyField(path: string, fieldName: string): LoadedApiSpec {
  return {
    source: 'test',
    spec: {
      paths: {
        [path]: {
          post: {
            requestBody: {
              content: {
                'application/json': {
                  schema: { type: 'object', properties: { [fieldName]: { type: 'string' } } }
                }
              }
            }
          }
        }
      }
    },
    endpoints: [{ method: 'post', path }]
  };
}

describe('injection suite', () => {
  it('returns empty findings and logs a reason when no OpenAPI spec is loaded', async () => {
    const logged: string[] = [];
    const ctx = {
      ...makeSuiteCtx(),
      logger: { info: (m: string) => logged.push(m), warn: () => {}, error: () => {}, debug: () => {} }
    };

    const findings = await injectionSuite().run(ctx);

    expect(findings).toHaveLength(0);
    expect(logged.some((m) => m.includes('no OpenAPI spec'))).toBe(true);
  });

  it('emits injection.error_disclosure on SQL error string in response', async () => {
    mockFetchQueue([{ status: 500, bodyText: "ERROR: sql syntax near ''" }]);

    const api = makeSpecWithQueryParam('/search', 'q');
    const ctx = { ...makeSuiteCtx(), api, selectedEndpoints: [{ method: 'get', path: '/search' }] };
    ctx.config.injection.categories = ['sql'];

    const findings = await injectionSuite().run(ctx);

    const f = findings.find((x) => x.id === 'injection.error_disclosure');
    expect(f).toBeDefined();
    expect(f?.severity).toBe('high');
    expect(f?.suite).toBe('injection');
    expect(f?.tags).toContain('sql');
    expect(f?.evidence?.parameter).toBe('q');
    expect(f?.evidence?.matchedError).toBe('sql syntax');
  });

  it('emits injection.possible_template_injection when 49 appears in response', async () => {
    mockFetchQueue([{ status: 200, bodyText: 'Hello, 49!' }]);

    const api = makeSpecWithQueryParam('/greet', 'name');
    const ctx = { ...makeSuiteCtx(), api, selectedEndpoints: [{ method: 'get', path: '/greet' }] };
    ctx.config.injection.categories = ['template'];

    const findings = await injectionSuite().run(ctx);

    const f = findings.find((x) => x.id === 'injection.possible_template_injection');
    expect(f).toBeDefined();
    expect(f?.severity).toBe('high');
    expect(f?.suite).toBe('injection');
    expect(f?.tags).toContain('template');
    expect(f?.evidence?.parameter).toBe('name');
    expect(f?.evidence?.evaluated).toBe('49');
  });

  it('early-outs on first hit per parameter (single finding, single request)', async () => {
    // Only one response queued — if suite sends a second request, the mock throws.
    mockFetchQueue([{ status: 500, bodyText: 'sql syntax error near test' }]);

    const api = makeSpecWithQueryParam('/search', 'q');
    const ctx = { ...makeSuiteCtx(), api, selectedEndpoints: [{ method: 'get', path: '/search' }] };
    ctx.config.injection.categories = ['sql'];

    const findings = await injectionSuite().run(ctx);

    expect(findings.filter((f) => f.evidence?.parameter === 'q')).toHaveLength(1);
  });

  it('stops the entire suite when the request cap is reached', async () => {
    // Cap = 1: suite makes one request (no hit), then bails on the second payload.
    mockFetchQueue([{ status: 200, bodyText: 'nothing here' }]);

    const api = makeSpecWithQueryParam('/search', 'q');
    const logged: string[] = [];
    const ctx = {
      ...makeSuiteCtx(),
      api,
      selectedEndpoints: [{ method: 'get', path: '/search' }],
      logger: { info: (m: string) => logged.push(m), warn: () => {}, error: () => {}, debug: () => {} }
    };
    ctx.config.injection.categories = ['sql'];
    ctx.config.active.maxRequestsPerSuite = 1;

    const findings = await injectionSuite().run(ctx);

    expect(findings).toHaveLength(0);
    expect(logged.some((m) => m.includes('request cap reached'))).toBe(true);
  });

  it('emits injection.possible_command_injection when sentinel9 echoes back (command opt-in)', async () => {
    mockFetchQueue([{ status: 200, bodyText: 'output: sentinel9' }]);

    const api = makeSpecWithQueryParam('/run', 'cmd');
    const ctx = { ...makeSuiteCtx(), api, selectedEndpoints: [{ method: 'get', path: '/run' }] };
    ctx.config.injection.categories = ['command'];

    const findings = await injectionSuite().run(ctx);

    const f = findings.find((x) => x.id === 'injection.possible_command_injection');
    expect(f).toBeDefined();
    expect(f?.severity).toBe('critical');
    expect(f?.suite).toBe('injection');
    expect(f?.tags).toContain('command');
    expect(f?.evidence?.parameter).toBe('cmd');
  });

  it('probes body fields as POST requests', async () => {
    mockFetchQueue([{ status: 500, bodyText: 'pg_query failed: invalid input' }]);

    const api = makeSpecWithBodyField('/items', 'name');
    const ctx = { ...makeSuiteCtx(), api, selectedEndpoints: [{ method: 'post', path: '/items' }] };
    ctx.config.injection.categories = ['sql'];
    ctx.config.injection.paramTypes = ['body'];

    const findings = await injectionSuite().run(ctx);

    const f = findings.find((x) => x.id === 'injection.error_disclosure');
    expect(f).toBeDefined();
    expect(f?.evidence?.parameter).toBe('name');
    expect(f?.evidence?.paramType).toBe('body');
    expect(f?.evidence?.matchedError).toBe('pg_query');
  });
});
