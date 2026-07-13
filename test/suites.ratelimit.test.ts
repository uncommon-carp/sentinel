import { describe, it, expect } from 'vitest';
import { rateLimitSuite } from '../src/suites/ratelimit.js';
import { mockFetchQueue } from './helpers/fetchMock.js';
import { makeSuiteCtx } from './helpers/makeConfig.js';
import type { LoadedApiSpec } from '../src/openapi/types.js';

function makeCtx(overrides?: { burstCount?: number }) {
  const ctx = makeSuiteCtx();
  ctx.config.ratelimit.burstCount = overrides?.burstCount ?? 3;
  return ctx;
}

// Helpers for readable mock queues.
const ok = (headers: Record<string, string> = {}) => ({ status: 200, headers });
const tooMany = (headers: Record<string, string> = {}) => ({ status: 429, headers });
const rl = { 'x-ratelimit-limit': '100', 'x-ratelimit-remaining': '99' };
const retryAfter = { 'retry-after': '30' };

describe('ratelimit suite — Phase 1: header scan', () => {
  it('emits no_headers when no endpoints return rate-limit headers', async () => {
    // Phase 1: 1 probe (no headers). Phase 2: 3 burst (no headers).
    mockFetchQueue([ok(), ok(), ok(), ok()]);

    const findings = await rateLimitSuite().run(makeCtx());

    expect(findings.some((f) => f.id === 'ratelimit.no_headers')).toBe(true);
    const finding = findings.find((f) => f.id === 'ratelimit.no_headers');
    expect(finding?.severity).toBe('low');
    expect(finding?.suite).toBe('ratelimit');
    expect(finding?.evidence?.probed).toBe(1);
  });

  it('does not emit no_headers when any probed endpoint returns rate-limit headers', async () => {
    // Phase 1: 1 probe with rate-limit headers (breaks early). Phase 2: 3 burst.
    mockFetchQueue([ok(rl), ok(), ok(), ok()]);

    const findings = await rateLimitSuite().run(makeCtx());

    expect(findings.some((f) => f.id === 'ratelimit.no_headers')).toBe(false);
  });

  it('probes multiple selected endpoints before concluding no headers', async () => {
    // Phase 1: 2 probes (no headers). Phase 2: 2 burst.
    mockFetchQueue([ok(), ok(), ok(), ok()]);

    const findings = await rateLimitSuite().run({
      ...makeCtx({ burstCount: 2 }),
      selectedEndpoints: [
        { method: 'get', path: '/users' },
        { method: 'get', path: '/posts' }
      ]
    });

    const finding = findings.find((f) => f.id === 'ratelimit.no_headers');
    expect(finding).toBeDefined();
    expect(finding?.evidence?.probed).toBe(2);
  });
});

describe('ratelimit suite — Phase 2: burst probe', () => {
  it('emits no_429_on_burst when burst completes with no 429 and no rate-limit headers', async () => {
    // Phase 1: 1 probe (no headers). Phase 2: 3 burst (no headers, no 429).
    mockFetchQueue([ok(), ok(), ok(), ok()]);

    const findings = await rateLimitSuite().run(makeCtx());

    const finding = findings.find((f) => f.id === 'ratelimit.no_429_on_burst');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
    expect(finding?.suite).toBe('ratelimit');
    expect(finding?.evidence?.burstCount).toBe(3);
    expect(finding?.evidence?.statuses).toEqual([200, 200, 200]);
  });

  it('does not emit no_429_on_burst when burst responses include rate-limit headers', async () => {
    // Phase 1: no headers. Phase 2: burst where first response has rate-limit headers.
    mockFetchQueue([ok(), ok(rl), ok(), ok()]);

    const findings = await rateLimitSuite().run(makeCtx());

    expect(findings.some((f) => f.id === 'ratelimit.no_429_on_burst')).toBe(false);
  });

  it('emits missing_retry_after when a 429 has no Retry-After header', async () => {
    // Phase 1: 1 probe. Phase 2: burst hits 429 on the second request without Retry-After.
    mockFetchQueue([ok(), ok(), tooMany()]);

    const findings = await rateLimitSuite().run(makeCtx());

    const finding = findings.find((f) => f.id === 'ratelimit.missing_retry_after');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('low');
    expect(finding?.suite).toBe('ratelimit');
    expect(finding?.evidence?.requestsBeforeThrottle).toBe(2);
  });

  it('does not emit missing_retry_after when 429 includes a Retry-After header', async () => {
    // Phase 2: first burst request returns 429 with Retry-After.
    mockFetchQueue([ok(), tooMany(retryAfter)]);

    const findings = await rateLimitSuite().run(makeCtx());

    expect(findings.some((f) => f.id === 'ratelimit.missing_retry_after')).toBe(false);
  });

  it('does not emit no_429_on_burst when a 429 is received (even without Retry-After)', async () => {
    // A 429 means rate limiting IS present — no_429_on_burst must not also fire.
    mockFetchQueue([ok(), tooMany()]);

    const findings = await rateLimitSuite().run(makeCtx());

    expect(findings.some((f) => f.id === 'ratelimit.no_429_on_burst')).toBe(false);
  });

  it('stops the burst on the first 429 without sending further requests', async () => {
    // Provide only 2 mock responses (phase 1 + one burst hit). A 3rd would throw if consumed.
    mockFetchQueue([ok(), tooMany(retryAfter)]);

    // Should not throw (would throw if the 3rd burst request were attempted).
    await expect(rateLimitSuite().run(makeCtx())).resolves.not.toThrow();
  });
});

describe('ratelimit suite — Phase 3: sensitive business-flow burst probe', () => {
  function makeFlowCtx(
    sensitivePaths: string[],
    overrides?: { burstCount?: number; api?: LoadedApiSpec; cap?: number }
  ) {
    const ctx = makeCtx({ burstCount: overrides?.burstCount ?? 2 });
    ctx.config.businessFlow.sensitivePaths = sensitivePaths;
    if (overrides?.api) ctx.api = overrides.api;
    if (overrides?.cap) ctx.config.active.maxRequestsPerSuite = overrides.cap;
    return ctx;
  }

  it('emits sensitive_flow_unthrottled when a declared flow completes burst with no 429/headers', async () => {
    // Phase 1: 1 probe. Phase 2: 2 burst. Phase 3: 2 burst for the declared flow. All ok().
    mockFetchQueue([ok(), ok(), ok(), ok(), ok()]);

    const findings = await rateLimitSuite().run(makeFlowCtx(['POST /api/v2/coupons/redeem']));

    const finding = findings.find((f) => f.id === 'ratelimit.sensitive_flow_unthrottled');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.suite).toBe('ratelimit');
    expect(finding?.owasp).toContain('API6');
    const flows = finding?.evidence?.flows as Array<{ endpoint: string; statuses: number[] }>;
    expect(flows).toHaveLength(1);
    expect(flows[0]).toMatchObject({
      endpoint: 'POST /api/v2/coupons/redeem',
      statuses: [200, 200]
    });
  });

  it('does not emit sensitive_flow_unthrottled when the declared flow is throttled', async () => {
    // Phase 1: 1. Phase 2: 2 burst (ok). Phase 3: throttled on the 1st request, stops early.
    mockFetchQueue([ok(), ok(), ok(), tooMany(retryAfter)]);

    const findings = await rateLimitSuite().run(makeFlowCtx(['POST /api/v2/coupons/redeem']));

    expect(findings.some((f) => f.id === 'ratelimit.sensitive_flow_unthrottled')).toBe(false);
  });

  it('emits missing_retry_after when a sensitive flow is throttled without Retry-After', async () => {
    mockFetchQueue([ok(), ok(), ok(), tooMany()]);

    const findings = await rateLimitSuite().run(makeFlowCtx(['POST /api/v2/coupons/redeem']));

    const finding = findings.find((f) => f.id === 'ratelimit.missing_retry_after');
    expect(finding).toBeDefined();
    expect(finding?.tags).toContain('business-flow');
  });

  it('does not run the sensitive-flow probe when businessFlow.sensitivePaths is empty (default)', async () => {
    // Phase 1: 1. Phase 2: 2 burst. No phase 3 requests — a stray one would exhaust the queue.
    const fetchMock = mockFetchQueue([ok(), ok(), ok()]);

    const findings = await rateLimitSuite().run(makeCtx({ burstCount: 2 }));

    expect(findings.some((f) => f.id === 'ratelimit.sensitive_flow_unthrottled')).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('probes an explicit "METHOD /path" declaration with the declared method', async () => {
    const fetchMock = mockFetchQueue([ok(), ok(), ok()]);

    await rateLimitSuite().run(makeFlowCtx(['PUT /api/v2/settings'], { burstCount: 1 }));

    const lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1];
    const init = lastCall?.[1] as RequestInit;
    expect(init.method).toBe('PUT');
    expect(lastCall?.[0] as string).toContain('/api/v2/settings');
  });

  it('defaults a bare path declaration to GET', async () => {
    const fetchMock = mockFetchQueue([ok(), ok(), ok()]);

    await rateLimitSuite().run(makeFlowCtx(['/api/v2/coupons/redeem'], { burstCount: 1 }));

    const lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1];
    const init = lastCall?.[1] as RequestInit;
    expect(init.method).toBe('GET');
  });

  it('resolves an operationId against the loaded OpenAPI spec', async () => {
    const fetchMock = mockFetchQueue([ok(), ok(), ok()]);
    const api: LoadedApiSpec = {
      source: 'test',
      spec: {
        paths: {
          '/api/v2/coupons/redeem': {
            post: { operationId: 'redeemCoupon', responses: { 200: {} } }
          }
        }
      },
      endpoints: []
    };

    await rateLimitSuite().run(makeFlowCtx(['redeemCoupon'], { burstCount: 1, api }));

    const lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1];
    const init = lastCall?.[1] as RequestInit;
    expect(init.method).toBe('POST');
    expect(lastCall?.[0] as string).toContain('/api/v2/coupons/redeem');
  });

  it('skips a sensitive path entry that cannot be resolved (unknown operationId, no spec)', async () => {
    // Phase 1: 1. Phase 2: 1 burst. No phase 3 requests since resolution fails.
    const fetchMock = mockFetchQueue([ok(), ok()]);

    await rateLimitSuite().run(makeFlowCtx(['nonexistentOperation'], { burstCount: 1 }));

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('aggregates multiple unthrottled flows into one finding', async () => {
    // Phase 1: 1. Phase 2: 1 burst. Phase 3: 2 flows x 1 burst each.
    mockFetchQueue([ok(), ok(), ok(), ok()]);

    const findings = await rateLimitSuite().run(
      makeFlowCtx(['POST /api/v2/coupons/redeem', 'POST /api/v2/checkout'], { burstCount: 1 })
    );

    const finding = findings.find((f) => f.id === 'ratelimit.sensitive_flow_unthrottled');
    expect(finding).toBeDefined();
    const flows = finding?.evidence?.flows as Array<{ endpoint: string }>;
    expect(flows).toHaveLength(2);
  });

  it('bounds total phase-3 requests by the per-suite cap instead of firing burstCount per flow unconditionally', async () => {
    // cap=3, burstCount=3, two declared flows: naively firing a full burst per
    // flow would send 2 x 3 = 6 phase-3 requests, blowing well past the cap.
    // Phase 1: 1 probe. Phase 2: 3 burst (min(burstCount, cap)). Phase 3:
    // flow1 consumes the entire remaining budget (3 requests, all ok — no
    // early 429 exit), leaving none for flow2. Only 7 mocked responses total
    // (1 + 3 + 3); an 8th request (flow2) would throw "no more mocked responses".
    const fetchMock = mockFetchQueue([
      ok(), // phase 1
      ok(),
      ok(),
      ok(), // phase 2
      ok(),
      ok(),
      ok() // phase 3, flow1 only
    ]);

    const ctx = makeFlowCtx(['POST /api/v2/coupons/redeem', 'POST /api/v2/checkout'], {
      burstCount: 3,
      cap: 3
    });

    await rateLimitSuite().run(ctx);

    expect(fetchMock).toHaveBeenCalledTimes(7);
  });
});
