import { describe, it, expect } from 'vitest';
import { rateLimitSuite } from '../src/suites/ratelimit.js';
import { mockFetchQueue } from './helpers/fetchMock.js';
import { makeSuiteCtx } from './helpers/makeConfig.js';

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
