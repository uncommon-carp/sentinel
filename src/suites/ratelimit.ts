/**
 * Rate limit suite
 *
 * What it checks:
 * - Header presence: probes selected endpoints for standard rate-limit response headers
 *   (X-RateLimit-*, RateLimit-*). Absent headers across all probed endpoints is a soft signal.
 * - Burst probe: sends a sequential burst of requests to probePath with a configurable
 *   inter-request delay, then checks whether a 429 was returned or rate-limit headers
 *   appeared. No 429 and no headers after the burst is a stronger signal.
 * - Retry-After semantics: if a 429 is observed, flags the absence of Retry-After.
 *
 * Safety / scope:
 * - Burst requests are sequential with a configurable delay between each (default 75ms).
 *   True concurrent hammering is intentionally avoided — sequential-with-delay is more
 *   predictable, still fast enough to trigger most rate limiters, and easier to explain
 *   in the report.
 * - Burst size is capped at min(ratelimit.burstCount, active.maxRequestsPerSuite).
 *
 * Configuration:
 * - ratelimit.probePath   endpoint for the burst probe (default "/")
 * - ratelimit.burstCount  number of burst requests (default 10)
 * - ratelimit.delayMs     ms to wait between burst requests (default 75)
 */

import type { Suite, Finding } from '../core/types.js';

const RATE_LIMIT_HEADERS = new Set([
  'x-ratelimit-limit',
  'x-ratelimit-remaining',
  'x-ratelimit-reset',
  'ratelimit-limit',
  'ratelimit-remaining',
  'ratelimit-reset',
  'x-rate-limit-limit',
  'x-rate-limit-remaining'
]);

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

function hasRateLimitHeaders(headers: Record<string, string>): boolean {
  return [...RATE_LIMIT_HEADERS].some((h) => h in headers);
}

export function rateLimitSuite(): Suite {
  return {
    name: 'ratelimit',
    description:
      'Checks for HTTP rate limiting via header inspection and a sequential burst probe.',
    async run(ctx): Promise<Finding[]> {
      const findings: Finding[] = [];
      const cap = Math.max(1, ctx.config.active.maxRequestsPerSuite ?? 20);

      // Phase 1: header scan across selected endpoints.
      // Checks whether any endpoint advertises rate-limit quota headers.
      const endpoints =
        ctx.selectedEndpoints && ctx.selectedEndpoints.length > 0
          ? ctx.selectedEndpoints
          : [{ method: 'get', path: '/' }];

      const toProbe = endpoints.slice(0, cap);
      let anyHeadersFound = false;

      for (const ep of toProbe) {
        const res = await ctx.http.request({ method: 'GET', path: ep.path });
        if (hasRateLimitHeaders(res.headers)) {
          anyHeadersFound = true;
          break;
        }
      }

      if (!anyHeadersFound) {
        findings.push({
          id: 'ratelimit.no_headers',
          title: 'No rate limit headers observed',
          severity: 'low',
          description:
            'None of the probed endpoints returned standard rate-limit headers ' +
            '(X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, etc.). ' +
            'Rate limiting may still be enforced at the infrastructure level without ' +
            'being communicated to clients via headers.',
          remediation:
            'Return standard rate-limit headers so clients can observe and adapt to quota ' +
            'constraints before being throttled (e.g. X-RateLimit-Limit, X-RateLimit-Remaining, ' +
            'X-RateLimit-Reset).',
          evidence: { probed: toProbe.length, paths: toProbe.map((e) => e.path) },
          suite: 'ratelimit',
          tags: ['ratelimit', 'http']
        });
      }

      // Phase 2: burst probe against a single configurable endpoint.
      // Requests are sent sequentially with a short inter-request delay to remain
      // predictable and safe while still being fast enough to trigger most rate limiters.
      const probePath = ctx.config.ratelimit.probePath ?? '/';
      const burstCount = Math.min(Math.max(2, ctx.config.ratelimit.burstCount ?? 10), cap);
      const delayMs = ctx.config.ratelimit.delayMs ?? 75;

      type BurstResponse = { status: number; headers: Record<string, string>; url: string };
      const burst: BurstResponse[] = [];

      for (let i = 0; i < burstCount; i++) {
        if (i > 0) await sleep(delayMs);
        const res = await ctx.http.request({ method: 'GET', path: probePath });
        burst.push({ status: res.status, headers: res.headers, url: res.url });
        if (res.status === 429) break;
      }

      const throttled = burst.find((r) => r.status === 429);
      const burstHasHeaders = burst.some((r) => hasRateLimitHeaders(r.headers));

      if (throttled) {
        // Rate limiting is enforced — check that clients are told when to retry.
        if (!throttled.headers['retry-after']) {
          findings.push({
            id: 'ratelimit.missing_retry_after',
            title: '429 response missing Retry-After header',
            severity: 'low',
            description:
              'Rate limiting was triggered (HTTP 429) but the response did not include a ' +
              'Retry-After header. Without it, clients have no signal for when to safely retry ' +
              'and may resort to aggressive polling.',
            remediation:
              'Include a Retry-After header on 429 responses. The value should be the number ' +
              'of seconds to wait, or an HTTP-date indicating when the client may retry.',
            evidence: {
              probeUrl: throttled.url,
              requestsBeforeThrottle: burst.length,
              burstCount,
              delayMs
            },
            suite: 'ratelimit',
            tags: ['ratelimit', 'http']
          });
        }
      } else if (!burstHasHeaders) {
        // No 429 and no rate-limit headers across the entire burst — stronger signal
        // that HTTP-layer rate limiting is absent on this endpoint.
        findings.push({
          id: 'ratelimit.no_429_on_burst',
          title: 'No rate limiting observed after burst',
          severity: 'medium',
          description:
            `A burst of ${burst.length} sequential requests (${delayMs}ms apart) to ` +
            `${probePath} completed without triggering a 429 or returning rate-limit headers. ` +
            'HTTP-layer rate limiting may not be enforced on this endpoint.',
          remediation:
            'Implement rate limiting at the API gateway or application layer. Return 429 ' +
            'when limits are exceeded and include standard rate-limit headers ' +
            '(X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset).',
          evidence: {
            probeUrl: burst[0]?.url,
            burstCount: burst.length,
            delayMs,
            statuses: burst.map((r) => r.status)
          },
          suite: 'ratelimit',
          tags: ['ratelimit']
        });
      }

      return findings;
    }
  };
}
