/**
 * Rate limit suite
 *
 * Checks:
 * - Header scan: probes selected endpoints for X-RateLimit-* / RateLimit-* headers
 * - Burst probe: sequential requests to the first selected endpoint; flags missing 429 or headers
 * - Retry-After: flags 429 responses that omit Retry-After
 *
 * Burst is sequential with delay (default 75ms) — no concurrent hammering.
 * Burst size is capped at min(ratelimit.burstCount, active.maxRequestsPerSuite).
 *
 * Configuration:
 * - ratelimit.burstCount  number of burst requests (default 10)
 * - ratelimit.delayMs     ms between burst requests (default 75)
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

      // Phase 1: scan endpoints for rate-limit headers.
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
          whyItMatters:
            'Without visible quota signals, clients cannot self-throttle and automated tools have no indication that limits exist before hitting them — increasing the risk of accidental or deliberate overload.',
          remediation:
            'Return standard rate-limit headers so clients can observe and adapt to quota ' +
            'constraints before being throttled (e.g. X-RateLimit-Limit, X-RateLimit-Remaining, ' +
            'X-RateLimit-Reset).',
          owasp: 'API4: Unrestricted Resource Consumption',
          evidence: { probed: toProbe.length, paths: toProbe.map((e) => e.path) },
          suite: 'ratelimit',
          tags: ['ratelimit', 'http']
        });
      }

      // Phase 2: burst probe against a single configurable endpoint.
      // Requests are sent sequentially with a short inter-request delay to remain
      // predictable and safe while still being fast enough to trigger most rate limiters.
      const probePath = toProbe[0]?.path ?? '/';
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
            whyItMatters:
              'Clients with no retry guidance typically resort to aggressive polling, worsening load on an already-throttled endpoint and turning a protective mechanism into an amplifier.',
            remediation:
              'Include a Retry-After header on 429 responses. The value should be the number ' +
              'of seconds to wait, or an HTTP-date indicating when the client may retry.',
            owasp: 'API4: Unrestricted Resource Consumption',
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
          whyItMatters:
            'Unthrottled endpoints are vulnerable to brute-force, credential stuffing, scraping, and denial-of-service via sustained high request volume. Rate limiting is a primary control against all of these.',
          remediation:
            'Implement rate limiting at the API gateway or application layer. Return 429 ' +
            'when limits are exceeded and include standard rate-limit headers ' +
            '(X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset).',
          owasp: 'API4: Unrestricted Resource Consumption',
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
