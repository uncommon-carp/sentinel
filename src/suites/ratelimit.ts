/**
 * Rate limit suite
 *
 * Checks:
 * - Header scan: probes selected endpoints for X-RateLimit-* / RateLimit-* headers
 * - Burst probe: sequential requests to the first selected endpoint; flags missing 429 or headers
 * - Retry-After: flags 429 responses that omit Retry-After
 * - Sensitive business-flow burst probe (opt-in): when businessFlow.sensitivePaths is
 *   non-empty, retargets the same burst probe at each declared endpoint instead of the
 *   first selected one, emitting a higher-severity finding on an unthrottled result (API6)
 *
 * Burst is sequential with delay (default 75ms) — no concurrent hammering.
 * Burst size is capped at min(ratelimit.burstCount, active.maxRequestsPerSuite).
 *
 * Configuration:
 * - ratelimit.burstCount        number of burst requests (default 10)
 * - ratelimit.delayMs           ms between burst requests (default 75)
 * - businessFlow.sensitivePaths method+path pairs or operationIds to run the sensitive-flow probe against
 */

import type { Suite, Finding, SuiteContext } from '../core/types.js';
import { resolveEndpoints } from '../core/endpoints.js';

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

type BurstResponse = { status: number; headers: Record<string, string>; url: string };

// Sequential burst of `burstCount` requests to a single method+path, `delayMs`
// apart, stopping early on the first 429. Shared by phase 2 (the default
// probe endpoint) and phase 3 (each declared sensitive business-flow endpoint)
// — same mechanism, different target.
async function runBurst(
  ctx: SuiteContext,
  method: string,
  path: string,
  burstCount: number,
  delayMs: number
): Promise<BurstResponse[]> {
  const { logger } = ctx;
  logger.debug('Starting burst probe', {
    event: 'ratelimit.burst.start',
    probePath: path,
    method,
    burstCount,
    delayMs
  });

  const burst: BurstResponse[] = [];
  for (let i = 0; i < burstCount; i++) {
    if (i > 0) await sleep(delayMs);
    const res = await ctx.http.request({ method, path });
    burst.push({ status: res.status, headers: res.headers, url: res.url });
    logger.debug('Burst request completed', {
      event: 'ratelimit.burst.request',
      index: i + 1,
      of: burstCount,
      status: res.status
    });
    if (res.status === 429) {
      logger.debug('Burst probe throttled', {
        event: 'ratelimit.burst.throttled',
        requestsBeforeThrottle: i + 1
      });
      break;
    }
  }
  return burst;
}

// Sensitive business-flow path resolution (OWASP API6 groundwork, story 5.10).
// Each declared entry is one of:
// - "METHOD /path"  (explicit method + path, e.g. "POST /api/v2/coupons/redeem")
// - "/path"         (bare path, defaults to GET — same convention as auth.probePaths)
// - an operationId  (resolved against the loaded OpenAPI spec, if any)
const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head']);

function resolveSensitivePath(
  raw: string,
  spec: Record<string, unknown> | undefined
): { method: string; path: string } | null {
  const trimmed = raw.trim();

  const explicit = trimmed.match(/^([A-Za-z]+)\s+(\/\S*)$/);
  if (explicit) {
    const method = explicit[1]!.toLowerCase();
    if (HTTP_METHODS.has(method)) return { method, path: explicit[2]! };
  }

  if (trimmed.startsWith('/')) return { method: 'get', path: trimmed };

  const paths = spec?.paths as Record<string, unknown> | undefined;
  if (paths && typeof paths === 'object') {
    for (const [path, pathItemRaw] of Object.entries(paths)) {
      const pathItem = pathItemRaw as Record<string, unknown> | undefined;
      if (!pathItem) continue;
      for (const [method, operationRaw] of Object.entries(pathItem)) {
        if (!HTTP_METHODS.has(method)) continue;
        const operation = operationRaw as Record<string, unknown> | undefined;
        if (operation?.['operationId'] === trimmed) return { method, path };
      }
    }
  }
  return null;
}

export function rateLimitSuite(): Suite {
  return {
    name: 'ratelimit',
    description:
      'Checks for HTTP rate limiting via header inspection and a sequential burst probe.',
    async run(ctx): Promise<Finding[]> {
      const { logger } = ctx;
      const findings: Finding[] = [];
      const cap = ctx.config.active.maxRequestsPerSuite;

      // Phase 1: scan endpoints for rate-limit headers.
      const toProbe = resolveEndpoints(ctx.selectedEndpoints).slice(0, cap);
      let anyHeadersFound = false;

      for (const ep of toProbe) {
        logger.debug('Rate limiting probing', { event: 'ratelimit.probe', endpoint: ep });
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
      const burstCount = Math.min(ctx.config.ratelimit.burstCount, cap);
      const delayMs = ctx.config.ratelimit.delayMs;

      const burst = await runBurst(ctx, 'GET', probePath, burstCount, delayMs);

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

      // Phase 3: sensitive business-flow burst probe (OWASP API6), opt-in via
      // businessFlow.sensitivePaths (story 5.10) — only runs when the user has
      // declared at least one sensitive-flow endpoint (checkout, coupon
      // redemption, password reset, ...). Same burst-probe mechanism as phase
      // 2, retargeted at each declared path instead of toProbe[0]. An
      // unthrottled *declared-sensitive* endpoint is a stronger signal than a
      // generically unthrottled one, so it gets its own higher-severity
      // finding ID rather than reusing ratelimit.no_429_on_burst.
      const sensitiveFlows = ctx.config.businessFlow.sensitivePaths
        .map((raw) => resolveSensitivePath(raw, ctx.api?.spec))
        .filter((r): r is { method: string; path: string } => r !== null);

      const unthrottledFlows: Array<{ endpoint: string; statuses: number[] }> = [];

      // Bound total phase-3 work by the per-suite request cap. Each flow can
      // burn up to `burstCount` requests, so charge the actual number sent
      // (runBurst may stop early on a 429) against a running budget rather
      // than just capping the number of flows — otherwise N declared flows
      // at the default burstCount could fire N × burstCount requests, far
      // exceeding the cap.
      let budget = cap;
      for (const flow of sensitiveFlows) {
        if (budget < 1) break;
        const method = flow.method.toUpperCase();
        const flowBurstCount = Math.min(burstCount, budget);
        const flowBurst = await runBurst(ctx, method, flow.path, flowBurstCount, delayMs);
        budget -= flowBurst.length;

        const flowThrottled = flowBurst.find((r) => r.status === 429);
        const flowHasHeaders = flowBurst.some((r) => hasRateLimitHeaders(r.headers));

        if (flowThrottled) {
          if (!flowThrottled.headers['retry-after']) {
            findings.push({
              id: 'ratelimit.missing_retry_after',
              title: '429 response missing Retry-After header',
              severity: 'low',
              description:
                'Rate limiting was triggered (HTTP 429) on a declared sensitive business-flow ' +
                'endpoint, but the response did not include a Retry-After header. Without it, ' +
                'clients have no signal for when to safely retry and may resort to aggressive polling.',
              whyItMatters:
                'Clients with no retry guidance typically resort to aggressive polling, worsening load on an already-throttled endpoint and turning a protective mechanism into an amplifier.',
              remediation:
                'Include a Retry-After header on 429 responses. The value should be the number ' +
                'of seconds to wait, or an HTTP-date indicating when the client may retry.',
              owasp: 'API4: Unrestricted Resource Consumption',
              evidence: {
                probeUrl: flowThrottled.url,
                requestsBeforeThrottle: flowBurst.length,
                burstCount: flowBurstCount,
                delayMs
              },
              suite: 'ratelimit',
              tags: ['ratelimit', 'http', 'business-flow']
            });
          }
        } else if (!flowHasHeaders) {
          unthrottledFlows.push({
            endpoint: `${method} ${flow.path}`,
            statuses: flowBurst.map((r) => r.status)
          });
        }
      }

      if (unthrottledFlows.length > 0) {
        findings.push({
          id: 'ratelimit.sensitive_flow_unthrottled',
          title: 'Declared sensitive business flow endpoint is not rate limited',
          severity: 'high',
          description:
            `${unthrottledFlows.length} endpoint(s) declared as sensitive business flows ` +
            `(businessFlow.sensitivePaths) completed a burst of ${burstCount} sequential ` +
            `requests (${delayMs}ms apart) without triggering a 429 or returning rate-limit ` +
            'headers. Unlike a generically unthrottled endpoint, this one was explicitly ' +
            'named as a sensitive flow — checkout, coupon redemption, password reset, or ' +
            'similar — where unrestricted automation has direct business or fraud impact.',
          whyItMatters:
            'Sensitive business flows are prime targets for scripted abuse — coupon farming, ' +
            'credential stuffing on login/reset, automated checkout fraud — where the damage is ' +
            'measured in real financial or account-takeover impact, not just infrastructure load.',
          remediation:
            'Apply stricter rate limiting or CAPTCHA/step-up verification specifically to ' +
            'business-critical flows, in addition to general API rate limiting. Return 429 ' +
            'with standard rate-limit headers when limits are exceeded.',
          owasp: 'API6: Unrestricted Access to Sensitive Business Flows',
          evidence: { flows: unthrottledFlows, burstCount, delayMs },
          suite: 'ratelimit',
          tags: ['ratelimit', 'business-flow', 'api6']
        });
      }

      return findings;
    }
  };
}
