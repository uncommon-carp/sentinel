/**
 * Auth suite
 *
 * Checks:
 * - 401 semantics: WWW-Authenticate should be present to advertise the auth scheme
 * - Redirect safety: cross-origin redirects on an auth probe can leak credentials
 * - Enforcement heuristic: compares authed vs. unauthed responses on probePath
 * - JWT inspection: if any response includes a JWT (headers or body), decode and check
 *   for alg:none, missing exp, already-expired issuance, and overly long TTL (>24h)
 *
 * Heuristic by design — false positives are possible if probePaths are not protected.
 *
 * Configuration:
 * - auth.probePaths       endpoints for probing (default ["/"])
 * - auth.compareUnauthed  gates the authed vs. unauthed comparison
 */

import type { Suite, Finding, SelectedEndpoint } from '../core/types.js';
import type { HttpResponse } from '../http/client.js';

const JWT_TTL_LIMIT = 86400;
const JWT_RE = /[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/g;

function extractJwts(res: HttpResponse): string[] {
  const seen = new Set<string>();
  const scan = (text: string) => {
    for (const m of text.matchAll(JWT_RE)) seen.add(m[0]);
  };
  for (const v of Object.values(res.headers)) scan(v);
  scan(res.bodyText);
  return [...seen];
}

function decodeJwt(
  token: string
): { header: Record<string, unknown>; payload: Record<string, unknown> } | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8'));
    if (typeof header !== 'object' || header === null) return null;
    if (typeof payload !== 'object' || payload === null) return null;
    return { header: header as Record<string, unknown>, payload: payload as Record<string, unknown> };
  } catch {
    return null;
  }
}

function inspectJwts(tokens: string[], res: HttpResponse): Finding[] {
  const findings: Finding[] = [];
  const now = Math.floor(Date.now() / 1000);

  for (const token of tokens) {
    const decoded = decodeJwt(token);
    if (!decoded) continue;

    const { header, payload } = decoded;
    const tokenPreview = `${token.slice(0, 40)}...`;

    if (typeof header.alg === 'string' && header.alg.toLowerCase() === 'none') {
      findings.push({
        id: 'auth.jwt_alg_none',
        title: 'JWT with alg:none detected in response',
        severity: 'critical',
        description:
          'A JWT using the "none" algorithm was found in a response. Tokens with alg:none carry no cryptographic signature; servers that accept them can be trivially bypassed.',
        whyItMatters:
          'An attacker can forge arbitrary JWT claims — including elevated roles — and gain unauthorized access to any endpoint that trusts the token, with no cryptographic barrier.',
        remediation:
          'Reject JWTs with alg:none server-side and enforce an explicit algorithm allowlist.',
        owasp: 'API2: Broken Authentication',
        evidence: { url: res.url, status: res.status, tokenPreview },
        suite: 'auth',
        tags: ['auth', 'jwt']
      });
    }

    if (!('exp' in payload)) {
      findings.push({
        id: 'auth.jwt_missing_exp',
        title: 'JWT with no expiration claim (exp) detected in response',
        severity: 'medium',
        description:
          'A JWT without an exp claim was found in a response. Non-expiring tokens cannot be automatically invalidated and remain valid indefinitely if leaked.',
        whyItMatters:
          'A stolen token without an expiry is valid forever. There is no time-bounded window to limit blast radius if a token is compromised, logged, or leaked through a third party.',
        remediation:
          'Always include an exp claim in issued JWTs and reject tokens that lack one on the server side.',
        owasp: 'API2: Broken Authentication',
        evidence: { url: res.url, status: res.status, tokenPreview },
        suite: 'auth',
        tags: ['auth', 'jwt']
      });
    }

    const exp = typeof payload.exp === 'number' ? payload.exp : null;
    const iat = typeof payload.iat === 'number' ? payload.iat : null;

    if (exp !== null && exp < now && res.status >= 200 && res.status < 300) {
      findings.push({
        id: 'auth.jwt_expired_accepted',
        title: 'Server issued an already-expired JWT',
        severity: 'high',
        description:
          'A JWT with an exp claim in the past was present in a successful (2xx) response. The server appears to have issued a token that is already expired.',
        whyItMatters:
          'If the server issues or accepts expired tokens, expiry-based revocation is not enforced. Leaked tokens remain usable past their intended lifetime, removing the primary time-bound safety net.',
        remediation:
          'Validate JWT expiry server-side and ensure issued tokens have exp set in the future.',
        owasp: 'API2: Broken Authentication',
        evidence: { url: res.url, status: res.status, exp, now, tokenPreview },
        suite: 'auth',
        tags: ['auth', 'jwt']
      });
    }

    if (exp !== null) {
      const ttl = exp - (iat ?? now);
      if (ttl > JWT_TTL_LIMIT) {
        findings.push({
          id: 'auth.jwt_long_ttl',
          title: 'JWT with unusually long TTL detected in response',
          severity: 'low',
          description:
            `A JWT valid for more than ${JWT_TTL_LIMIT / 3600}h was found in a response. Long-lived access tokens extend the window of opportunity if a token is compromised.`,
          whyItMatters:
            'Short-lived tokens limit attacker dwell time after a compromise — if a token leaks, it expires quickly. Long-lived access tokens negate this protection without requiring explicit revocation.',
          remediation:
            'Issue short-lived access tokens (ideally ≤1h) and use refresh tokens for long-lived sessions.',
          owasp: 'API2: Broken Authentication',
          evidence: { url: res.url, status: res.status, ttlSeconds: ttl, tokenPreview },
          suite: 'auth',
          tags: ['auth', 'jwt']
        });
      }
    }
  }

  return findings;
}

function isRedirect(status: number) {
  return status >= 300 && status < 400;
}

export function authSuite(): Suite {
  return {
    name: 'auth',
    description: 'Checks HTTP auth semantics and basic auth enforcement behavior.',
    async run(ctx): Promise<Finding[]> {
      const findings: Finding[] = [];

      const cap = Math.max(1, ctx.config.active.maxRequestsPerSuite ?? 20);
      const toProbe: SelectedEndpoint[] = ctx.config.auth.probePaths
        .slice(0, cap)
        .map((path) => ({ method: 'get', path }));

      const authConfigured = ctx.config.auth.type !== 'none';
      const overrideHeaders: Record<string, string> = {};
      if (ctx.config.auth.type === 'bearer') overrideHeaders['authorization'] = '';
      if (ctx.config.auth.type === 'apiKey' && ctx.config.auth.apiKeyHeader) {
        overrideHeaders[ctx.config.auth.apiKeyHeader] = '';
      }

      for (const ep of toProbe) {
        const url = new URL(ep.path, ctx.config.target.baseUrl).toString();

        const authedRes = await ctx.http.request({
          method: 'GET',
          path: ep.path
        });

        findings.push(...inspectJwts(extractJwts(authedRes), authedRes));

        // Redirect handling:
        // We do not follow redirects. If the target redirects across origins,
        // naive clients can accidentally forward Authorization headers.
        // Flag cross-origin redirects as a safety signal (not an exploit).
        if (isRedirect(authedRes.status)) {
          const location = authedRes.headers['location'];
          if (location) {
            try {
              const locUrl = new URL(location, authedRes.url);
              const baseOrigin = new URL(ctx.config.target.baseUrl).origin;
              if (locUrl.origin !== baseOrigin) {
                findings.push({
                  id: 'auth.redirect_cross_origin',
                  title: 'Cross-origin redirect observed on auth probe',
                  severity: 'medium',
                  description:
                    'Auth probe returned a redirect to a different origin. Following redirects with credentials can risk leaking Authorization headers in naive clients.',
                  whyItMatters:
                    'Some HTTP clients and SDKs forward Authorization headers on redirects without checking whether the destination is the same origin. A cross-origin redirect can silently exfiltrate credentials to an attacker-controlled domain.',
                  remediation:
                    'Avoid redirecting authenticated endpoints across origins, or ensure clients do not forward credentials across origins.',
                  owasp: 'API2: Broken Authentication',
                  evidence: {
                    probeUrl: authedRes.url,
                    location: locUrl.toString(),
                    status: authedRes.status
                  },
                  suite: 'auth',
                  tags: ['auth', 'redirect']
                });
              }
            } catch {
              // Ignore malformed Location values (could add a low severity finding later)
            }
          }
        }

        if (authedRes.status === 401) {
          const www = authedRes.headers['www-authenticate'];
          if (!www) {
            findings.push({
              id: 'auth.401_missing_www_authenticate',
              title: '401 response missing WWW-Authenticate header',
              severity: 'low',
              description:
                'Endpoint returned 401 Unauthorized but did not include a WWW-Authenticate header. This can break clients and obscures the intended auth scheme.',
              whyItMatters:
                'Clients have no standard way to discover the required auth scheme, which breaks spec-compliant HTTP clients and can mask auth bypass conditions during testing.',
              remediation:
                'Return a WWW-Authenticate header on 401 responses that require authentication (e.g., Bearer realm=...).',
              owasp: 'API2: Broken Authentication',
              evidence: { probeUrl: authedRes.url, status: authedRes.status },
              suite: 'auth',
              tags: ['auth', 'http']
            });
          }
        }

        // Optional enforcement heuristic:
        // If auth is configured, compare responses with auth vs. "cleared" auth.
        // This is only meaningful when probePaths are expected to be protected.
        if (authConfigured && (ctx.config.auth.compareUnauthed ?? true)) {
          // HttpClient merges auth headers before per-request headers.
          // To simulate an unauthenticated request without creating a second client,
          // we override relevant credential headers with empty strings.
          const unauthedRes = await ctx.http.request({
            method: 'GET',
            path: ep.path,
            headers: overrideHeaders
          });

          findings.push(...inspectJwts(extractJwts(unauthedRes), unauthedRes));

          // If both authed and unauthed succeed (2xx), that's suspicious *if the path is meant to be protected*.
          const authedOk = authedRes.status >= 200 && authedRes.status < 300;
          const unauthedOk = unauthedRes.status >= 200 && unauthedRes.status < 300;

          if (authedOk && unauthedOk) {
            findings.push({
              id: 'auth.possible_bypass_probe',
              title: 'Auth probe succeeded with and without credentials',
              severity: 'medium',
              description:
                'The configured auth probe endpoint returned success both with configured credentials and with credentials cleared. This may indicate the endpoint is not protected or auth is not enforced as expected.',
              whyItMatters:
                'If an endpoint returns the same success response regardless of credential validity, unauthenticated access may be possible — the core broken authentication scenario.',
              remediation:
                'Verify that the probe path points to an endpoint that requires authentication, and ensure auth is enforced server-side.',
              owasp: 'API2: Broken Authentication',
              evidence: {
                probeUrl: url,
                authedStatus: authedRes.status,
                unauthedStatus: unauthedRes.status
              },
              suite: 'auth',
              tags: ['auth', 'bypass']
            });
          }
        }
      }

      return findings;
    }
  };
}
