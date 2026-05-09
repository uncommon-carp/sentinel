/**
 * Auth suite
 *
 * Checks:
 * - 401 semantics: WWW-Authenticate should be present to advertise the auth scheme
 * - Redirect safety: cross-origin redirects on an auth probe can leak credentials
 * - Enforcement heuristic: compares authed vs. unauthed responses on probePath
 *
 * Heuristic by design — false positives are possible if probePaths are not protected.
 *
 * Configuration:
 * - auth.probePaths     endpoints for probing (default ["/"])
 * - auth.compareUnauthed   gates the authed vs. unauthed comparison
 */

import type { Suite, Finding, SelectedEndpoint } from '../core/types.js';

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
                  remediation:
                    'Avoid redirecting authenticated endpoints across origins, or ensure clients do not forward credentials across origins.',
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
              remediation:
                'Return a WWW-Authenticate header on 401 responses that require authentication (e.g., Bearer realm=...).',
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
              remediation:
                'Verify that the probe path points to an endpoint that requires authentication, and ensure auth is enforced server-side.',
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
