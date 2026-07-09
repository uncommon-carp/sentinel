/**
 * Auth suite
 *
 * Checks:
 * - 401 semantics: WWW-Authenticate should be present to advertise the auth scheme
 * - Redirect safety: cross-origin redirects on an auth probe can leak credentials
 * - Enforcement heuristic: compares authed vs. unauthed responses on probePath
 * - JWT inspection: if any response includes a JWT (headers or body), decode and check
 *   for alg:none, weak/stub signatures, missing exp, already-expired issuance, and
 *   overly long TTL (>24h)
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
// HMAC-SHA256, the weakest standard JWS algorithm, produces a 32-byte (256-bit)
// signature; every registered HS/RS/ES algorithm is at least this long. A
// shorter signature on a non-"none" token cannot be a real one — it is a stub
// or placeholder.
const MIN_SIG_BYTES = 32;
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
    return {
      header: header as Record<string, unknown>,
      payload: payload as Record<string, unknown>
    };
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

    const alg = typeof header.alg === 'string' ? header.alg.toLowerCase() : null;
    const rawSig = token.split('.')[2] ?? '';
    if (alg !== null && alg !== 'none' && rawSig.length > 0) {
      // alg:none is already covered by jwt_alg_none above — don't double-flag.
      const sigBytes = Buffer.from(rawSig, 'base64url').length;
      if (sigBytes > 0 && sigBytes < MIN_SIG_BYTES) {
        findings.push({
          id: 'auth.jwt_weak_signature',
          title: 'JWT with a weak or stub signature detected in response',
          severity: 'high',
          description: `A JWT signature that decodes to only ${sigBytes} byte(s) was found in a response — far shorter than the ${MIN_SIG_BYTES}-byte minimum any standard algorithm (HS256) produces. This is consistent with a placeholder or stub signature rather than a real cryptographic one.`,
          whyItMatters:
            'A token signed with a stub or trivially short signature is effectively unsigned — an attacker who knows or guesses the placeholder can forge arbitrary claims, defeating authentication even when the algorithm is not "none".',
          remediation:
            'Sign tokens with a real secret or key using a standard algorithm, and never ship a constant or placeholder signature. Enforce an algorithm allowlist and verify signatures server-side.',
          owasp: 'API2: Broken Authentication',
          evidence: {
            url: res.url,
            status: res.status,
            alg,
            signatureBytes: sigBytes,
            tokenPreview
          },
          suite: 'auth',
          tags: ['auth', 'jwt']
        });
      }
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
          description: `A JWT valid for more than ${JWT_TTL_LIMIT / 3600}h was found in a response. Long-lived access tokens extend the window of opportunity if a token is compromised.`,
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

// Produce a credential that is structurally plausible but definitely not the
// one the server issued: a validating server must reject it, a server that only
// checks for the *presence* of a token will accept it. For a JWT we break the
// signature segment (append a char — also handles the empty alg:none signature,
// so the result always differs from the original); otherwise we mutate the
// opaque value.
function corruptBearer(token: string): string {
  const parts = token.split('.');
  if (parts.length === 3) {
    return `${parts[0]}.${parts[1]}.${parts[2]}x`;
  }
  return `${token}x`;
}

export function authSuite(): Suite {
  return {
    name: 'auth',
    description: 'Checks HTTP auth semantics and basic auth enforcement behavior.',
    async run(ctx): Promise<Finding[]> {
      const { logger } = ctx;
      const findings: Finding[] = [];

      const cap = ctx.config.active.maxRequestsPerSuite;
      const toProbe: SelectedEndpoint[] = ctx.config.auth.probePaths
        .slice(0, cap)
        .map((path) => ({ method: 'get', path }));

      const authConfigured = ctx.config.auth.type !== 'none';

      // Two credential overrides for the enforcement probe. Both win over the
      // HttpClient's injected auth header (the client merges authHeader() first,
      // then per-request headers). `clearedHeaders` simulates no credentials;
      // `invalidHeaders` sends a deliberately invalid one.
      const clearedHeaders: Record<string, string> = {};
      const invalidHeaders: Record<string, string> = {};
      // The invalid credential must use the *same scheme* as the real one, so a
      // server that rejects it does so because the credential is invalid — not
      // because the auth scheme is wrong (which would be a false negative on the
      // exact case invalid_token_accepted is meant to catch).
      if (ctx.config.auth.type === 'bearer') {
        clearedHeaders['authorization'] = '';
        invalidHeaders['authorization'] = `Bearer ${corruptBearer(
          ctx.config.auth.bearerToken ?? 'x'
        )}`;
      }
      if (ctx.config.auth.type === 'basic') {
        clearedHeaders['authorization'] = '';
        const bogus = Buffer.from('sentinel-invalid:sentinel-invalid').toString('base64');
        invalidHeaders['authorization'] = `Basic ${bogus}`;
      }
      if (ctx.config.auth.type === 'apiKey' && ctx.config.auth.apiKeyHeader) {
        clearedHeaders[ctx.config.auth.apiKeyHeader] = '';
        invalidHeaders[ctx.config.auth.apiKeyHeader] = 'sentinel-invalid-key';
      }

      for (const ep of toProbe) {
        logger.debug('Probing auth path', { event: 'auth.probe', probePath: ep });
        const url = new URL(ep.path, ctx.config.target.baseUrl).toString();

        const authedRes = await ctx.http.request({
          method: 'GET',
          path: ep.path
        });

        const jwtResult = inspectJwts(extractJwts(authedRes), authedRes);
        findings.push(...jwtResult);
        logger.debug('JWT Results', { event: 'auth.jwt.inspected', jwtResult });

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

        // Enforcement probe:
        // If auth is configured, compare the protected endpoint's response to a
        // valid credential (authedRes), a deliberately invalid one, and none.
        // This is only meaningful when probePaths are expected to be protected.
        if (authConfigured && (ctx.config.auth.compareUnauthed ?? true)) {
          // HttpClient merges auth headers before per-request headers, so these
          // per-request overrides replace the injected valid credential without
          // needing a second client. Order (invalid, then cleared) is stable for
          // test fixtures that queue mocked responses.
          const invalidRes = await ctx.http.request({
            method: 'GET',
            path: ep.path,
            headers: invalidHeaders
          });
          const unauthedRes = await ctx.http.request({
            method: 'GET',
            path: ep.path,
            headers: clearedHeaders
          });

          findings.push(...inspectJwts(extractJwts(unauthedRes), unauthedRes));

          const is2xx = (s: number) => s >= 200 && s < 300;
          const validOk = is2xx(authedRes.status);
          const invalidOk = is2xx(invalidRes.status);
          const noneOk = is2xx(unauthedRes.status);

          if (validOk && noneOk) {
            // Success with and without any credential — the endpoint enforces no
            // auth at all (or the probe path is genuinely public).
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
                invalidStatus: invalidRes.status,
                unauthedStatus: unauthedRes.status
              },
              suite: 'auth',
              tags: ['auth', 'bypass']
            });
          } else if (validOk && invalidOk) {
            // Rejects the no-credential request but accepts a structurally
            // invalid token — the endpoint checks token presence, not validity.
            // Unlike possible_bypass_probe this is definitive, not heuristic: a
            // genuinely public route would also serve the no-credential request.
            findings.push({
              id: 'auth.invalid_token_accepted',
              title: 'Protected endpoint accepted an invalid token',
              severity: 'high',
              description:
                'The endpoint returned success for a structurally invalid credential while rejecting the request with no credential at all. It appears to check that a token is present but never validates it (e.g. signature or expiry), so any well-formed-looking token is accepted.',
              whyItMatters:
                'An attacker only needs to supply any token-shaped value — not a legitimately issued one — to access a protected endpoint. This is a full authentication bypass with a trivially forgeable credential.',
              remediation:
                'Validate the token server-side (signature, issuer, and expiry) on every protected endpoint rather than checking only for the presence of an Authorization header.',
              owasp: 'API2: Broken Authentication',
              evidence: {
                probeUrl: url,
                validStatus: authedRes.status,
                invalidStatus: invalidRes.status,
                noneStatus: unauthedRes.status
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
