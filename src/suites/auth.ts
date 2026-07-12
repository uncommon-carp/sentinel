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
import { extractBasePath } from '../core/endpoints.js';

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

// BOLA (Broken Object Level Authorization, OWASP API1) probe support.
//
// v1 handles object endpoints keyed by an enumerable (integer) path parameter —
// the common IDOR case and what the Anemone fixture uses. Opaque/UUID ids aren't
// synthesized yet (that needs list-endpoint discovery — future work).
const BOLA_CANDIDATE_IDS = [1, 2, 3, 4, 5];

type ObjectEndpoint = { path: string; paramName: string };

function asParamArray(value: unknown): Array<Record<string, unknown>> {
  return Array.isArray(value) ? (value as Array<Record<string, unknown>>) : [];
}

function pathParamNames(path: string): string[] {
  return [...path.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]!);
}

function pathParamSchemaType(
  operation: Record<string, unknown>,
  pathItem: Record<string, unknown>,
  paramName: string
): string | null {
  // Operation-level params override path-level ones (OpenAPI merge rule).
  for (const p of [
    ...asParamArray(operation['parameters']),
    ...asParamArray(pathItem['parameters'])
  ]) {
    if (p['in'] === 'path' && p['name'] === paramName) {
      const schema = p['schema'] as Record<string, unknown> | undefined;
      return typeof schema?.['type'] === 'string' ? (schema['type'] as string) : null;
    }
  }
  return null;
}

// Object endpoints are GET operations whose path has exactly one `{param}` that
// is declared `in: path` with an integer/number schema — i.e. a single
// enumerable resource id we can synthesize candidate values for.
function discoverObjectEndpoints(spec: Record<string, unknown>): ObjectEndpoint[] {
  const paths = spec.paths as Record<string, unknown> | undefined;
  if (!paths || typeof paths !== 'object') return [];
  const out: ObjectEndpoint[] = [];
  for (const [path, pathItemRaw] of Object.entries(paths)) {
    const pathItem = pathItemRaw as Record<string, unknown> | undefined;
    if (!pathItem) continue;
    const operation = pathItem['get'] as Record<string, unknown> | undefined;
    if (!operation) continue;
    const params = pathParamNames(path);
    if (params.length !== 1) continue;
    const paramName = params[0]!;
    const type = pathParamSchemaType(operation, pathItem, paramName);
    if (type !== 'integer' && type !== 'number') continue;
    out.push({ path, paramName });
  }
  return out;
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

      // The primary identity (identities[0]) is the one ctx.http authenticates as.
      const primary = ctx.config.auth.identities[0];
      const authConfigured = (primary?.type ?? 'none') !== 'none';

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
      if (primary?.type === 'bearer') {
        clearedHeaders['authorization'] = '';
        invalidHeaders['authorization'] = `Bearer ${corruptBearer(primary.bearerToken ?? 'x')}`;
      }
      if (primary?.type === 'basic') {
        clearedHeaders['authorization'] = '';
        const bogus = Buffer.from('sentinel-invalid:sentinel-invalid').toString('base64');
        invalidHeaders['authorization'] = `Basic ${bogus}`;
      }
      if (primary?.type === 'apiKey' && primary.apiKeyHeader) {
        clearedHeaders[primary.apiKeyHeader] = '';
        invalidHeaders[primary.apiKeyHeader] = 'sentinel-invalid-key';
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

      // BOLA probe (OWASP API1). Requires an OpenAPI spec to discover object
      // endpoints and at least two configured identities (Tier-2) to compare.
      // GET-only and non-mutating, so it runs whenever both are present — no
      // separate opt-in beyond the user configuring a second identity.
      const identities = ctx.identities ?? [];
      if (ctx.api && identities.length >= 2) {
        const basePath = extractBasePath(ctx.api);
        const objectEndpoints = discoverObjectEndpoints(ctx.api.spec);

        const accesses: Array<{
          endpoint: string;
          resourceId: number;
          identities: string[];
          statuses: Record<string, number>;
          unauthStatus: number;
          bodiesMatch: boolean;
        }> = [];

        // Bound total work by the per-suite request cap. Each probe unit (one
        // candidate id) fires a request per identity plus the unauthenticated
        // guard, so charge that real cost against the cap rather than one-per-id
        // — otherwise this section alone burns (identities + 1)× the cap. Only
        // start a unit we can fully afford. One confirmed access per endpoint is
        // enough to flag it, so stop sweeping an endpoint's remaining ids once
        // it's confirmed and spend the leftover budget on other endpoints.
        const requestsPerUnit = identities.length + 1;
        let budget = cap;
        for (const ep of objectEndpoints) {
          if (budget < requestsPerUnit) break;
          for (const id of BOLA_CANDIDATE_IDS) {
            if (budget < requestsPerUnit) break;
            budget -= requestsPerUnit;

            const requestPath = `${basePath}${ep.path.replace(`{${ep.paramName}}`, String(id))}`;
            const endpointLabel = `GET ${requestPath}`;
            logger.debug('BOLA probe', {
              event: 'auth.bola.probe',
              endpoint: endpointLabel,
              resourceId: id
            });

            const perIdentity: { name: string; status: number; bodyText: string }[] = [];
            for (const identity of identities) {
              const res = await identity.http.request({ method: 'GET', path: requestPath });
              perIdentity.push({ name: identity.name, status: res.status, bodyText: res.bodyText });
            }

            // Unauthenticated guard: an object the endpoint serves with no
            // credential at all is public (or a full auth bypass, already covered
            // by possible_bypass_probe) — not an object-level authorization gap.
            // Reuse `clearedHeaders` from the enforcement probe so the credential
            // is stripped for the primary identity's *actual* scheme — an
            // apiKey-in-custom-header identity isn't left carrying valid auth,
            // which would silently read as "public" and suppress a real finding.
            const unauthRes = await identities[0]!.http.request({
              method: 'GET',
              path: requestPath,
              headers: clearedHeaders
            });
            if (unauthRes.status >= 200 && unauthRes.status < 300) continue;

            // Group the 2xx responses by body. A body returned to two or more
            // distinct identities is the same object served across identities —
            // the BOLA signal (identity B received the record identity A did).
            const byBody = new Map<string, Set<string>>();
            for (const r of perIdentity) {
              if (r.status < 200 || r.status >= 300) continue;
              if (!byBody.has(r.bodyText)) byBody.set(r.bodyText, new Set());
              byBody.get(r.bodyText)!.add(r.name);
            }
            const shared = [...byBody.values()].find((names) => names.size >= 2);
            if (shared) {
              const statuses: Record<string, number> = {};
              for (const r of perIdentity) statuses[r.name] = r.status;
              accesses.push({
                endpoint: endpointLabel,
                resourceId: id,
                identities: [...shared],
                statuses,
                unauthStatus: unauthRes.status,
                bodiesMatch: true
              });
              break; // endpoint confirmed — move to the next one
            }
          }
        }

        if (accesses.length > 0) {
          findings.push({
            id: 'auth.bola_object_access',
            title: 'Object-level endpoint served the same resource to multiple identities',
            severity: 'high',
            description:
              `${accesses.length} object access(es) returned a byte-identical resource to two or ` +
              'more distinct authenticated identities while rejecting the unauthenticated request. ' +
              'The endpoint authenticates the caller but does not verify that the caller is ' +
              'authorized for the specific object, so any authenticated identity can read another ' +
              "identity's records by enumerating the resource id (BOLA / IDOR).",
            whyItMatters:
              'Broken object-level authorization is the most common and impactful API vulnerability ' +
              '(OWASP API1): an attacker with any valid account can enumerate object ids and read or ' +
              "modify other users' data because the endpoint never checks ownership.",
            remediation:
              'Enforce object-level authorization on every request — verify the authenticated ' +
              'identity may access the specific object before returning it, not just that the caller ' +
              'is authenticated. Use non-enumerable identifiers as defense-in-depth.',
            owasp: 'API1: Broken Object Level Authorization',
            // Evidence deliberately omits response bodies: the leaked records
            // carry sensitive fields (emails, API keys) — the very data the
            // finding is about. Statuses and identity names are enough to act on.
            evidence: { accesses },
            suite: 'auth',
            tags: ['auth', 'bola', 'api1']
          });
        }
      }

      return findings;
    }
  };
}
