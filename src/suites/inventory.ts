/**
 * Inventory suite
 *
 * Checks:
 * - Sensitive endpoint exposure: probes debug/admin/doc paths for unexpected 2xx (API9)
 * - GraphQL introspection: POSTs a minimal introspection query to /graphql; flags if
 *   introspection data is returned (API9 / hardening)
 * - Stale API version: if an OpenAPI spec is loaded with a declared base version, checks
 *   whether older version prefixes (/v1/, /api/v1/) are still responding (API9)
 * - SSRF surface: if an OpenAPI spec is loaded, finds parameters that accept a URL and
 *   confirms the server takes an external URL without a validation signal (API7). GET
 *   query params only by default; `inventory.ssrfActiveProbe` opts into probing
 *   POST/PUT/PATCH and body params (active, may create/mutate resources on the target).
 * - Excessive data exposure: if an OpenAPI spec is loaded, finds GET operations whose
 *   declared 200 response schema names a sensitive-looking field (apiKey, password,
 *   secret, token, ssn, internal, role, isAdmin, or `format: password`) and confirms
 *   the field is actually present and non-null in a live read (API3)
 *
 * Multiple paths triggering the same class of issue are collapsed into one finding.
 *
 * Maps primarily to OWASP API9: Improper Inventory Management (the SSRF surface check
 * maps to API7, excessive data exposure maps to API3 — one suite can emit findings
 * across OWASP categories).
 */

import type { Suite, Finding } from '../core/types.js';
import { extractBasePath } from '../core/endpoints.js';

type ProbedPath = { path: string; status: number; url: string };

const SENSITIVE_PATHS = [
  '/swagger',
  '/openapi.json',
  '/api-docs',
  '/graphql',
  '/debug',
  '/actuator',
  '/metrics'
];

const VERSION_PATHS = ['/v1/', '/api/v1/'];

const ALL_PROBE_PATHS = [...SENSITIVE_PATHS, ...VERSION_PATHS];

const GRAPHQL_PATH = '/graphql';
const INTROSPECTION_BODY = JSON.stringify({ query: '{ __schema { queryType { name } } }' });

// SSRF surface detection (API7). We probe query parameters that look like they
// accept a URL with a benign, non-resolving probe (the ".invalid" TLD never
// resolves, so even a target that fetches it reaches nothing) and flag those the
// server accepts without a validation/rejection signal.
const SSRF_PROBE_URL = 'http://ssrf-probe.sentinel.invalid/';
const SSRF_PROBE_HOST = 'ssrf-probe.sentinel.invalid';
const URL_PARAM_NAMES = new Set([
  'callback',
  'webhook',
  'redirect',
  'redirect_uri',
  'feed',
  'proxy',
  'dest',
  'destination',
  'fetch'
]);
const URL_SCHEMA_FORMATS = new Set(['uri', 'url']);
// Note: kept free of substrings that appear in SSRF_PROBE_URL (e.g. "ssrf"),
// so a server reflecting the probe URL isn't mistaken for a rejection.
const REJECTION_PATTERNS = ['not allowed', 'disallowed', 'invalid url', 'blocked', 'forbidden'];

// Methods probed when inventory.ssrfActiveProbe is on. DELETE is excluded — it
// almost never carries a URL-to-fetch param and is purely destructive.
const ACTIVE_METHODS = ['get', 'post', 'put', 'patch'];

type UrlParam = { path: string; method: string; name: string; paramType: 'query' | 'body' };

function isUrlLikeParam(param: Record<string, unknown>): boolean {
  const name = typeof param['name'] === 'string' ? param['name'].toLowerCase() : '';
  if (!name) return false;
  if (name.includes('url') || name.includes('uri')) return true;
  if (URL_PARAM_NAMES.has(name)) return true;
  const schema = param['schema'] as Record<string, unknown> | undefined;
  const format = typeof schema?.['format'] === 'string' ? schema['format'].toLowerCase() : '';
  return URL_SCHEMA_FORMATS.has(format);
}

function asParamArray(value: unknown): Array<Record<string, unknown>> {
  return Array.isArray(value) ? (value as Array<Record<string, unknown>>) : [];
}

// URL-accepting JSON body fields declared on an operation's requestBody.
function collectBodyFields(operation: Record<string, unknown>): string[] {
  const requestBody = operation['requestBody'] as Record<string, unknown> | undefined;
  const content = requestBody?.['content'] as Record<string, unknown> | undefined;
  const json = content?.['application/json'] as Record<string, unknown> | undefined;
  const schema = json?.['schema'] as Record<string, unknown> | undefined;
  const properties = schema?.['properties'];
  if (!properties || typeof properties !== 'object') return [];
  return Object.entries(properties as Record<string, unknown>)
    .filter(([name, propSchema]) => isUrlLikeParam({ name, schema: propSchema }))
    .map(([name]) => name);
}

// Collect URL-accepting parameters to probe.
//
// Default (activeProbe=false): GET query params only. This check lives in the
// always-on inventory suite, which must not send state-changing requests to the
// target, and GET is the only method whose response body we can inspect for a
// validation signal.
//
// activeProbe=true: also probe POST/PUT/PATCH and JSON body params — the common
// real-world SSRF vector (webhook registration, resource create/update that
// fetches a supplied URL). Opt-in because these requests may create or mutate
// resources on the target.
//
// Query params declared at the path-item level (a valid OpenAPI pattern applying
// to every operation on the path) are merged in; non-verb path-item keys
// (summary, description, path-level `parameters`) are not treated as operations.
function collectUrlParams(spec: Record<string, unknown>, activeProbe: boolean): UrlParam[] {
  const paths = spec.paths as Record<string, unknown> | undefined;
  if (!paths || typeof paths !== 'object') return [];
  const methods = activeProbe ? ACTIVE_METHODS : ['get'];
  const out: UrlParam[] = [];
  for (const [path, pathItemRaw] of Object.entries(paths)) {
    const pathItem = pathItemRaw as Record<string, unknown> | undefined;
    if (!pathItem) continue;
    const pathLevelParams = asParamArray(pathItem['parameters']);

    for (const method of methods) {
      const operation = pathItem[method] as Record<string, unknown> | undefined;
      if (!operation) continue;

      // Query params: operation-level first so they win the per-name dedup over
      // any same-named path-level param (OpenAPI operation params override path
      // params).
      const merged = [...asParamArray(operation['parameters']), ...pathLevelParams];
      const seen = new Set<string>();
      for (const p of merged) {
        const name = typeof p['name'] === 'string' ? p['name'] : '';
        if (!name || seen.has(name)) continue;
        seen.add(name);
        if (p['in'] === 'query' && isUrlLikeParam(p)) {
          out.push({ path, method, name, paramType: 'query' });
        }
      }

      // Body params (active probe only — GET has no request body).
      if (activeProbe) {
        for (const name of collectBodyFields(operation)) {
          out.push({ path, method, name, paramType: 'body' });
        }
      }
    }
  }
  return out;
}

function extractDeclaredVersion(spec: Record<string, unknown>): string | null {
  const servers = spec.servers as Array<{ url: string }> | undefined;
  if (Array.isArray(servers) && servers.length > 0) {
    const first = servers[0];
    if (first) {
      return first.url.match(/\/(v\d+)/i)?.[1] ?? null;
    }
  }
  const basePath = spec.basePath as string | undefined;
  if (typeof basePath === 'string') {
    return basePath.match(/\/(v\d+)/i)?.[1] ?? null;
  }
  return null;
}

function versionNumber(v: string): number {
  const m = v.match(/(\d+)/);
  return m ? parseInt(m[1] ?? '0', 10) : 0;
}

// Excessive data exposure (API3). We walk each GET operation's declared 200
// response schema — the same tree-walk shape collectUrlParams/collectBodyFields
// use for request params, applied to responses instead — for property names
// that look sensitive, then confirm with a live read that the field is
// actually present and non-null. A schema match alone isn't sufficient: a
// documented-but-unused response property would otherwise false-positive.
const SENSITIVE_FIELD_PATTERNS = [
  'apikey',
  'password',
  'secret',
  'token',
  'ssn',
  'internal',
  'role',
  'isadmin'
];

// Same precedent as auth.ts's BOLA_CANDIDATE_IDS: v1 only handles object
// endpoints keyed by a single enumerable (integer) path parameter. Opaque/UUID
// ids aren't synthesized yet.
const DATA_EXPOSURE_CANDIDATE_IDS = [1, 2, 3, 4, 5];

type DataExposureEndpoint = {
  path: string;
  paramName: string | null;
  sensitiveFields: string[];
};

function isSensitiveField(name: string, schema: Record<string, unknown> | undefined): boolean {
  const lower = name.toLowerCase();
  if (SENSITIVE_FIELD_PATTERNS.some((p) => lower.includes(p))) return true;
  const format = typeof schema?.['format'] === 'string' ? schema['format'].toLowerCase() : '';
  return format === 'password';
}

// Sensitive-looking property names declared on a GET operation's 200 JSON
// response schema.
function collectSensitiveResponseFields(operation: Record<string, unknown>): string[] {
  const responses = operation['responses'] as Record<string, unknown> | undefined;
  const ok = responses?.['200'] as Record<string, unknown> | undefined;
  const content = ok?.['content'] as Record<string, unknown> | undefined;
  const json = content?.['application/json'] as Record<string, unknown> | undefined;
  const schema = json?.['schema'] as Record<string, unknown> | undefined;
  const properties = schema?.['properties'];
  if (!properties || typeof properties !== 'object') return [];
  return Object.entries(properties as Record<string, unknown>)
    .filter(([name, propSchema]) =>
      isSensitiveField(name, propSchema as Record<string, unknown> | undefined)
    )
    .map(([name]) => name);
}

function pathParamNames(path: string): string[] {
  return [...path.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]!);
}

function pathParamSchemaType(
  operation: Record<string, unknown>,
  pathItem: Record<string, unknown>,
  paramName: string
): string | null {
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

// GET operations whose declared 200 response includes at least one
// sensitive-looking field, restricted to paths with zero or one path
// parameter — more than one is too speculative to synthesize candidate
// values for (same precedent as auth.ts's discoverObjectEndpoints), and a
// non-integer single param can't be synthesized either.
function discoverDataExposureEndpoints(spec: Record<string, unknown>): DataExposureEndpoint[] {
  const paths = spec.paths as Record<string, unknown> | undefined;
  if (!paths || typeof paths !== 'object') return [];
  const out: DataExposureEndpoint[] = [];
  for (const [path, pathItemRaw] of Object.entries(paths)) {
    const pathItem = pathItemRaw as Record<string, unknown> | undefined;
    if (!pathItem) continue;
    const operation = pathItem['get'] as Record<string, unknown> | undefined;
    if (!operation) continue;
    const sensitiveFields = collectSensitiveResponseFields(operation);
    if (sensitiveFields.length === 0) continue;
    const params = pathParamNames(path);
    if (params.length > 1) continue;
    let paramName: string | null = null;
    if (params.length === 1) {
      const type = pathParamSchemaType(operation, pathItem, params[0]!);
      if (type !== 'integer' && type !== 'number') continue;
      paramName = params[0]!;
    }
    out.push({ path, paramName, sensitiveFields });
  }
  return out;
}

export function inventorySuite(): Suite {
  return {
    name: 'inventory',
    description:
      'Probes common API paths for sensitive endpoint exposure and stale version endpoints.',
    async run(ctx): Promise<Finding[]> {
      const { logger } = ctx;
      const findings: Finding[] = [];
      const cap = ctx.config.active.maxRequestsPerSuite;
      const toProbe = ALL_PROBE_PATHS.slice(0, cap);

      const results: Record<string, ProbedPath> = {};
      for (const probePath of toProbe) {
        logger.debug('Inventory probe', { event: 'inventory.probe', endpoint: probePath });
        const res = await ctx.http.request({ method: 'GET', path: probePath });
        results[probePath] = { path: probePath, status: res.status, url: res.url };
      }

      const exposedSensitive: ProbedPath[] = SENSITIVE_PATHS.flatMap((p) => {
        const r = results[p];
        return r && r.status >= 200 && r.status < 300 ? [r] : [];
      });

      if (exposedSensitive.length > 0) {
        findings.push({
          id: 'inventory.sensitive_endpoint_exposed',
          title: 'Sensitive endpoint(s) responding with 2xx',
          severity: 'medium',
          description:
            `${exposedSensitive.length} sensitive path(s) returned a success response. ` +
            'Debug, documentation, and admin endpoints should not be accessible in production.',
          whyItMatters:
            'Debug, admin, and documentation endpoints reveal internal API structure, routes, and implementation details that attackers use to map attack surface and identify exploitable paths.',
          remediation:
            'Disable or restrict access to debug, admin, and API documentation endpoints in ' +
            'production. If public docs are intentional, verify the spec does not expose ' +
            'sensitive implementation details.',
          owasp: 'API9: Improper Inventory Management',
          evidence: { paths: exposedSensitive },
          suite: 'inventory',
          tags: ['inventory', 'api9']
        });
      }

      const gqlRes = await ctx.http.request({
        method: 'POST',
        path: GRAPHQL_PATH,
        headers: { 'content-type': 'application/json' },
        body: INTROSPECTION_BODY
      });

      try {
        const gqlBody = JSON.parse(gqlRes.bodyText) as Record<string, unknown>;
        const schema = (gqlBody?.data as Record<string, unknown> | undefined)?.__schema;
        if (gqlRes.status >= 200 && gqlRes.status < 300 && schema != null) {
          findings.push({
            id: 'inventory.graphql_introspection_enabled',
            title: 'GraphQL introspection is enabled',
            severity: 'low',
            description:
              'The GraphQL endpoint responded to an introspection query and returned schema ' +
              'data. In production, introspection exposes the full API type system to ' +
              'unauthenticated clients, giving attackers a detailed roadmap of available ' +
              'queries, mutations, and types.',
            whyItMatters:
              'Introspection gives attackers a complete, machine-readable map of every query, mutation, type, and field — significantly accelerating reconnaissance and reducing the cost of finding injection points.',
            remediation:
              'Disable introspection in production. Most GraphQL servers have a dedicated ' +
              'option for this (e.g. introspection: false in Apollo Server). Expose schema ' +
              'documentation through controlled channels instead.',
            owasp: 'API9: Improper Inventory Management',
            evidence: { url: gqlRes.url, status: gqlRes.status },
            suite: 'inventory',
            tags: ['inventory', 'graphql', 'api9']
          });
        }
      } catch {
        // Non-JSON response — not a GraphQL introspection result
      }

      if (ctx.api) {
        const declaredVersion = extractDeclaredVersion(ctx.api.spec);
        if (declaredVersion) {
          const declaredNum = versionNumber(declaredVersion);
          const stale = VERSION_PATHS.flatMap((p) => {
            const r = results[p];
            if (!r || r.status < 200 || r.status >= 300) return [];
            const m = r.path.match(/v(\d+)/i);
            return m && parseInt(m[1] ?? '0', 10) < declaredNum ? [r] : [];
          });

          if (stale.length > 0) {
            findings.push({
              id: 'inventory.stale_version_responding',
              title: 'Deprecated API version endpoint is responding',
              severity: 'medium',
              description:
                `The API spec declares ${declaredVersion} as the current version, but ` +
                `${stale.length} older version path(s) are still returning success responses. ` +
                'Stale versions may lack security controls present in the current version.',
              whyItMatters:
                'Old API versions often miss security patches and hardening applied to the current version. They represent untracked attack surface that can bypass newer controls entirely.',
              remediation:
                'Decommission or block deprecated version endpoints. If parallel versioning is ' +
                'intentional, ensure older versions receive equivalent security updates and are ' +
                'tracked in your API inventory.',
              owasp: 'API9: Improper Inventory Management',
              evidence: {
                declaredVersion,
                stale: stale.map((r) => ({ path: r.path, status: r.status, url: r.url }))
              },
              suite: 'inventory',
              tags: ['inventory', 'api9']
            });
          }
        }
      }

      if (ctx.api) {
        const basePath = extractBasePath(ctx.api);
        const urlParams = collectUrlParams(
          ctx.api.spec,
          ctx.config.inventory.ssrfActiveProbe
        ).slice(0, cap);
        const accepted: Array<{
          endpoint: string;
          method: string;
          parameter: string;
          paramType: 'query' | 'body';
          status: number;
          reflected: boolean;
        }> = [];

        for (const p of urlParams) {
          const method = p.method.toUpperCase();
          const endpoint = `${method} ${basePath}${p.path}`;
          logger.debug('SSRF surface probe', {
            event: 'inventory.ssrf.probe',
            endpoint,
            parameter: p.name,
            paramType: p.paramType
          });

          // Probe with the parameter's own method and location so the request
          // always matches the logged/evidenced endpoint rather than silently
          // diverging from it.
          let res;
          if (p.paramType === 'body') {
            res = await ctx.http.request({
              method,
              path: `${basePath}${p.path}`,
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ [p.name]: SSRF_PROBE_URL })
            });
          } else {
            const qs = new URLSearchParams({ [p.name]: SSRF_PROBE_URL });
            res = await ctx.http.request({ method, path: `${basePath}${p.path}?${qs}` });
          }

          const ok = res.status >= 200 && res.status < 300;
          const bodyLower = res.bodyText.toLowerCase();
          const rejected = REJECTION_PATTERNS.some((r) => bodyLower.includes(r));
          if (ok && !rejected) {
            accepted.push({
              endpoint,
              method,
              parameter: p.name,
              paramType: p.paramType,
              status: res.status,
              reflected: res.bodyText.includes(SSRF_PROBE_HOST)
            });
          }
        }

        if (accepted.length > 0) {
          findings.push({
            id: 'inventory.ssrf_surface',
            title: 'Parameter(s) accept an external URL without validation',
            severity: 'medium',
            description:
              `${accepted.length} parameter(s) accepted an external URL probe without a ` +
              'validation or rejection signal. An endpoint that fetches a user-supplied URL can ' +
              'be steered at internal-only services, cloud metadata endpoints, or other hosts the ' +
              'API can reach but the caller should not — the core SSRF condition.',
            whyItMatters:
              'Server-side request forgery lets an attacker pivot from the public API into the ' +
              'internal network: reaching admin services, databases, or cloud metadata endpoints ' +
              '(e.g. 169.254.169.254) that are otherwise unreachable from outside.',
            remediation:
              'Validate and allowlist outbound URL destinations, reject internal and link-local ' +
              'address ranges, and avoid fetching user-supplied URLs directly. Where a fetch is ' +
              'required, resolve and check the target host before connecting.',
            owasp: 'API7: Server Side Request Forgery',
            evidence: { probeUrl: SSRF_PROBE_URL, parameters: accepted },
            suite: 'inventory',
            tags: ['inventory', 'ssrf', 'api7']
          });
        }
      }

      if (ctx.api) {
        const basePath = extractBasePath(ctx.api);
        const dataExposureEndpoints = discoverDataExposureEndpoints(ctx.api.spec);
        const flagged: Array<{ endpoint: string; fields: string[] }> = [];

        // Same budget-against-cap discipline as the BOLA probe: an endpoint
        // keyed by a synthesized id may need several attempts to land a 2xx,
        // so charge the worst case (one request per candidate id) against the
        // shared cap rather than one-per-endpoint.
        let budget = cap;
        for (const ep of dataExposureEndpoints) {
          if (budget < 1) break;
          const candidates = ep.paramName === null ? [null] : DATA_EXPOSURE_CANDIDATE_IDS;
          for (const id of candidates) {
            if (budget < 1) break;
            budget -= 1;

            const concretePath =
              ep.paramName === null || id === null
                ? ep.path
                : ep.path.replace(`{${ep.paramName}}`, String(id));
            const requestPath = `${basePath}${concretePath}`;
            logger.debug('Excessive data exposure probe', {
              event: 'inventory.data_exposure.probe',
              endpoint: `GET ${requestPath}`
            });

            const res = await ctx.http.request({ method: 'GET', path: requestPath });
            if (res.status < 200 || res.status >= 300) continue;

            let body: unknown;
            try {
              body = JSON.parse(res.bodyText);
            } catch {
              break; // not JSON — no schema field to confirm; other ids won't match either
            }
            if (typeof body !== 'object' || body === null) break;

            const present = ep.sensitiveFields.filter((f) => {
              const v = (body as Record<string, unknown>)[f];
              return v !== undefined && v !== null;
            });
            if (present.length > 0) {
              flagged.push({ endpoint: `GET ${basePath}${ep.path}`, fields: present });
            }
            break; // got a live 2xx read for this endpoint — done regardless of match
          }
        }

        if (flagged.length > 0) {
          findings.push({
            id: 'inventory.excessive_data_exposure',
            title: 'Response includes sensitive fields beyond what the client needs',
            severity: 'medium',
            description:
              `${flagged.length} endpoint(s) returned a live response containing a field ` +
              'declared sensitive by name (e.g. apiKey, password, secret, token, ssn, internal, ' +
              'role, isAdmin) or by OpenAPI format (password). The endpoint relies on the client ' +
              'to discard fields it does not need rather than omitting them server-side.',
            whyItMatters:
              'Serving more data than a client needs — credentials, internal flags, other ' +
              "users' identifiers — means every consumer of the API becomes a place that sensitive " +
              'data can leak from: logs, browser dev tools, a compromised client, or a caller that ' +
              'was never meant to see the field at all.',
            remediation:
              'Return only the fields a given endpoint or caller actually needs. Use per-endpoint ' +
              'response models (not a shared internal object) and strip credentials, secrets, and ' +
              'internal-only fields before serialization — never rely on the client to ignore them.',
            owasp: 'API3: Broken Object Property Level Authorization',
            // Evidence names the leaked fields, not their values — the values
            // are the sensitive data the finding is about.
            evidence: { endpoints: flagged },
            suite: 'inventory',
            tags: ['inventory', 'data-exposure', 'api3']
          });
        }
      }

      return findings;
    }
  };
}
