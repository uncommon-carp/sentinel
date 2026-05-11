/**
 * Inventory suite
 *
 * Checks:
 * - Sensitive endpoint exposure: probes debug/admin/doc paths for unexpected 2xx (API9)
 * - GraphQL introspection: POSTs a minimal introspection query to /graphql; flags if
 *   introspection data is returned (API9 / hardening)
 * - Stale API version: if an OpenAPI spec is loaded with a declared base version, checks
 *   whether older version prefixes (/v1/, /api/v1/) are still responding (API9)
 *
 * Multiple paths triggering the same class of issue are collapsed into one finding.
 *
 * Maps to OWASP API9: Improper Inventory Management.
 */

import type { Suite, Finding } from '../core/types.js';

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

const ALL_PROBE_PATHS = [...SENSITIVE_PATHS, ...VERSION_PATHS, '/health'];

const GRAPHQL_PATH = '/graphql';
const INTROSPECTION_BODY = JSON.stringify({ query: '{ __schema { queryType { name } } }' });

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

export function inventorySuite(): Suite {
  return {
    name: 'inventory',
    description:
      'Probes common API paths for sensitive endpoint exposure and stale version endpoints.',
    async run(ctx): Promise<Finding[]> {
      const findings: Finding[] = [];
      const cap = ctx.config.active.maxRequestsPerSuite;
      const toProbe = ALL_PROBE_PATHS.slice(0, cap);

      const results: Record<string, ProbedPath> = {};
      for (const probePath of toProbe) {
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

      return findings;
    }
  };
}
