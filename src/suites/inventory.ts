/**
 * Inventory suite
 *
 * Checks:
 * - Sensitive endpoint exposure: probes debug/admin/doc paths for unexpected 2xx (API9)
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

function extractDeclaredVersion(spec: Record<string, unknown>): string | null {
  const servers = spec.servers as Array<{ url: string }> | undefined;
  if (Array.isArray(servers) && servers.length > 0) {
    const match = servers[0].url.match(/\/(v\d+)/i);
    return match ? match[1] : null;
  }
  const basePath = spec.basePath as string | undefined;
  if (typeof basePath === 'string') {
    const match = basePath.match(/\/(v\d+)/i);
    return match ? match[1] : null;
  }
  return null;
}

function versionNumber(v: string): number {
  const m = v.match(/(\d+)/);
  return m ? parseInt(m[1], 10) : 0;
}

export function inventorySuite(): Suite {
  return {
    name: 'inventory',
    description:
      'Probes common API paths for sensitive endpoint exposure and stale version endpoints.',
    async run(ctx): Promise<Finding[]> {
      const findings: Finding[] = [];
      const cap = Math.max(1, ctx.config.active.maxRequestsPerSuite ?? 20);
      const toProbe = ALL_PROBE_PATHS.slice(0, cap);

      const results: Record<string, ProbedPath> = {};
      for (const probePath of toProbe) {
        const res = await ctx.http.request({ method: 'GET', path: probePath });
        results[probePath] = { path: probePath, status: res.status, url: res.url };
      }

      const exposedSensitive: ProbedPath[] = SENSITIVE_PATHS.filter(
        (p) => p in results && results[p].status >= 200 && results[p].status < 300
      ).map((p) => results[p]);

      if (exposedSensitive.length > 0) {
        findings.push({
          id: 'inventory.sensitive_endpoint_exposed',
          title: 'Sensitive endpoint(s) responding with 2xx',
          severity: 'medium',
          description:
            `${exposedSensitive.length} sensitive path(s) returned a success response. ` +
            'Debug, documentation, and admin endpoints should not be accessible in production.',
          remediation:
            'Disable or restrict access to debug, admin, and API documentation endpoints in ' +
            'production. If public docs are intentional, verify the spec does not expose ' +
            'sensitive implementation details.',
          evidence: { paths: exposedSensitive },
          suite: 'inventory',
          tags: ['inventory', 'api9']
        });
      }

      if (ctx.api) {
        const declaredVersion = extractDeclaredVersion(ctx.api.spec);
        if (declaredVersion) {
          const declaredNum = versionNumber(declaredVersion);
          const stale = VERSION_PATHS.filter((p) => p in results)
            .map((p) => results[p])
            .filter((r) => {
              if (r.status < 200 || r.status >= 300) return false;
              const m = r.path.match(/v(\d+)/i);
              return m ? parseInt(m[1], 10) < declaredNum : false;
            });

          if (stale.length > 0) {
            findings.push({
              id: 'inventory.stale_version_responding',
              title: 'Deprecated API version endpoint is responding',
              severity: 'medium',
              description:
                `The API spec declares ${declaredVersion} as the current version, but ` +
                `${stale.length} older version path(s) are still returning success responses. ` +
                'Stale versions may lack security controls present in the current version ' +
                '(OWASP API9: Improper Inventory Management).',
              remediation:
                'Decommission or block deprecated version endpoints. If parallel versioning is ' +
                'intentional, ensure older versions receive equivalent security updates and are ' +
                'tracked in your API inventory.',
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
