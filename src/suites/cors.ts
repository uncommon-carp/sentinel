/**
 * CORS suite
 *
 * Sends a GET with a synthetic Origin header and checks for:
 * - Wildcard ACAO combined with credentials
 * - Reflected Origin (overly permissive ACAO)
 *
 * Heuristic — flags dangerous patterns without full browser CORS simulation.
 */

import type { Suite, Finding } from '../core/types.js';
import { resolveEndpoints } from '../core/endpoints.js';

export function corsSuite(): Suite {
  return {
    name: 'cors',
    description: 'Performs basic CORS misconfiguration checks on the base endpoint.',
    async run(ctx): Promise<Finding[]> {
      const { logger } = ctx;
      const findings: Finding[] = [];
      const origin = 'https://sentinel.invalid';

      const cap = ctx.config.active.maxRequestsPerSuite;
      const toProbe = resolveEndpoints(ctx.selectedEndpoints).slice(0, cap);

      for (const ep of toProbe) {
        logger.debug('Probing CORS endpoint', { event: 'cors.probe', probePath: ep });
        const res = await ctx.http.request({
          method: 'GET',
          path: ep.path,
          headers: { origin }
        });

        const acao = res.headers['access-control-allow-origin'];
        const acc = res.headers['access-control-allow-credentials'];

        if (acao === '*' && acc === 'true') {
          findings.push({
            id: 'cors.wildcard_with_credentials',
            title: 'CORS allows credentials with wildcard origin',
            severity: 'high',
            description:
              "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is 'true'.",
            whyItMatters:
              'Any website can make credentialed cross-origin requests to this API on behalf of a logged-in user. This enables cross-site attacks that bypass same-origin protections at the browser level.',
            remediation: 'Do not use wildcard ACAO with credentials. Reflect only trusted origins.',
            owasp: 'API8: Security Misconfiguration',
            evidence: { url: res.url, acao, acc },
            suite: 'cors',
            tags: ['cors']
          });
        }

        if (acao === origin) {
          findings.push({
            id: 'cors.origin_reflection',
            title: 'CORS reflects arbitrary Origin',
            severity: 'medium',
            description: 'Server reflected the Origin header value in Access-Control-Allow-Origin.',
            whyItMatters:
              'Reflecting arbitrary origins grants any domain CORS access. Combined with user credentials, this allows malicious sites to make authenticated API calls on behalf of a victim without their knowledge.',
            remediation:
              'Validate Origin against an allowlist; avoid reflecting arbitrary origins.',
            owasp: 'API8: Security Misconfiguration',
            evidence: { url: res.url, origin, acao },
            suite: 'cors',
            tags: ['cors']
          });
        }
      }

      return findings;
    }
  };
}
