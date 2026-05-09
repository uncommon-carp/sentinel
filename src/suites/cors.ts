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

export function corsSuite(): Suite {
  return {
    name: 'cors',
    description: 'Performs basic CORS misconfiguration checks on the base endpoint.',
    async run(ctx): Promise<Finding[]> {
      const findings: Finding[] = [];
      const origin = 'https://sentinel.invalid';

      const endpoints = ctx.selectedEndpoints && ctx.selectedEndpoints.length > 0 ? ctx.selectedEndpoints : [{ method: 'get', path: '/' }]

      const cap = Math.max(1, ctx.config.active.maxRequestsPerSuite ?? 20);
      const toProbe = endpoints.slice(0, cap);

      for (const ep of toProbe) {
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
            remediation: 'Do not use wildcard ACAO with credentials. Reflect only trusted origins.',
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
            remediation: 'Validate Origin against an allowlist; avoid reflecting arbitrary origins.',
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
