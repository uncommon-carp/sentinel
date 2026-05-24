/**
 * Headers suite
 *
 * Checks:
 * - Presence of baseline HTTP security headers (HSTS, X-Content-Type-Options, Referrer-Policy)
 *
 * Intentionally conservative: flags obviously missing headers rather than validating
 * directive semantics (e.g. CSP parsing). Evidence aggregates affected endpoints so
 * each header produces one finding regardless of how many paths are probed.
 */

import type { Suite, Finding, Severity, AffectedEndpoint } from '../core/types.js';
import { resolveEndpoints } from '../core/endpoints.js';

type HeaderRule = {
  id: `headers.${string}`;
  header: string;
  severity: Severity;
  title: string;
  description: string;
  whyItMatters: string;
  remediation: string;
  owasp: string;
};

const REQUIRED_HEADERS: Array<HeaderRule> = [
  {
    id: 'headers.missing_hsts',
    header: 'strict-transport-security',
    severity: 'medium',
    title: 'Missing Strict-Transport-Security (HSTS)',
    description:
      'HSTS helps enforce HTTPS by telling browsers to only connect over TLS for a period of time.',
    whyItMatters:
      'Without HSTS, browsers may connect over plain HTTP on subsequent visits, enabling downgrade attacks that allow credential and session token interception on the local network.',
    remediation:
      'Add a Strict-Transport-Security header on HTTPS responses (e.g. max-age=31536000; includeSubDomains).',
    owasp: 'API8: Security Misconfiguration'
  },
  {
    id: 'headers.missing_xcto',
    header: 'x-content-type-options',
    severity: 'low',
    title: 'Missing X-Content-Type-Options',
    description: 'X-Content-Type-Options: nosniff helps prevent MIME type sniffing in browsers.',
    whyItMatters:
      'MIME sniffing can cause browsers to interpret non-HTML API responses as executable content, opening the door to content injection attacks in certain browser and integration contexts.',
    remediation: 'Add X-Content-Type-Options: nosniff.',
    owasp: 'API8: Security Misconfiguration'
  },
  {
    id: 'headers.missing_referrer_policy',
    header: 'referrer-policy',
    severity: 'low',
    title: 'Missing Referrer-Policy',
    description:
      'Referrer-Policy controls how much referrer information is sent with requests to other origins.',
    whyItMatters:
      'Without a Referrer-Policy, sensitive data in URL paths — such as tokens, IDs, or search terms — can be silently leaked to third-party domains via the Referer header.',
    remediation:
      'Add a Referrer-Policy header (e.g. no-referrer or strict-origin-when-cross-origin).',
    owasp: 'API8: Security Misconfiguration'
  }
];

export function headersSuite(): Suite {
  return {
    name: 'headers',
    description: 'Checks for baseline HTTP security headers across selected endpoints.',
    async run(ctx): Promise<Finding[]> {
      const findings: Finding[] = [];

      const cap = ctx.config.active.maxRequestsPerSuite;
      const toProbe = resolveEndpoints(ctx.selectedEndpoints).slice(0, cap);

      const missingMap = new Map<string, AffectedEndpoint[]>();

      for (const ep of toProbe) {
        const res = await ctx.http.request({ method: 'GET', path: ep.path });

        for (const rule of REQUIRED_HEADERS) {
          const present = Boolean(res.headers[rule.header]);
          if (!present) {
            const arr = missingMap.get(rule.id) ?? [];
            arr.push({ method: 'get', path: ep.path, url: res.url, status: res.status });
            missingMap.set(rule.id, arr);
          }
        }
      }

      for (const rule of REQUIRED_HEADERS) {
        const affected = missingMap.get(rule.id);
        if (!affected || affected.length === 0) continue;

        findings.push({
          id: rule.id,
          title: rule.title,
          severity: rule.severity,
          description: rule.description,
          whyItMatters: rule.whyItMatters,
          remediation: rule.remediation,
          owasp: rule.owasp,
          suite: 'headers',
          tags: ['headers', 'http'],
          evidence: {
            header: rule.header,
            count: affected.length,
            probed: toProbe.length,
            affected
          }
        });
      }

      return findings;
    }
  };
}
