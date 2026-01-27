/**
 * Headers suite
 *
 * What it checks:
 * - Presence of common HTTP security headers (e.g. HSTS, CSP, XCTO, Referrer-Policy)
 *
 * How it checks:
 * - Passive: performs a simple GET to a baseline path (currently "/") and inspects headers
 *
 * Output:
 * - Missing/weak headers are reported as findings with stable IDs (headers.missing_*)
 * - Evidence includes URL and status (and can be extended with header values as needed)
 *
 * Notes:
 * - This suite is intentionally conservative: it checks for “obviously missing” signals,
 *   not full semantic validation of directives (e.g. CSP parsing) — that can be added later.
 */

import type { Suite, Finding, Severity } from "../core/types.js";

type HeaderRule = {
  id: `headers.${string}`
  header: string;
  severity: Severity
  title: string;
  description: string;
  remediation: string;
}

const REQUIRED_HEADERS: Array<HeaderRule> = [
  {
    id: "headers.missing_hsts",
    header: "strict-transport-security",
    severity: "medium",
    title: "Missing Strict-Transport-Security (HSTS)",
    description:
      "HSTS helps enforce HTTPS by telling browsers to only connect over TLS for a period of time.",
    remediation:
      "Add a Strict-Transport-Security header on HTTPS responses (e.g. max-age=31536000; includeSubDomains)."
  },
  {
    id: "headers.missing_xcto",
    header: "x-content-type-options",
    severity: "low",
    title: "Missing X-Content-Type-Options",
    description:
      "X-Content-Type-Options: nosniff helps prevent MIME type sniffing in browsers.",
    remediation: "Add X-Content-Type-Options: nosniff."
  },
  {
    id: "headers.missing_referrer_policy",
    header: "referrer-policy",
    severity: "low",
    title: "Missing Referrer-Policy",
    description:
      "Referrer-Policy controls how much referrer information is sent with requests to other origins.",
    remediation:
      "Add a Referrer-Policy header (e.g. no-referrer or strict-origin-when-cross-origin)."
  }
  // Add CSP etc later if you want, but CSP validation is nuanced.
];

type Affected = { method: string; path: string; url: string; status: number };

export function headersSuite(): Suite {
  return {
    name: "headers",
    description: "Checks for baseline HTTP security headers across selected endpoints.",
    async run(ctx): Promise<Finding[]> {
      const findings: Finding[] = [];

      const endpoints =
        ctx.selectedEndpoints && ctx.selectedEndpoints.length > 0
          ? ctx.selectedEndpoints
          : [{ method: "get", path: "/" }];

      // Budget: keep request volume predictable in CI.
      const cap = Math.max(1, ctx.config.active.maxRequestsPerSuite ?? 20);
      const toProbe = endpoints.slice(0, cap);

      // Collect missing headers → affected endpoints
      const missingMap = new Map<string, Affected[]>();

      for (const ep of toProbe) {
        // Use GET for now (safe + consistent). HEAD support varies.
        const res = await ctx.http.request({ method: "GET", path: ep.path });

        for (const rule of REQUIRED_HEADERS) {
          const present = Boolean(res.headers[rule.header]);
          if (!present) {
            const arr = missingMap.get(rule.id) ?? [];
            arr.push({ method: "get", path: ep.path, url: res.url, status: res.status });
            missingMap.set(rule.id, arr);
          }
        }
      }

      // Emit one finding per missing header with list of affected endpoints
      for (const rule of REQUIRED_HEADERS) {
        const affected = missingMap.get(rule.id);
        if (!affected || affected.length === 0) continue;

        findings.push({
          id: rule.id,
          title: rule.title,
          severity: rule.severity,
          description: rule.description,
          remediation: rule.remediation,
          suite: "headers",
          tags: ["headers", "http"],
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

