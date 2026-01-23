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

import type { Suite, Finding } from "../core/types.js";

export function headersSuite(): Suite {
  return {
    name: "headers",
    description: "Checks for common HTTP security headers on the base endpoint.",
    async run(ctx): Promise<Finding[]> {
      const res = await ctx.http.request({ method: "GET", path: "/" });
      const findings: Finding[] = [];

      const required = [
        { key: "strict-transport-security", id: "headers.missing_hsts", sev: "medium" as const, title: "Missing HSTS" },
        { key: "x-content-type-options", id: "headers.missing_xcto", sev: "low" as const, title: "Missing X-Content-Type-Options" },
        { key: "content-security-policy", id: "headers.missing_csp", sev: "low" as const, title: "Missing Content-Security-Policy" },
        { key: "referrer-policy", id: "headers.missing_referrer_policy", sev: "info" as const, title: "Missing Referrer-Policy" }
      ];

      for (const r of required) {
        if (!res.headers[r.key]) {
          findings.push({
            id: r.id,
            title: r.title,
            severity: r.sev,
            description: `Response did not include the ${r.key} header.`,
            remediation: "Set appropriate security headers at the edge or application layer.",
            evidence: { url: res.url, status: res.status },
            suite: "headers",
            tags: ["headers"]
          });
        }
      }

      return findings;
    }
  };
}
