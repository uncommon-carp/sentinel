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
