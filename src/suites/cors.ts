import type { Suite, Finding } from "../core/types.js";

export function corsSuite(): Suite {
  return {
    name: "cors",
    description: "Performs basic CORS misconfiguration checks on the base endpoint.",
    async run(ctx): Promise<Finding[]> {
      const findings: Finding[] = [];
      const origin = "https://sentinel.invalid";

      const res = await ctx.http.request({
        method: "GET",
        path: "/",
        headers: { origin }
      });

      const acao = res.headers["access-control-allow-origin"];
      const acc = res.headers["access-control-allow-credentials"];

      if (acao === "*" && acc === "true") {
        findings.push({
          id: "cors.wildcard_with_credentials",
          title: "CORS allows credentials with wildcard origin",
          severity: "high",
          description: "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is 'true'.",
          remediation: "Do not use wildcard ACAO with credentials. Reflect only trusted origins.",
          evidence: { url: res.url, acao, acc },
          suite: "cors",
          tags: ["cors"]
        });
      }

      // Very basic reflection check
      if (acao === origin) {
        findings.push({
          id: "cors.origin_reflection",
          title: "CORS reflects arbitrary Origin",
          severity: "medium",
          description: "Server reflected the Origin header value in Access-Control-Allow-Origin.",
          remediation: "Validate Origin against an allowlist; avoid reflecting arbitrary origins.",
          evidence: { url: res.url, origin, acao },
          suite: "cors",
          tags: ["cors"]
        });
      }

      return findings;
    }
  };
}
