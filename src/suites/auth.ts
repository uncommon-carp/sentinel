import type { Suite, Finding } from "../core/types.js";

function isRedirect(status: number) {
  return status >= 300 && status < 400;
}

export function authSuite(): Suite {
  return {
    name: "auth",
    description: "Checks HTTP auth semantics and basic auth enforcement behavior.",
    async run(ctx): Promise<Finding[]> {
      const findings: Finding[] = [];

      const probePath = ctx.config.auth.probePath ?? "/";
      const url = new URL(probePath, ctx.config.target.baseUrl).toString();

      // 1) Baseline request (with configured auth)
      const authedRes = await ctx.http.request({
        method: "GET",
        path: probePath
      });

      // Redirect safety: we don't follow, but we can flag cross-origin redirects.
      if (isRedirect(authedRes.status)) {
        const location = authedRes.headers["location"];
        if (location) {
          try {
            const locUrl = new URL(location, authedRes.url);
            const baseOrigin = new URL(ctx.config.target.baseUrl).origin;
            if (locUrl.origin !== baseOrigin) {
              findings.push({
                id: "auth.redirect_cross_origin",
                title: "Cross-origin redirect observed on auth probe",
                severity: "medium",
                description:
                  "Auth probe returned a redirect to a different origin. Following redirects with credentials can risk leaking Authorization headers in naive clients.",
                remediation:
                  "Avoid redirecting authenticated endpoints across origins, or ensure clients do not forward credentials across origins.",
                evidence: { probeUrl: authedRes.url, location: locUrl.toString(), status: authedRes.status },
                suite: "auth",
                tags: ["auth", "redirect"]
              });
            }
          } catch {
            // Ignore malformed Location values (could add a low severity finding later)
          }
        }
      }

      // 2) 401 should include WWW-Authenticate (best practice / semantics)
      if (authedRes.status === 401) {
        const www = authedRes.headers["www-authenticate"];
        if (!www) {
          findings.push({
            id: "auth.401_missing_www_authenticate",
            title: "401 response missing WWW-Authenticate header",
            severity: "low",
            description:
              "Endpoint returned 401 Unauthorized but did not include a WWW-Authenticate header. This can break clients and obscures the intended auth scheme.",
            remediation:
              "Return a WWW-Authenticate header on 401 responses that require authentication (e.g., Bearer realm=...).",
            evidence: { probeUrl: authedRes.url, status: authedRes.status },
            suite: "auth",
            tags: ["auth", "http"]
          });
        }
      }

      // 3) Optional compare: if auth is configured, compare behavior with and without auth.
      const authConfigured = ctx.config.auth.type !== "none";
      if (authConfigured && (ctx.config.auth.compareUnauthed ?? true)) {
        // Perform the same request but explicitly without auth headers.
        // We bypass ctx.http's authHeader injection by using an absolute URL and an explicit empty auth header:
        // simplest approach: create a one-off fetch via the HttpClient by passing headers that override auth
        // BUT our HttpClient merges auth first then req.headers; so we can override Authorization with an empty string.
        const overrideHeaders: Record<string, string> = {};
        if (ctx.config.auth.type === "bearer") overrideHeaders["authorization"] = "";
        if (ctx.config.auth.type === "apiKey" && ctx.config.auth.apiKeyHeader) {
          overrideHeaders[ctx.config.auth.apiKeyHeader] = "";
        }

        const unauthedRes = await ctx.http.request({
          method: "GET",
          path: probePath,
          headers: overrideHeaders
        });

        // If both authed and unauthed succeed (2xx), that's suspicious *if probePath is meant to be protected*.
        const authedOk = authedRes.status >= 200 && authedRes.status < 300;
        const unauthedOk = unauthedRes.status >= 200 && unauthedRes.status < 300;

        if (authedOk && unauthedOk) {
          findings.push({
            id: "auth.possible_bypass_probe",
            title: "Auth probe succeeded with and without credentials",
            severity: "medium",
            description:
              "The configured auth probe endpoint returned success both with configured credentials and with credentials cleared. This may indicate the endpoint is not protected or auth is not enforced as expected.",
            remediation:
              "Verify that the probe path points to an endpoint that requires authentication, and ensure auth is enforced server-side.",
            evidence: {
              probeUrl: url,
              authedStatus: authedRes.status,
              unauthedStatus: unauthedRes.status
            },
            suite: "auth",
            tags: ["auth", "bypass"]
          });
        }
      }

      return findings;
    }
  };
}
