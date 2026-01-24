/**
 * Auth suite
 *
 * Goal:
 * - Provide high-signal, low-risk checks around HTTP authentication behavior.
 *
 * What it checks (v1):
 * - 401 semantics: WWW-Authenticate should be present to advertise the auth scheme
 * - Redirect safety: flag cross-origin redirects on an auth probe (credential leakage risk)
 * - Enforcement heuristic: compare an "authed" request with an "unauthed" request
 *   against a probe endpoint to detect possible missing auth protection
 *
 * Safety / scope:
 * - Uses GET-only requests and does not follow redirects.
 * - This suite is heuristic by design; false positives are possible if the probe path
 *   is not expected to be protected.
 *
 * Configuration:
 * - auth.probePath controls which endpoint is used for probing (default "/")
 * - auth.compareUnauthed gates the "authed vs unauthed" comparison
 */

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

      // Probe path should ideally point at an endpoint that *requires* auth.
      // Defaults to "/" for safety, but may not be protected on many APIs.
      const probePath = ctx.config.auth.probePath ?? "/";
      const url = new URL(probePath, ctx.config.target.baseUrl).toString();

      // Baseline probe request: minimal, safe, and representative.
      // Note: auth header injection is handled by HttpClient based on config.auth.
      const authedRes = await ctx.http.request({
        method: "GET",
        path: probePath
      });

      // Redirect handling:
      // We do not follow redirects. If the target redirects across origins,
      // naive clients can accidentally forward Authorization headers.
      // Flag cross-origin redirects as a safety signal (not an exploit).
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

      // Optional enforcement heuristic:
      // If auth is configured, compare responses with auth vs. "cleared" auth.
      // This is only meaningful when probePath is expected to be protected.
      const authConfigured = ctx.config.auth.type !== "none";
      if (authConfigured && (ctx.config.auth.compareUnauthed ?? true)) {
        // HttpClient merges auth headers before per-request headers.
        // To simulate an unauthenticated request without creating a second client,
        // we override relevant credential headers with empty strings.
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
