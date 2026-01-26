import { describe, it, expect } from "vitest";
import { selectEndpoints } from "../src/core/endpoints.js";
import type { SentinelConfig } from "../src/config/schema.js";
import type { LoadedApiSpec } from "../src/openapi/types.js";

function makeConfig(): SentinelConfig {
  return {
    target: { baseUrl: "https://api.example.com" },
    auth: { type: "none", probePath: "/", compareUnauthed: false },
    suites: { headers: true, cors: true, auth: true, ratelimit: true, injection: false },
    active: { enabled: true, maxRequestsPerSuite: 40, timeoutMs: 8000 },
    output: { dir: "./sentinel-out", json: true, markdown: true },
    verbose: false,
    scope: {
      enabled: true,
      methods: ["get", "head"],
      maxEndpoints: 3,
      includePaths: [],
      excludePaths: [],
      prefer: ["^/health", "^/me"],
      seed: 0
    }
  };
}

function makeApi(): LoadedApiSpec {
  return {
    source: "test",
    spec: {},
    endpoints: [
      { method: "get", path: "/users/{id}" },
      { method: "delete", path: "/users/{id}" },
      { method: "head", path: "/health" },
      { method: "get", path: "/me" },
      { method: "get", path: "/" }
    ]
  };
}

describe("selectEndpoints", () => {
  it("falls back to GET / when scope disabled or api missing", () => {
    const config = makeConfig();
    config.scope.enabled = false;

    expect(selectEndpoints({ config })).toEqual([{ method: "get", path: "/" }]);
  });

  it("filters methods, applies prefer ordering, and caps", () => {
    const config = makeConfig();
    const api = makeApi();

    const selected = selectEndpoints({ config, api });
    const keys = selected.map((e) => `${e.method} ${e.path}`);

    expect(keys).toEqual(expect.arrayContaining(["head /health", "get /me"]));

    const firstNonPreferredIndex = keys.findIndex((k) => !k.includes("/health") && !k.includes("/me"));
    if (firstNonPreferredIndex !== -1) {
      const preferredAfter = keys.slice(firstNonPreferredIndex).some((k) => k.includes("/health") || k.includes("/me"));
      expect(preferredAfter).toBe(false);
    }
  });

  it("supports include/exclude regex filters", () => {
    const config = makeConfig();
    config.scope.includePaths = ["^/users"];
    config.scope.excludePaths = ["\\{id\\}"]; // exclude param path

    const api = makeApi();
    const selected = selectEndpoints({ config, api });

    // includePaths narrows to /users..., then exclude removes /users/{id} leaving fallback
    // Because selection becomes empty after filters, we guarantee GET /
    expect(selected).toEqual([{ method: "get", path: "/" }]);
  });
});
