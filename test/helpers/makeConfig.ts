import { SentinelConfig } from "../../src/config/schema";

export function makeConfig(baseUrl: string, authType: "none" | "basic" | "bearer" | "apiKey" = "none"): SentinelConfig {
  return {
    target: { baseUrl },
    auth: { type: authType, probePath: "/", compareUnauthed: authType !== "none", bearerToken: authType === "bearer" ? "test-token" : undefined },
    suites: { headers: true, cors: true, auth: true, ratelimit: true, injection: false },
    active: { enabled: true, maxRequestsPerSuite: 40, timeoutMs: 8000 },
    output: { dir: "./sentinel-out", json: true, markdown: true },
    verbose: false
  };
}
