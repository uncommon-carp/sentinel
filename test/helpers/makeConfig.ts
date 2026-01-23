import { SentinelConfig } from "../../src/config/schema";

export function makeConfig(baseUrl: string): SentinelConfig {
  return {
    target: { baseUrl },
    auth: { type: "none" },
    suites: { headers: true, cors: true, auth: true, ratelimit: true, injection: false },
    active: { enabled: true, maxRequestsPerSuite: 40, timeoutMs: 8000 },
    output: { dir: "./sentinel-out", json: true, markdown: true },
    verbose: false
  };
}
