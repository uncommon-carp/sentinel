import { describe, it, expect } from "vitest";
import { headersSuite } from "../src/suites/headers.js";
import { HttpClient } from "../src/http/client.js";
import { createLogger } from "../src/core/logger.js";
import type { SentinelConfig } from "../src/config/schema.js";
import { mockFetchOnce } from "./helpers/fetchMock.js";

function makeConfig(baseUrl: string): SentinelConfig {
  return {
    target: { baseUrl },
    auth: { type: "none" },
    suites: {
      headers: true,
      cors: true,
      auth: true,
      ratelimit: true,
      injection: false
    },
    active: { enabled: true, maxRequestsPerSuite: 40, timeoutMs: 8000 },
    output: { dir: "./sentinel-out", json: true, markdown: true },
    verbose: false
  };
}

describe("headers suite", () => {
  it("emits findings when security headers are missing", async () => {
    const fetchMock = mockFetchOnce({
      status: 200,
      headers: {
        // intentionally empty security headers
        "content-type": "application/json"
      },
      bodyText: "{}"
    });

    const config = makeConfig("https://api.example.com");
    const http = new HttpClient({
      baseUrl: config.target.baseUrl,
      timeoutMs: config.active.timeoutMs
    });

    const suite = headersSuite();
    const findings = await suite.run({
      http,
      config,
      logger: createLogger({ verbose: false })
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(findings.length).toBeGreaterThan(0);

    // We expect at least missing_hsts in your suite
    expect(findings.some((f) => f.id === "headers.missing_hsts")).toBe(true);
  });

  it("emits fewer findings when some headers are present", async () => {
    mockFetchOnce({
      status: 200,
      headers: {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "x-content-type-options": "nosniff",
        "content-type": "application/json"
      },
      bodyText: "{}"
    });

    const config = makeConfig("https://api.example.com");
    const http = new HttpClient({
      baseUrl: config.target.baseUrl,
      timeoutMs: config.active.timeoutMs
    });

    const findings = await headersSuite().run({
      http,
      config,
      logger: createLogger({ verbose: false })
    });

    // missing_hsts and missing_xcto should be gone
    expect(findings.some((f) => f.id === "headers.missing_hsts")).toBe(false);
    expect(findings.some((f) => f.id === "headers.missing_xcto")).toBe(false);
  });
});
