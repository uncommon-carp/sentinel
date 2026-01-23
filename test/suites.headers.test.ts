import { describe, it, expect } from "vitest";
import { headersSuite } from "../src/suites/headers.js";
import { HttpClient } from "../src/http/client.js";
import { createLogger } from "../src/core/logger.js";
import { mockFetchQueue } from "./helpers/fetchMock.js";
import { makeConfig } from "./helpers/makeConfig.js";

describe("headers suite", () => {
  it("emits findings when security headers are missing", async () => {
    const fetchMock = mockFetchQueue([{
      status: 200,
      headers: {
        // intentionally empty security headers
        "content-type": "application/json"
      },
      bodyText: "{}"
    }]);

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
    mockFetchQueue([{
      status: 200,
      headers: {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "x-content-type-options": "nosniff",
        "content-type": "application/json"
      },
      bodyText: "{}"
    }]);

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
