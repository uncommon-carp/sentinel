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
  it("aggregates missing header findings across selected endpoints", async () => {
    mockFetchQueue([
      { status: 200, headers: { "x-content-type-options": "nosniff" }, bodyText: "ok" },
      { status: 200, headers: { "strict-transport-security": "max-age=31536000" }, bodyText: "ok" },
      { status: 200, headers: {}, bodyText: "ok" }
    ]);

    const config = makeConfig("https://api.example.com");
    const http = new HttpClient({ baseUrl: config.target.baseUrl, timeoutMs: config.active.timeoutMs });

    const findings = await headersSuite().run({
      http,
      config,
      logger: createLogger({ verbose: false }),
      selectedEndpoints: [
        { method: "get", path: "/a" },
        { method: "get", path: "/b" },
        { method: "get", path: "/c" }
      ]
    });

    const hsts = findings.find((f) => f.id === "headers.missing_hsts");
    const xcto = findings.find((f) => f.id === "headers.missing_xcto");

    expect(hsts).toBeDefined();
    expect(hsts?.evidence!.count).toBe(2);
    expect(hsts?.evidence!.probed).toBe(3);
    expect(xcto).toBeDefined();

    const hstsAffected = (hsts!.evidence as any).affected as Array<unknown>;
    const xctoAffected = (xcto!.evidence as any).affected as Array<unknown>;

    expect(hstsAffected).toHaveLength(2);
    expect(xctoAffected).toHaveLength(2);
  });
});
