import { describe, it, expect } from "vitest";
import { authSuite } from "../src/suites/auth.js";
import { HttpClient } from "../src/http/client.js";
import { createLogger } from "../src/core/logger.js";
import { mockFetchQueue } from "./helpers/fetchMock.js";
import { makeConfig } from "./helpers/makeConfig.js";

describe("auth suite", () => {
  it("emits a finding when a 401 missing WWW-Authenticate is received", async () => {
    mockFetchQueue([
      {
        status: 401,
        headers: {}
      }
    ]);

    const config = makeConfig("https://api.example.com");
    const http = new HttpClient({ baseUrl: config.target.baseUrl, timeoutMs: config.active.timeoutMs });

    const findings = await authSuite().run({
      http,
      config,
      logger: createLogger({ verbose: false })
    });

    expect(findings).toHaveLength(1);
    const finding = findings.find((f) => f.id === "auth.401_missing_www_authenticate");

    expect(finding).toBeDefined();
    expect(finding?.suite).toBe("auth");
    expect(finding?.severity).toBe("low");
    expect(finding?.evidence).toMatchObject({
      status: 401
    });
  });
  it("emits a finding when auth vs unauthed request yield same result", async () => {
    mockFetchQueue([
      {
        status: 200,
        bodyText: "ok"
      },
      {
        status: 200,
        bodyText: "ok"
      }
    ]);

    const config = makeConfig("https://api.example.com", "bearer");
    const http = new HttpClient({ baseUrl: config.target.baseUrl, timeoutMs: config.active.timeoutMs });

    const findings = await authSuite().run({
      http,
      config,
      logger: createLogger({ verbose: false })
    });

    const finding = findings.find((f) => f.id === "auth.possible_bypass_probe");
    expect(finding).toBeDefined();
    expect(finding?.suite).toBe("auth");
    expect(finding?.severity).toBe("medium");
  });
});
