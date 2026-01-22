import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect } from "vitest";
import { runScan } from "../src/core/runner.js";
import { createLogger } from "../src/core/logger.js";
import { HttpClient } from "../src/http/client.js";
import type { SentinelConfig } from "../src/config/schema.js";
import type { Suite } from "../src/core/types.js";
import { jsonReporter } from "../src/reporters/json.js";
import { markdownReporter } from "../src/reporters/markdown.js";

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-test-"));
}

function makeConfig(baseUrl: string): SentinelConfig {
  return {
    target: { baseUrl },
    auth: { type: "none" },
    suites: { headers: true, cors: true, auth: true, ratelimit: true, injection: false },
    active: { enabled: true, maxRequestsPerSuite: 40, timeoutMs: 8000 },
    output: { dir: "./sentinel-out", json: true, markdown: true },
    verbose: false
  };
}

describe("runner", () => {
  it("writes json + markdown report files", async () => {
    const out = tmpDir();
    const config = makeConfig("https://api.example.com");

    // Use a suite that returns deterministic findings (no fetch)
    const suite: Suite = {
      name: "test-suite",
      description: "Deterministic suite for runner test",
      async run() {
        return [
          {
            id: "test.finding",
            title: "Test Finding",
            severity: "low",
            description: "This is a test finding",
            suite: "test-suite"
          }
        ];
      }
    };

    const http = new HttpClient({
      baseUrl: config.target.baseUrl,
      timeoutMs: config.active.timeoutMs
    });

    const result = await runScan({
      suites: [suite],
      reporters: [jsonReporter(), markdownReporter()],
      ctx: { http, config, logger: createLogger({ verbose: false }) },
      sanitizedConfig: { target: { baseUrl: config.target.baseUrl } },
      outputDir: out,
      meta: {
        startedAt: new Date().toISOString(),
        targetBaseUrl: config.target.baseUrl,
        version: "0.1.0"
      }
    });

    expect(result.findings).toHaveLength(1);

    const jsonPath = path.join(out, "sentinel-report.json");
    const mdPath = path.join(out, "sentinel-report.md");

    expect(fs.existsSync(jsonPath)).toBe(true);
    expect(fs.existsSync(mdPath)).toBe(true);

    const json = JSON.parse(fs.readFileSync(jsonPath, "utf-8"));
    expect(json.findings).toHaveLength(1);

    const md = fs.readFileSync(mdPath, "utf-8");
    expect(md).toContain("# Sentinel Report");
    expect(md).toContain("Test Finding");
  });
});
