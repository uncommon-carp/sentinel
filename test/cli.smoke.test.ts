import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect } from "vitest";
import { scanCommand } from "../src/cli/commands/scan.js";
import { mockFetchQueue } from "./helpers/fetchMock.js";

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-smoke-"));
}

describe("CLI smoke", () => {
  it("runs scanCommand and writes reports", async () => {
    mockFetchQueue([
      { status: 200, headers: { "content-type": "text/html" }, bodyText: "ok" }, // headers suite
      {
        status: 200,
        headers: {
          "access-control-allow-origin": "https://sentinel.invalid",
          "access-control-allow-credentials": "true"
        },
        bodyText: "ok"
      }, // cors suite
      { status: 401, headers: {} },
      { status: 300, headers: {} }
    ]);

    const out = tmpDir();

    const { exitCode, outputDir } = await scanCommand({
      url: "https://api.example.com",
      out,
      verbose: true
    });

    expect(outputDir).toBe(out);
    expect([0, 2]).toContain(exitCode);

    const jsonPath = path.join(out, "sentinel-report.json");
    const mdPath = path.join(out, "sentinel-report.md");

    expect(fs.existsSync(jsonPath)).toBe(true);
    expect(fs.existsSync(mdPath)).toBe(true);

    const json = JSON.parse(fs.readFileSync(jsonPath, "utf-8"));
    expect(json.meta.targetBaseUrl).toBe("https://api.example.com");
    expect(Array.isArray(json.findings)).toBe(true);

    const md = fs.readFileSync(mdPath, "utf-8");
    expect(md).toContain("# Sentinel Report");
  });
});
