#!/usr/bin/env node
import { Command } from "commander";
import { loadConfig } from "../config/load.js";
import { createLogger } from "../core/logger.js";
import { HttpClient } from "../http/client.js";
import { buildSuites } from "../suites/index.js";
import { jsonReporter } from "../reporters/json.js";
import { markdownReporter } from "../reporters/markdown.js";
import { runScan } from "../core/runner.js";

const program = new Command();

program
  .name("sentinel")
  .description("Sentinel: CLI API security scanner (passive + active checks)")
  .version("0.1.0");

program
  .command("scan")
  .description("Run security checks against a target API")
  .requiredOption("-u, --url <baseUrl>", "Base URL of the target API, e.g. https://api.example.com")
  .option("-c, --config <path>", "Path to sentinel.config.json", "sentinel.config.json")
  .option("--openapi <pathOrUrl>", "OpenAPI file path or URL")
  .option("-o, --out <dir>", "Output directory", "./sentinel-out")
  .option("-v, --verbose", "Verbose logging", false)
  .action(async (opts) => {
    const { config, sanitized } = await loadConfig({
      configPath: opts.config,
      baseUrl: opts.url,
      openapi: opts.openapi,
      verbose: opts.verbose
    });

    const logger = createLogger({ verbose: config.verbose });
    const http = new HttpClient({
      baseUrl: config.target.baseUrl,
      timeoutMs: config.active.timeoutMs,
      defaultHeaders: {
        "user-agent": "sentinel/0.1.0",
        accept: "application/json,*/*"
      },
      authHeader: () => {
        if (config.auth.type === "bearer" && config.auth.bearerToken) {
          return { authorization: `Bearer ${config.auth.bearerToken}` };
        }
        if (config.auth.type === "apiKey" && config.auth.apiKeyHeader && config.auth.apiKeyValue) {
          return { [config.auth.apiKeyHeader]: config.auth.apiKeyValue };
        }
        return {};
      }
    });

    const suites = buildSuites({
      headers: config.suites.headers ?? true,
      cors: config.suites.cors ?? true
    });

    const reporters = [
      ...(config.output.json ? [jsonReporter()] : []),
      ...(config.output.markdown ? [markdownReporter()] : [])
    ];

    const result = await runScan({
      suites,
      reporters,
      ctx: { http, config, logger },
      sanitizedConfig: sanitized,
      outputDir: opts.out ?? config.output.dir,
      meta: {
        startedAt: new Date().toISOString(),
        targetBaseUrl: config.target.baseUrl,
        version: "0.1.0"
      }
    });

    const hasHigh = result.findings.some((f) => f.severity === "high" || f.severity === "critical");
    process.exit(hasHigh ? 2 : 0);
  });

program.parseAsync(process.argv).catch((err) => {
  console.error(err?.message ?? err);
  process.exit(1);
});
