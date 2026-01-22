import { loadConfig } from "../../config/load.js";
import { createLogger } from "../../core/logger.js";
import { HttpClient } from "../../http/client.js";
import { buildSuites } from "../../suites/index.js";
import { jsonReporter } from "../../reporters/json.js";
import { markdownReporter } from "../../reporters/markdown.js";
import { runScan } from "../../core/runner.js";

export type ScanCommandOptions = {
  url: string;
  config?: string;
  openapi?: string;
  out?: string;
  verbose?: boolean;
};

// Separated for testability; CLI can decide process.exit policy.
export async function scanCommand(opts: ScanCommandOptions): Promise<{
  exitCode: number;
  outputDir: string;
}> {
  const { config, sanitized } = await loadConfig({
    ...(opts.config !== undefined ? { configPath: opts.config } : {}),
    ...(opts.openapi !== undefined ? { openapi: opts.openapi } : {}),
    ...(opts.verbose !== undefined ? { verbose: opts.verbose } : {}),
    baseUrl: opts.url
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

  const outputDir = opts.out ?? config.output.dir;

  const result = await runScan({
    suites,
    reporters,
    ctx: { http, config, logger },
    sanitizedConfig: sanitized,
    outputDir,
    meta: {
      startedAt: new Date().toISOString(),
      targetBaseUrl: config.target.baseUrl,
      version: "0.1.0"
    }
  });

  const hasHigh = result.findings.some((f) => f.severity === "high" || f.severity === "critical");
  return { exitCode: hasHigh ? 2 : 0, outputDir };
}
