import { loadConfig } from '../../config/load.js';
import { createLogger } from '../../core/logger.js';
import { HttpClient } from '../../http/client.js';
import { buildSuites } from '../../suites/index.js';
import { jsonReporter } from '../../reporters/json.js';
import { markdownReporter } from '../../reporters/markdown.js';
import { runScan } from '../../core/runner.js';
import { loadOpenApi } from '../../openapi/load.js';
import { selectEndpoints } from '../../core/endpoints.js';
import type { SentinelConfig } from '../../config/schema.js';

export type ScanCommandOptions = {
  version: string;
  url: string;
  config?: string;
  openapi?: string;
  out?: string;
  verbose?: boolean;
};

export function buildAuthHeader(auth: SentinelConfig['auth']): Record<string, string> {
  if (auth.type === 'bearer' && auth.bearerToken) {
    return { authorization: `Bearer ${auth.bearerToken}` };
  }
  if (auth.type === 'apiKey' && auth.apiKeyHeader && auth.apiKeyValue) {
    return { [auth.apiKeyHeader]: auth.apiKeyValue };
  }
  if (auth.type === 'basic' && auth.basicUser && auth.basicPass) {
    const encoded = Buffer.from(`${auth.basicUser}:${auth.basicPass}`).toString('base64');
    return { authorization: `Basic ${encoded}` };
  }
  return {};
}

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

  const http = new HttpClient(
    {
      baseUrl: config.target.baseUrl,
      timeoutMs: config.active.timeoutMs,
      defaultHeaders: {
        'user-agent': `sentinel/${opts.version}`,
        accept: 'application/json,*/*'
      },
      authHeader: () => buildAuthHeader(config.auth),
      authType: config.auth.type
    },
    logger
  );

  const suites = buildSuites(config.suites);

  const reporters = [
    ...(config.output.json ? [jsonReporter()] : []),
    ...(config.output.markdown ? [markdownReporter()] : [])
  ];

  const outputDir = opts.out ?? config.output.dir;

  const api = config.target.openapi ? await loadOpenApi(config.target.openapi) : undefined;

  if (api) {
    logger.debug('Loaded OpenAPI spec', {
      event: 'sentinel.openapi.loaded',
      source: api.source,
      endpoints: api.endpoints.length
    });
  }

  const selectedEndpoints = selectEndpoints({ config, logger, ...(api ? { api } : {}) });

  const result = await runScan({
    suites,
    reporters,
    ctx: { http, config, logger, selectedEndpoints, ...(api ? { api } : {}) },
    sanitizedConfig: sanitized,
    outputDir,
    meta: {
      startedAt: new Date().toISOString(),
      targetBaseUrl: config.target.baseUrl,
      version: opts.version
    }
  });

  const hasHigh = result.findings.some((f) => f.severity === 'high' || f.severity === 'critical');
  const incomplete = result.suiteErrors.length > 0;
  return { exitCode: hasHigh ? 2 : incomplete ? 1 : 0, outputDir };
}
