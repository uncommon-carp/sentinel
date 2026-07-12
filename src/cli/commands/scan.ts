import { loadConfig, sanitizeConfigForReport } from '../../config/load.js';
import { uploadReportToS3 } from '../../reporters/s3.js';
import { createLogger } from '../../core/logger.js';
import type { Logger } from '../../core/logger.js';
import { HttpClient } from '../../http/client.js';
import { fetchAuthToken } from '../../http/token.js';
import { buildSuites } from '../../suites/index.js';
import { jsonReporter } from '../../reporters/json.js';
import { markdownReporter } from '../../reporters/markdown.js';
import { runScan } from '../../core/runner.js';
import { loadOpenApi } from '../../openapi/load.js';
import { selectEndpoints } from '../../core/endpoints.js';
import type { Credential, NamedIdentity } from '../../config/schema.js';
import type { LoadedApiSpec } from '../../openapi/types.js';

export type IdentitySession = { name: string; http: HttpClient; credential: NamedIdentity };

export type ScanCommandOptions = {
  version: string;
  url?: string;
  config?: string;
  openapi?: string;
  out?: string;
  verbose?: boolean;
};

export function buildAuthHeader(cred: Credential): Record<string, string> {
  if (cred.type === 'bearer' && cred.bearerToken) {
    return { authorization: `Bearer ${cred.bearerToken}` };
  }
  if (cred.type === 'apiKey' && cred.apiKeyHeader && cred.apiKeyValue) {
    return { [cred.apiKeyHeader]: cred.apiKeyValue };
  }
  if (cred.type === 'basic' && cred.basicUser && cred.basicPass) {
    const encoded = Buffer.from(`${cred.basicUser}:${cred.basicPass}`).toString('base64');
    return { authorization: `Basic ${encoded}` };
  }
  return {};
}

// Resolve a credential's dynamic token (Tier-1): if tokenUrl is set, fetch a
// bearer token once and fold it in. Failure is fatal by design (the caller asked
// for authenticated scanning) — the thrown error propagates to cli/index.ts (exit 3).
export async function resolveIdentityToken(
  cred: NamedIdentity,
  opts: { logger: Logger; timeoutMs: number }
): Promise<NamedIdentity> {
  if (!cred.tokenUrl) return cred;
  const token = await fetchAuthToken(
    {
      tokenUrl: cred.tokenUrl,
      method: cred.tokenMethod,
      field: cred.tokenField,
      ...(cred.tokenRequestHeaders ? { headers: cred.tokenRequestHeaders } : {}),
      ...(cred.tokenRequestBody ? { body: cred.tokenRequestBody } : {}),
      timeoutMs: opts.timeoutMs
    },
    opts.logger
  );
  return { ...cred, type: 'bearer', bearerToken: token };
}

// Resolve each configured identity and give it its own HttpClient session, so
// suites can hold several authenticated identities at once (Tier-2). identities[0]
// is the primary/default session. Never logs token values.
export async function buildIdentitySessions(
  identities: NamedIdentity[],
  opts: {
    baseUrl: string;
    timeoutMs: number;
    defaultHeaders: Record<string, string>;
    logger: Logger;
  }
): Promise<IdentitySession[]> {
  const sessions: IdentitySession[] = [];
  for (const identity of identities) {
    const resolved = await resolveIdentityToken(identity, {
      logger: opts.logger,
      timeoutMs: opts.timeoutMs
    });
    const http = new HttpClient(
      {
        baseUrl: opts.baseUrl,
        timeoutMs: opts.timeoutMs,
        defaultHeaders: opts.defaultHeaders,
        authHeader: () => buildAuthHeader(resolved),
        authType: resolved.type
      },
      opts.logger
    );
    opts.logger.debug('Resolved identity session', {
      event: 'auth.identity.resolved',
      name: identity.name
    });
    sessions.push({ name: identity.name, http, credential: resolved });
  }
  return sessions;
}

export function classifyOpenApiError(source: string, err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  const suffix = '— endpoint selection and injection suite will be skipped';

  if (err instanceof Error && (err as NodeJS.ErrnoException).code === 'ENOENT') {
    return `OpenAPI spec not found: '${source}' ${suffix}`;
  }
  if (msg.startsWith('Failed to fetch OpenAPI spec')) {
    return `${msg} ${suffix}`;
  }
  if (msg.startsWith('Failed to parse OpenAPI spec')) {
    return `${msg} ${suffix}`;
  }
  return `OpenAPI spec could not be loaded: ${msg} ${suffix}`;
}

// Separated for testability; CLI can decide process.exit policy.
export async function scanCommand(opts: ScanCommandOptions): Promise<{
  exitCode: number;
  outputDir: string;
}> {
  const { config, sanitized, pipeline, pipelineWarning } = await loadConfig({
    ...(opts.config !== undefined ? { configPath: opts.config } : {}),
    ...(opts.openapi !== undefined ? { openapi: opts.openapi } : {}),
    ...(opts.verbose !== undefined ? { verbose: opts.verbose } : {}),
    ...(opts.url !== undefined ? { baseUrl: opts.url } : {})
  });

  const logger = createLogger({ verbose: config.verbose });

  if (pipelineWarning) {
    logger.warn(pipelineWarning, { event: 'sentinel.pipeline.partial' });
  }

  const defaultHeaders = {
    'user-agent': `sentinel/${opts.version}`,
    accept: 'application/json,*/*'
  };

  // Resolve every configured identity into its own session (Tier-1 dynamic
  // tokens are fetched here; a failure is fatal and propagates to cli/index.ts →
  // exit 3). identities[0] is the primary session every suite uses via ctx.http;
  // additional identities are exposed on ctx.identities for multi-identity checks.
  let scanConfig = config;
  let sanitizedConfig = sanitized;
  const sessions = await buildIdentitySessions(config.auth.identities, {
    baseUrl: config.target.baseUrl,
    timeoutMs: config.active.timeoutMs,
    defaultHeaders,
    logger
  });

  if (sessions.length > 0) {
    // Fold resolved credentials back into the config so the report's sanitized
    // snapshot redacts the fetched tokens.
    scanConfig = {
      ...config,
      auth: { ...config.auth, identities: sessions.map((s) => s.credential) }
    };
    sanitizedConfig = sanitizeConfigForReport(scanConfig);
  }

  const primarySession = sessions[0];
  const http =
    primarySession?.http ??
    new HttpClient(
      {
        baseUrl: scanConfig.target.baseUrl,
        timeoutMs: scanConfig.active.timeoutMs,
        defaultHeaders
      },
      logger
    );

  const suites = buildSuites(scanConfig.suites);

  const reporters = [
    ...(scanConfig.output.json ? [jsonReporter()] : []),
    ...(scanConfig.output.markdown ? [markdownReporter()] : [])
  ];

  const outputDir = opts.out ?? scanConfig.output.dir;

  let api: LoadedApiSpec | undefined;
  if (scanConfig.target.openapi) {
    try {
      api = await loadOpenApi(scanConfig.target.openapi);
      logger.debug('Loaded OpenAPI spec', {
        event: 'sentinel.openapi.loaded',
        source: api.source,
        endpoints: api.endpoints.length
      });
    } catch (err) {
      logger.warn(classifyOpenApiError(scanConfig.target.openapi, err), {
        event: 'sentinel.openapi.load_failed'
      });
    }
  }

  const selectedEndpoints = selectEndpoints({
    config: scanConfig,
    logger,
    ...(api ? { api } : {})
  });

  const identities = sessions.map((s) => ({ name: s.name, http: s.http }));

  const result = await runScan({
    suites,
    reporters,
    ctx: {
      http,
      config: scanConfig,
      logger,
      selectedEndpoints,
      ...(api ? { api } : {}),
      ...(identities.length > 0 ? { identities } : {})
    },
    sanitizedConfig,
    outputDir,
    meta: {
      startedAt: new Date().toISOString(),
      targetBaseUrl: scanConfig.target.baseUrl,
      version: opts.version
    }
  });

  if (pipeline) {
    logger.debug('Uploading report to S3', {
      event: 'sentinel.s3.upload.start',
      bucket: pipeline.resultsBucket,
      runId: pipeline.runId
    });
    await uploadReportToS3(pipeline.resultsBucket, pipeline.runId, result);
    logger.info(
      `Report uploaded to s3://${pipeline.resultsBucket}/results/${pipeline.runId}.json`,
      { event: 'sentinel.s3.uploaded', bucket: pipeline.resultsBucket, runId: pipeline.runId }
    );
  }

  const hasHigh = result.findings.some((f) => f.severity === 'high' || f.severity === 'critical');
  const incomplete = result.suiteErrors.length > 0;
  return { exitCode: hasHigh ? 2 : incomplete ? 1 : 0, outputDir };
}
