import fs from 'node:fs';
import path from 'node:path';
import { SentinelConfigSchema, type SentinelConfig } from './schema.js';
import { expandEnvPlaceholders } from './env.js';
import type { ZodIssue } from 'zod';

type LoadConfigArgs = {
  configPath?: string;
  baseUrl?: string;
  openapi?: string;
  verbose?: boolean;
};

function readJsonIfExists(p: string): unknown | undefined {
  if (!fs.existsSync(p)) return undefined;
  const raw = fs.readFileSync(p, 'utf-8');
  return JSON.parse(raw);
}

export function sanitizeConfigForReport(cfg: SentinelConfig): Record<string, unknown> {
  const clone = structuredClone(cfg);
  if (clone.auth.bearerToken) clone.auth.bearerToken = '***';
  if (clone.auth.basicPass) clone.auth.basicPass = '***';
  if (clone.auth.apiKeyValue) clone.auth.apiKeyValue = '***';
  // Token-endpoint request material can carry secrets (e.g. a client secret
  // interpolated via ${VAR}). tokenUrl itself is just a URL — leave it visible.
  if (clone.auth.tokenRequestBody) clone.auth.tokenRequestBody = '***';
  if (clone.auth.tokenRequestHeaders) {
    clone.auth.tokenRequestHeaders = Object.fromEntries(
      Object.keys(clone.auth.tokenRequestHeaders).map((k) => [k, '***'])
    );
  }
  return clone as Record<string, unknown>;
}

export function formatZodIssue(issue: ZodIssue): string {
  const path = issue.path.join('.') || '(root)';

  switch (issue.code) {
    case 'invalid_type':
      return `${path}: expected ${issue.expected}, received ${issue.received}`;
    case 'invalid_enum_value':
      return `${path}: expected one of ${issue.options.map((o) => `'${o}'`).join(' | ')}, received '${issue.received}'`;
    case 'invalid_string': {
      const v = issue.validation;
      if (typeof v === 'string') return `${path}: invalid ${v}`;
      if ('includes' in v) return `${path}: must include '${v.includes}'`;
      if ('startsWith' in v) return `${path}: must start with '${v.startsWith}'`;
      if ('endsWith' in v) return `${path}: must end with '${v.endsWith}'`;
      return `${path}: invalid format`;
    }
    case 'too_small':
      return `${path}: must be >= ${issue.minimum}`;
    case 'too_big':
      return `${path}: must be <= ${issue.maximum}`;
    case 'unrecognized_keys':
      return `${path}: unrecognized key(s): ${issue.keys.map((k) => `'${k}'`).join(', ')}`;
    default:
      return `${path}: ${issue.message}`;
  }
}

export type Pipeline = {
  resultsBucket: string;
  runId: string;
};

export async function loadConfig(args: LoadConfigArgs): Promise<{
  config: SentinelConfig;
  sanitized: Record<string, unknown>;
  pipeline?: Pipeline;
  pipelineWarning?: string;
}> {
  const defaultPath = path.resolve(process.cwd(), 'sentinel.config.json');
  const filePath = path.resolve(process.cwd(), args.configPath ?? defaultPath);

  const fromFile = readJsonIfExists(filePath) ?? {};
  const fileConfig = expandEnvPlaceholders(fromFile) as Record<string, unknown>;

  const envTargetUrl = process.env.TARGET_URL;
  const envResultsBucket = process.env.RESULTS_BUCKET;
  const envRunId = process.env.RUN_ID;
  const envAuthTokenUrl = process.env.AUTH_TOKEN_URL;

  const merged = {
    ...fileConfig,
    target: {
      ...(typeof fileConfig.target === 'object' && fileConfig.target !== null
        ? (fileConfig.target as Record<string, unknown>)
        : {}),
      ...(envTargetUrl ? { baseUrl: envTargetUrl } : {}),
      ...(args.baseUrl ? { baseUrl: args.baseUrl } : {}),
      ...(args.openapi ? { openapi: args.openapi } : {})
    },
    // Only construct auth from file/env when either is present, so behavior is
    // unchanged when no auth is configured anywhere. AUTH_TOKEN_URL (the Weir
    // pipeline contract) maps to auth.tokenUrl, mirroring TARGET_URL→baseUrl;
    // env wins over file, consistent with target.
    ...(fileConfig.auth || envAuthTokenUrl
      ? {
          auth: {
            ...(typeof fileConfig.auth === 'object' && fileConfig.auth !== null
              ? (fileConfig.auth as Record<string, unknown>)
              : {}),
            ...(envAuthTokenUrl ? { tokenUrl: envAuthTokenUrl } : {})
          }
        }
      : {}),
    ...(typeof args.verbose === 'boolean' ? { verbose: args.verbose } : {})
  };

  const parsed = SentinelConfigSchema.safeParse(merged);
  if (!parsed.success) {
    const issues = parsed.error.issues.map(formatZodIssue);
    throw new Error(`Invalid config:\n  - ${issues.join('\n  - ')}`);
  }

  const pipeline =
    envResultsBucket && envRunId ? { resultsBucket: envResultsBucket, runId: envRunId } : undefined;

  const pipelineWarning =
    !pipeline && (envResultsBucket || envRunId)
      ? `Pipeline config incomplete: ${envResultsBucket ? 'RESULTS_BUCKET is set' : 'RESULTS_BUCKET is missing'} and ${envRunId ? 'RUN_ID is set' : 'RUN_ID is missing'} — S3 upload skipped`
      : undefined;

  return {
    config: parsed.data,
    sanitized: sanitizeConfigForReport(parsed.data),
    ...(pipeline ? { pipeline } : {}),
    ...(pipelineWarning ? { pipelineWarning } : {})
  };
}
