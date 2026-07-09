import { z } from 'zod';

const AuthSchema = z
  .object({
    type: z.enum(['none', 'bearer', 'basic', 'apiKey']).default('none'),
    bearerToken: z.string().optional(),
    basicUser: z.string().optional(),
    basicPass: z.string().optional(),
    apiKeyHeader: z.string().optional(),
    apiKeyValue: z.string().optional(),

    // Dynamic token auth (Tier-1). When tokenUrl is set, Sentinel fetches a
    // token before scanning and uses it as a bearer credential (see
    // cli/commands/scan.ts). Overrides any statically-configured `type`.
    tokenUrl: z.string().url().optional(),
    tokenMethod: z.enum(['GET', 'POST']).default('GET'),
    tokenField: z.string().default('token'),
    tokenRequestHeaders: z.record(z.string()).optional(),
    tokenRequestBody: z.string().optional(),

    probePaths: z.array(z.string()).default(['/']),
    compareUnauthed: z.boolean().default(true)
  })
  .default({ type: 'none' });

const ActiveSchema = z
  .object({
    maxRequestsPerSuite: z.number().int().min(1).max(500).default(40),
    timeoutMs: z.number().int().min(100).max(60000).default(8000)
  })
  .default({ maxRequestsPerSuite: 40, timeoutMs: 8000 });

const RateLimitSchema = z
  .object({
    burstCount: z.number().int().min(2).max(50).default(10),
    delayMs: z.number().int().min(0).max(2000).default(75)
  })
  .default({});

const InjectionConfigSchema = z
  .object({
    paramTypes: z.array(z.enum(['query', 'body'])).default(['query', 'body']),
    categories: z
      .array(z.enum(['sql', 'nosql', 'template', 'command']))
      .default(['sql', 'template'])
  })
  .default({});

const ScopeSchema = z
  .object({
    enabled: z.boolean().default(false),

    methods: z.array(z.enum(['get', 'head'])).default(['get', 'head']),

    maxEndpoints: z.number().int().positive().default(20),

    includePaths: z.array(z.string()).default([]),
    excludePaths: z.array(z.string()).default([]),

    prefer: z.array(z.string()).default(['^/health', '^/status', '^/me', '^/api/health'])
  })
  .default({});

export const SentinelConfigSchema = z.object({
  target: z.object({
    baseUrl: z.string().url(),
    openapi: z.string().optional()
  }),
  auth: AuthSchema,
  ratelimit: RateLimitSchema,
  suites: z
    .object({
      headers: z.boolean().default(true),
      cors: z.boolean().default(true),
      auth: z.boolean().default(true),
      ratelimit: z.boolean().default(true),
      inventory: z.boolean().default(true),
      injection: z.boolean().default(false)
    })
    .default({}),
  injection: InjectionConfigSchema,
  scope: ScopeSchema.default({}),
  active: ActiveSchema,
  output: z
    .object({
      dir: z.string().default('./sentinel-out'),
      json: z.boolean().default(true),
      markdown: z.boolean().default(true)
    })
    .default({ dir: './sentinel-out', json: true, markdown: true }),
  verbose: z.boolean().default(false)
});

export type SentinelConfig = z.infer<typeof SentinelConfigSchema>;
