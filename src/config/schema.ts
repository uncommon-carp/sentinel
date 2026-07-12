import { z } from 'zod';

// A single set of credentials. Static (`bearer`/`basic`/`apiKey`) or, for Tier-1
// dynamic auth, a `tokenUrl` that Sentinel fetches a bearer token from before
// scanning (see cli/commands/scan.ts) — tokenUrl overrides the static `type`.
const CredentialSchema = z.object({
  type: z.enum(['none', 'bearer', 'basic', 'apiKey']).default('none'),
  bearerToken: z.string().optional(),
  basicUser: z.string().optional(),
  basicPass: z.string().optional(),
  apiKeyHeader: z.string().optional(),
  apiKeyValue: z.string().optional(),

  tokenUrl: z.string().url().optional(),
  tokenMethod: z.enum(['GET', 'POST']).default('GET'),
  tokenField: z.string().default('token'),
  tokenRequestHeaders: z.record(z.string()).optional(),
  tokenRequestBody: z.string().optional()
});
export type Credential = z.infer<typeof CredentialSchema>;

// A credential with a name, so suites can reference distinct identities (Tier-2).
const NamedIdentitySchema = CredentialSchema.extend({ name: z.string().min(1) });
export type NamedIdentity = z.infer<typeof NamedIdentitySchema>;

// Auth config. `identities` is an ordered list of authenticated identities:
// identities[0] is the primary/default session every suite uses; additional
// entries are held for multi-identity checks (Tier-2 — e.g. the BOLA probe
// compares one identity's session against another). Empty ⇒ unauthenticated.
const AuthSchema = z
  .object({
    identities: z.array(NamedIdentitySchema).default([]),
    probePaths: z.array(z.string()).default(['/']),
    compareUnauthed: z.boolean().default(true)
  })
  // Strict so the pre-array shape (flat `type`/`bearerToken`/`tokenUrl` on `auth`)
  // fails loudly with an unrecognized-keys error rather than silently dropping the
  // credentials and scanning unauthenticated.
  .strict()
  .superRefine((auth, ctx) => {
    const seen = new Set<string>();
    auth.identities.forEach((identity, i) => {
      if (seen.has(identity.name)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['identities', i, 'name'],
          message: `duplicate identity name '${identity.name}'`
        });
      }
      seen.add(identity.name);
    });
  })
  .default({});

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

const InventorySchema = z
  .object({
    // Opt-in: when true, the SSRF surface check also probes POST/PUT/PATCH and
    // body parameters. Default false keeps the always-on suite safe — GET query
    // params only, no state-changing requests to the target.
    ssrfActiveProbe: z.boolean().default(false)
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
  inventory: InventorySchema,
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
