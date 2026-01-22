import { z } from "zod";

const AuthSchema = z
  .object({
    type: z.enum(["none", "bearer", "basic", "apiKey"]).default("none"),
    bearerToken: z.string().optional(),
    basicUser: z.string().optional(),
    basicPass: z.string().optional(),
    apiKeyHeader: z.string().optional(),
    apiKeyValue: z.string().optional()
  })
  .default({ type: "none" });

const ActiveSchema = z
  .object({
    enabled: z.boolean().default(true),
    maxRequestsPerSuite: z.number().int().min(1).max(500).default(40),
    timeoutMs: z.number().int().min(100).max(60000).default(8000)
  })
  .default({ enabled: true, maxRequestsPerSuite: 40, timeoutMs: 8000 });

export const SentinelConfigSchema = z.object({
  target: z.object({
    baseUrl: z.string().url(),
    openapi: z.string().optional()
  }),
  auth: AuthSchema,
  suites: z
    .object({
      headers: z.boolean().default(true),
      cors: z.boolean().default(true),
      auth: z.boolean().default(true),
      ratelimit: z.boolean().default(true),
      injection: z.boolean().default(false)
    })
    .partial()
    .default({}),
  active: ActiveSchema,
  output: z
    .object({
      dir: z.string().default("./sentinel-out"),
      json: z.boolean().default(true),
      markdown: z.boolean().default(true)
    })
    .default({ dir: "./sentinel-out", json: true, markdown: true }),
  verbose: z.boolean().default(false)
});

export type SentinelConfig = z.infer<typeof SentinelConfigSchema>;
