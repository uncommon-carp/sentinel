import fs from "node:fs";
import path from "node:path";
import { SentinelConfigSchema, type SentinelConfig } from "./schema.js";

type LoadConfigArgs = {
  configPath?: string;
  baseUrl?: string;
  openapi?: string;
  verbose?: boolean;
};

function readJsonIfExists(p: string): unknown | undefined {
  if (!fs.existsSync(p)) return undefined;
  const raw = fs.readFileSync(p, "utf-8");
  return JSON.parse(raw);
}

function sanitizeConfigForReport(cfg: SentinelConfig): Record<string, unknown> {
  const clone: any = structuredClone(cfg);
  if (clone?.auth?.bearerToken) clone.auth.bearerToken = "***";
  if (clone?.auth?.basicPass) clone.auth.basicPass = "***";
  if (clone?.auth?.apiKeyValue) clone.auth.apiKeyValue = "***";
  return clone;
}

export async function loadConfig(args: LoadConfigArgs): Promise<{
  config: SentinelConfig;
  sanitized: Record<string, unknown>;
}> {
  const defaultPath = path.resolve(process.cwd(), "sentinel.config.json");
  const filePath = path.resolve(process.cwd(), args.configPath ?? defaultPath);

  const fromFile = readJsonIfExists(filePath) ?? {};
  const merged = {
    ...fromFile,
    target: {
      ...(typeof (fromFile as any).target === "object" ? (fromFile as any).target : {}),
      ...(args.baseUrl ? { baseUrl: args.baseUrl } : {}),
      ...(args.openapi ? { openapi: args.openapi } : {})
    },
    ...(typeof args.verbose === "boolean" ? { verbose: args.verbose } : {})
  };

  const parsed = SentinelConfigSchema.safeParse(merged);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`);
    throw new Error(`Invalid config:\n- ${issues.join("\n- ")}`);
  }

  return { config: parsed.data, sanitized: sanitizeConfigForReport(parsed.data) };
}
