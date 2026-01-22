
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type Finding = {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  remediation?: string;
  evidence?: Record<string, unknown>;
  location?: { method?: string; path?: string; url?: string };
  tags?: string[];
  suite: string;
};

export type RunMeta = {
  startedAt: string;
  finishedAt?: string;
  durationMs?: number;
  targetBaseUrl: string;
  version: string;
};

export type RunResult = {
  meta: RunMeta;
  config: Record<string, unknown>; // sanitized snapshot
  findings: Finding[];
};

export type SuiteContext = {
  http: import("../http/client.js").HttpClient;
  config: import("../config/schema.js").SentinelConfig;
  logger: import("./logger.js").Logger;
};

export type Suite = {
  name: string;
  description: string;
  run(ctx: SuiteContext): Promise<Finding[]>;
};

export type Reporter = {
  name: string;
  render(result: RunResult): Promise<string> | string;
};
