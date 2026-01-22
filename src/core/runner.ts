import fs from "node:fs";
import path from "node:path";
import type { Reporter, RunResult, Suite, SuiteContext } from "./types.js";

export async function runScan(args: {
  suites: Suite[];
  reporters: Reporter[];
  ctx: SuiteContext;
  meta: RunResult["meta"];
  sanitizedConfig: Record<string, unknown>;
  outputDir: string;
}): Promise<RunResult> {
  const started = Date.now();
  const findings: RunResult["findings"] = [];

  for (const suite of args.suites) {
    args.ctx.logger.info(`Running suite: ${suite.name}`);
    const suiteFindings = await suite.run(args.ctx);
    findings.push(...suiteFindings);
  }

  const finished = Date.now();
  const result: RunResult = {
    meta: {
      ...args.meta,
      finishedAt: new Date(finished).toISOString(),
      durationMs: finished - started
    },
    config: args.sanitizedConfig,
    findings
  };

  fs.mkdirSync(args.outputDir, { recursive: true });

  for (const reporter of args.reporters) {
    const rendered = await reporter.render(result);
    const ext = reporter.name === "markdown" ? "md" : reporter.name;
    const outPath = path.join(args.outputDir, `sentinel-report.${ext}`);
    fs.writeFileSync(outPath, rendered, "utf-8");
    args.ctx.logger.info(`Wrote report: ${outPath}`);
  }

  return result;
}
