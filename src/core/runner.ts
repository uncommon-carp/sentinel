/**
 * Scan runner
 *
 * Orchestrates a full Sentinel scan by:
 * - Executing enabled security suites in sequence
 * - Aggregating findings into a single run result
 * - Dispatching results to one or more reporters
 *
 * Responsibilities:
 * - Control scan lifecycle (timing, ordering, aggregation)
 * - Provide a stable execution environment for suites
 * - Handle output concerns (directory creation, file writing)
 *
 * Explicitly out of scope:
 * - HTTP request behavior (handled by HttpClient)
 * - Scan configuration or CLI parsing
 * - Security logic or decision-making (belongs in suites)
 *
 * Design notes:
 * - Suites are run sequentially to keep request volume predictable
 *   and to avoid surprising interactions between active checks.
 * - The runner is intentionally "dumb": it does not interpret findings,
 *   apply severity policy, or suppress results.
 */

import fs from 'node:fs';
import path from 'node:path';
import type { Reporter, RunResult, Suite, SuiteContext } from './types.js';

export async function runScan(args: {
  suites: Suite[];
  reporters: Reporter[];
  ctx: SuiteContext;
  meta: RunResult['meta'];
  sanitizedConfig: Record<string, unknown>;
  outputDir: string;
}): Promise<RunResult> {
  const started = Date.now();
  const findings: RunResult['findings'] = [];

  // Execute suites sequentially to preserve determinism and limit request bursts.
  for (const suite of args.suites) {
    args.ctx.logger.info(`Running suite: ${suite.name}`);
    const suiteFindings = await suite.run(args.ctx);
    findings.push(...suiteFindings);
  }

  const finished = Date.now();

  // Aggregate final scan metadata and all findings into a single result object.
  const result: RunResult = {
    meta: {
      ...args.meta,
      finishedAt: new Date(finished).toISOString(),
      durationMs: finished - started
    },
    config: args.sanitizedConfig,
    findings
  };

  // Ensure output directory exists before writing any reports.
  fs.mkdirSync(args.outputDir, { recursive: true });

  // Dispatch result to each configured reporter.
  for (const reporter of args.reporters) {
    const rendered = await reporter.render(result);
    const ext = reporter.name === 'markdown' ? 'md' : reporter.name;
    const outPath = path.join(args.outputDir, `sentinel-report.${ext}`);
    fs.writeFileSync(outPath, rendered, 'utf-8');
    args.ctx.logger.info(`Wrote report: ${outPath}`);
  }

  return result;
}
