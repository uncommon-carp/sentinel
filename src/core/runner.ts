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
 * - Isolate failures: a thrown suite or reporter is caught and recorded
 *   (suiteErrors / reporterErrors) so one failure cannot abort the run
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
  const { logger } = args.ctx;
  const started = Date.now();

  const findings: RunResult['findings'] = [];
  const suiteErrors: RunResult['suiteErrors'] = [];

  logger.debug('Scan started', { event: 'sentinel.scan.start', suiteCount: args.suites.length });

  for (const suite of args.suites) {
    logger.debug(`Running suite: ${suite.name}`, {
      event: 'sentinel.suite.run',
      suite: suite.name
    });
    try {
      const suiteFindings = await suite.run(args.ctx);
      findings.push(...suiteFindings);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const stack = err instanceof Error ? err.stack : undefined;
      logger.error(`Suite '${suite.name}' failed: ${message}`, {
        event: 'sentinel.suite.error',
        suite: suite.name,
        ...(stack ? { stack } : {})
      });
      suiteErrors.push({ suite: suite.name, message, ...(stack ? { stack } : {}) });
    }
  }

  const finished = Date.now();
  const duration = finished - started;

  logger.debug('Scan completed', {
    event: 'sentinel.scan.complete',
    findingsCount: findings.length,
    duration
  });

  const result: RunResult = {
    meta: {
      ...args.meta,
      finishedAt: new Date(finished).toISOString(),
      durationMs: finished - started
    },
    config: args.sanitizedConfig,
    findings,
    suiteErrors,
    reporterErrors: []
  };

  // Ensure output directory exists before writing any reports.
  fs.mkdirSync(args.outputDir, { recursive: true });

  const reporterErrors: RunResult['reporterErrors'] = [];

  for (const reporter of args.reporters) {
    try {
      const rendered = await reporter.render(result);
      const ext = reporter.name === 'markdown' ? 'md' : reporter.name;
      const outPath = path.join(args.outputDir, `sentinel-report.${ext}`);
      fs.writeFileSync(outPath, rendered, 'utf-8');
      logger.debug('Wrote report', { event: 'sentinel.report.written', outPath });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const stack = err instanceof Error ? err.stack : undefined;
      logger.error(`Reporter '${reporter.name}' failed: ${message}`, {
        event: 'sentinel.reporter.error',
        reporter: reporter.name,
        ...(stack ? { stack } : {})
      });
      reporterErrors.push({ reporter: reporter.name, message, ...(stack ? { stack } : {}) });
    }
  }

  result.reporterErrors = reporterErrors;
  return result;
}
