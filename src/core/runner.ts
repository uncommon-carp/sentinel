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

  // Destructure logger for cleaner calls
  const { logger } = args.ctx;

  /*
   * The runner is intentionally "dumb": it does not interpret findings,
   * apply severity policy, or suppress results.
   */

  // Log scan start
  logger.debug('Scan started', { suiteCount: args.suites.length });

  for (const suite of args.suites) {
    logger.info(`Running suite: ${suite.name}`);
    const suiteFindings = await suite.run(args.ctx);
    findings.push(...suiteFindings);

    // Log suite completion
    logger.debug(`Finished suite: ${suite.name}`, { findingsCount: suiteFindings.length });
  }

  const finished = Date.now();
  const durationMs = finished - started;

  // Log scan completion
  logger.debug('Scan complete', { totalFindings: findings.length, durationMs });

  const result: RunResult = {
    meta: {
      ...args.meta,
      finishedAt: new Date(finished).toISOString(),
      durationMs
    },
    config: args.sanitizedConfig,
    findings
  };

  fs.mkdirSync(args.outputDir, { recursive: true });

  for (const reporter of args.reporters) {
    const rendered = await reporter.render(result);
    const ext = reporter.name === 'markdown' ? 'md' : reporter.name;
    const outPath = path.join(args.outputDir, `sentinel-report.${ext}`);
    fs.writeFileSync(outPath, rendered, 'utf-8');
    logger.info(`Wrote report: ${outPath}`);
  }

  return result;
}
