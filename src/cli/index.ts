#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { Command } from 'commander';
import { scanCommand } from './commands/scan.js';

const { version } = JSON.parse(
  readFileSync(new URL('../../package.json', import.meta.url), 'utf-8')
) as { version: string };

const program = new Command();

program
  .name('sentinel')
  .description('Sentinel: CLI API security scanner (passive + active checks)')
  .version(version);

program
  .command('scan')
  .description('Run security checks against a target API')
  .option(
    '-u, --url <baseUrl>',
    'Base URL of the target API, e.g. https://api.example.com (or set TARGET_URL env var)'
  )
  .option('-c, --config <path>', 'Path to sentinel.config.json', 'sentinel.config.json')
  .option('--openapi <pathOrUrl>', 'OpenAPI file path or URL')
  // No commander defaults here: an omitted flag must stay `undefined` so the
  // config file's `output.dir` / `verbose` can take effect. A hardcoded default
  // would always win over the config (it's never undefined), silently shadowing
  // it. The ultimate fallback lives in the schema (output.dir → './sentinel-out',
  // verbose → false), so behaviour is unchanged when neither flag nor config sets them.
  .option('-o, --out <dir>', 'Output directory (default: config output.dir, else ./sentinel-out)')
  .option('-v, --verbose', 'Verbose logging (default: config verbose, else off)')
  .action(async (opts) => {
    const { exitCode } = await scanCommand({
      version,
      url: opts.url,
      config: opts.config,
      openapi: opts.openapi,
      out: opts.out,
      verbose: opts.verbose
    });

    process.exit(exitCode);
  });

program.parseAsync(process.argv).catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`sentinel: fatal error — ${message}`);
  if (process.argv.includes('-v') || process.argv.includes('--verbose')) {
    if (err instanceof Error && err.stack) {
      console.error(err.stack);
    }
  }
  process.exit(3);
});
