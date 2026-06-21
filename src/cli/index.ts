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
  .requiredOption('-u, --url <baseUrl>', 'Base URL of the target API, e.g. https://api.example.com')
  .option('-c, --config <path>', 'Path to sentinel.config.json', 'sentinel.config.json')
  .option('--openapi <pathOrUrl>', 'OpenAPI file path or URL')
  .option('-o, --out <dir>', 'Output directory', './sentinel-out')
  .option('-v, --verbose', 'Verbose logging', false)
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
