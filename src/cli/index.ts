#!/usr/bin/env node
import { Command } from 'commander';
import { scanCommand } from './commands/scan.js';

const program = new Command();

program
  .name('sentinel')
  .description('Sentinel: CLI API security scanner (passive + active checks)')
  .version('0.1.0');

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
      url: opts.url,
      config: opts.config,
      openapi: opts.openapi,
      out: opts.out,
      verbose: opts.verbose
    });

    process.exit(exitCode);
  });

program.parseAsync(process.argv).catch((err) => {
  console.error(err?.message ?? err);
  process.exit(1);
});
