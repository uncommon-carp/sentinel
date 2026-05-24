/**
 * Injection suite
 *
 * Requires an OpenAPI spec (ctx.api) to know which parameters to probe.
 * For each selected endpoint, extracts query and/or body parameters from the spec
 * and sends injection payloads. On the first confirmed hit per parameter, records
 * one finding and moves on — never piles multiple findings onto the same parameter.
 *
 * Checks:
 * - SQL error strings in response body  → injection.error_disclosure (high)
 * - NoSQL error strings in response body → injection.error_disclosure (high)
 * - Template expression evaluation: {{7*7}} → 49 → injection.possible_template_injection (high)
 * - Command echo: sentinel9 in response → injection.possible_command_injection (critical)
 *
 * No time-based payloads (no SLEEP/WAITFOR) — output-only detection only.
 *
 * Configuration:
 * - injection.paramTypes   which parameter locations to probe (query, body)
 * - injection.categories   payload categories to use; command requires explicit opt-in
 */

import type { Suite, Finding } from '../core/types.js';
import { resolveEndpoints } from '../core/endpoints.js';

type Category = 'sql' | 'nosql' | 'template' | 'command';

const PAYLOADS: Record<Category, string[]> = {
  sql: ["' OR '1'='1", "' OR 1=1--"],
  nosql: ['{"$gt": ""}', '{"$where": "1"}'],
  template: ['{{7*7}}', '${7*7}', '<%= 7*7 %>'],
  command: ['; echo sentinel9', '`echo sentinel9`'],
};

const SQL_ERROR_PATTERNS = ['sql syntax', 'ora-', 'pg_query', 'mysql_fetch', 'sqlite', 'sqlstate'];
const NOSQL_ERROR_PATTERNS = ['mongo', '$where', 'bson'];

function matchErrorPattern(body: string, patterns: string[]): string | null {
  const lower = body.toLowerCase();
  for (const p of patterns) {
    if (lower.includes(p)) return p;
  }
  return null;
}

function extractQueryParams(spec: Record<string, unknown>, method: string, path: string): string[] {
  const paths = spec.paths as Record<string, unknown> | undefined;
  const pathItem = paths?.[path] as Record<string, unknown> | undefined;
  const operation = pathItem?.[method] as Record<string, unknown> | undefined;
  const parameters = (operation?.parameters ?? []) as Array<Record<string, unknown>>;
  return parameters
    .filter((p) => p['in'] === 'query' && typeof p['name'] === 'string')
    .map((p) => p['name'] as string);
}

function extractBodyFields(spec: Record<string, unknown>, method: string, path: string): string[] {
  const paths = spec.paths as Record<string, unknown> | undefined;
  const pathItem = paths?.[path] as Record<string, unknown> | undefined;
  const operation = pathItem?.[method] as Record<string, unknown> | undefined;
  const requestBody = operation?.requestBody as Record<string, unknown> | undefined;
  const content = requestBody?.content as Record<string, unknown> | undefined;
  const jsonContent = content?.['application/json'] as Record<string, unknown> | undefined;
  const schemaObj = jsonContent?.schema as Record<string, unknown> | undefined;
  const properties = schemaObj?.properties;
  return properties && typeof properties === 'object' ? Object.keys(properties) : [];
}

export function injectionSuite(): Suite {
  return {
    name: 'injection',
    description:
      'Probes API parameters for SQL, NoSQL, template, and command injection signals. Requires an OpenAPI spec.',
    async run(ctx): Promise<Finding[]> {
      if (!ctx.api) {
        ctx.logger.info(
          'injection suite skipped: no OpenAPI spec loaded — pass --openapi to enable'
        );
        return [];
      }

      const findings: Finding[] = [];
      const { config } = ctx;
      const cap = config.active.maxRequestsPerSuite;
      let reqCount = 0;
      const categories = config.injection.categories as Category[];
      const paramTypes = config.injection.paramTypes;

      for (const ep of resolveEndpoints(ctx.selectedEndpoints)) {
        const params: Array<{ name: string; type: 'query' | 'body' }> = [];

        if (paramTypes.includes('query')) {
          for (const name of extractQueryParams(ctx.api.spec, ep.method, ep.path)) {
            params.push({ name, type: 'query' });
          }
        }
        if (paramTypes.includes('body')) {
          for (const name of extractBodyFields(ctx.api.spec, ep.method, ep.path)) {
            params.push({ name, type: 'body' });
          }
        }

        for (const param of params) {
          let hit = false;

          for (const category of categories) {
            if (hit) break;

            for (const payload of PAYLOADS[category]) {
              if (hit) break;

              if (reqCount >= cap) {
                ctx.logger.info('injection suite: request cap reached, stopping early');
                return findings;
              }

              let res;
              if (param.type === 'query') {
                const qs = new URLSearchParams({ [param.name]: payload });
                res = await ctx.http.request({ method: 'GET', path: `${ep.path}?${qs}` });
              } else {
                res = await ctx.http.request({
                  method: 'POST',
                  path: ep.path,
                  headers: { 'content-type': 'application/json' },
                  body: JSON.stringify({ [param.name]: payload }),
                });
              }
              reqCount++;

              const body = res.bodyText;
              const baseEvidence = {
                url: res.url,
                endpoint: `${ep.method.toUpperCase()} ${ep.path}`,
                parameter: param.name,
                paramType: param.type,
                payload,
              };

              if (category === 'sql') {
                const matched = matchErrorPattern(body, SQL_ERROR_PATTERNS);
                if (matched) {
                  findings.push({
                    id: 'injection.error_disclosure',
                    title: 'SQL injection error string detected in response',
                    severity: 'high',
                    description: `A SQL injection payload sent to the "${param.name}" ${param.type} parameter at ${ep.method.toUpperCase()} ${ep.path} produced a response containing SQL error strings.`,
                    whyItMatters:
                      'SQL error strings confirm an exploitable injection point and reveal internal database details, lowering the barrier for follow-on attacks.',
                    remediation:
                      'Use parameterized queries or prepared statements. Never surface raw database errors to clients.',
                    owasp: 'API8: Security Misconfiguration',
                    evidence: { ...baseEvidence, matchedError: matched.slice(0, 120) },
                    suite: 'injection',
                    tags: ['injection', 'sql'],
                  });
                  hit = true;
                }
              }

              if (category === 'nosql') {
                const matched = matchErrorPattern(body, NOSQL_ERROR_PATTERNS);
                if (matched) {
                  findings.push({
                    id: 'injection.error_disclosure',
                    title: 'NoSQL injection error string detected in response',
                    severity: 'high',
                    description: `A NoSQL injection payload sent to the "${param.name}" ${param.type} parameter at ${ep.method.toUpperCase()} ${ep.path} produced a response containing NoSQL error strings.`,
                    whyItMatters:
                      'NoSQL error strings confirm an exploitable injection point and reveal internal database details, lowering the barrier for follow-on attacks.',
                    remediation:
                      'Sanitize and validate all user input. Never expose raw database errors to clients.',
                    owasp: 'API8: Security Misconfiguration',
                    evidence: { ...baseEvidence, matchedError: matched.slice(0, 120) },
                    suite: 'injection',
                    tags: ['injection', 'nosql'],
                  });
                  hit = true;
                }
              }

              if (category === 'template' && body.includes('49')) {
                findings.push({
                  id: 'injection.possible_template_injection',
                  title: 'Possible template injection detected',
                  severity: 'high',
                  description: `A template injection payload sent to the "${param.name}" ${param.type} parameter at ${ep.method.toUpperCase()} ${ep.path} produced output consistent with expression evaluation (7*7=49).`,
                  whyItMatters:
                    'Template injection can allow attackers to execute arbitrary code on the server by injecting expressions evaluated by the template engine.',
                  remediation:
                    'Sanitize all user input before passing it to template engines. Use sandboxed evaluation or disable expression processing.',
                  owasp: 'API8: Security Misconfiguration',
                  evidence: { ...baseEvidence, evaluated: '49' },
                  suite: 'injection',
                  tags: ['injection', 'template'],
                });
                hit = true;
              }

              if (category === 'command' && body.includes('sentinel9')) {
                findings.push({
                  id: 'injection.possible_command_injection',
                  title: 'Possible command injection detected',
                  severity: 'critical',
                  description: `A command injection payload sent to the "${param.name}" ${param.type} parameter at ${ep.method.toUpperCase()} ${ep.path} was reflected in the response, suggesting server-side command execution.`,
                  whyItMatters:
                    'Command injection allows attackers to execute arbitrary OS commands on the server, typically leading to full system compromise.',
                  remediation:
                    'Never pass user input directly to shell commands. Use allowlisted values or parameterized APIs that do not invoke the shell.',
                  owasp: 'API8: Security Misconfiguration',
                  evidence: baseEvidence,
                  suite: 'injection',
                  tags: ['injection', 'command'],
                });
                hit = true;
              }
            }
          }
        }
      }

      return findings;
    },
  };
}
