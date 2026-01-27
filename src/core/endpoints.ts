/**
 * Endpoint selection (Scope)
 *
 * When an OpenAPI spec is available, this module selects which endpoints to test
 * rather than blindly probing the entire API surface. The goal is bounded, safe
 * expansion: test representative endpoints without overwhelming the target or
 * the scan duration.
 *
 * Selection priority: preferred paths (e.g. /health) → shorter paths → alphabetical.
 * Falls back to GET / when scope is disabled or no API metadata is available.
 */

import type { SentinelConfig } from '../config/schema.js';
import type { ApiEndpoint, LoadedApiSpec } from '../openapi/types.js';

export type SelectedEndpoint = {
  method: ApiEndpoint['method'];
  path: ApiEndpoint['path'];
};

function compileRegexes(patterns: string[]): RegExp[] {
  return patterns.filter((p) => p.trim().length > 0).map((p) => new RegExp(p));
}

function matchesAny(res: RegExp[], value: string): boolean {
  return res.some((r) => r.test(value));
}

function normalizeEndpoints(endpoints: ApiEndpoint[]): ApiEndpoint[] {
  const seen = new Set<string>();
  const out: ApiEndpoint[] = [];
  for (const e of endpoints) {
    const method = e.method.toLowerCase();
    const path = e.path;
    const key = `${method} ${path}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ method, path });
  }
  return out;
}

export function selectEndpoints(args: {
  config: SentinelConfig;
  api?: LoadedApiSpec;
}): SelectedEndpoint[] {
  const { config, api } = args;

  if (!config.scope.enabled || !api?.endpoints?.length) {
    return [{ method: 'get', path: '/' }];
  }

  const allowedMethods = new Set(config.scope.methods.map((m) => m.toLowerCase()));
  const include = compileRegexes(config.scope.includePaths);
  const exclude = compileRegexes(config.scope.excludePaths);
  const prefer = compileRegexes(config.scope.prefer);

  const all = normalizeEndpoints(api.endpoints);

  let filtered = all.filter((e) => allowedMethods.has(e.method));

  if (include.length > 0) {
    filtered = filtered.filter((e) => matchesAny(include, e.path));
  }
  if (exclude.length > 0) {
    filtered = filtered.filter((e) => !matchesAny(exclude, e.path));
  }

  filtered.sort((a, b) => {
    const ap = matchesAny(prefer, a.path) ? 0 : 1;
    const bp = matchesAny(prefer, b.path) ? 0 : 1;
    if (ap !== bp) return ap - bp;

    if (a.path.length !== b.path.length) return a.path.length - b.path.length;

    const aKey = `${a.method} ${a.path}`;
    const bKey = `${b.method} ${b.path}`;
    return aKey.localeCompare(bKey);
  });

  const cap = Math.max(1, config.scope.maxEndpoints);
  const selected = filtered.slice(0, cap);

  if (selected.length === 0) return [{ method: 'get', path: '/' }];

  return selected;
}
