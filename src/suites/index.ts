/**
 * Suite registry
 *
 * Central registration point for all Sentinel security suites.
 *
 * Responsibilities:
 * - Instantiate and return enabled suites based on configuration
 * - Provide a single place to control suite ordering and defaults
 *
 * Design notes:
 * - Suites are intentionally stateless and isolated.
 * - This file should contain *no* scan logic — only wiring.
 * - REGISTRY uses Record<SuiteName, ...> so TypeScript errors if a suite added
 *   to the schema config is not wired to a factory here.
 * - ORDER controls execution sequence independently of REGISTRY keys.
 */

import type { Suite } from '../core/types.js';
import type { SentinelConfig } from '../config/schema.js';
import { headersSuite } from './headers.js';
import { corsSuite } from './cors.js';
import { authSuite } from './auth.js';
import { rateLimitSuite } from './ratelimit.js';
import { inventorySuite } from './inventory.js';
import { injectionSuite } from './injection.js';

type SuiteName = keyof SentinelConfig['suites'];

const REGISTRY: Record<SuiteName, () => Suite> = {
  headers: headersSuite,
  cors: corsSuite,
  auth: authSuite,
  ratelimit: rateLimitSuite,
  inventory: inventorySuite,
  injection: injectionSuite
};

const ORDER: SuiteName[] = ['headers', 'cors', 'auth', 'ratelimit', 'inventory', 'injection'];

export function buildSuites(enabled: SentinelConfig['suites']): Suite[] {
  return ORDER.filter((name) => enabled[name]).map((name) => REGISTRY[name]());
}
