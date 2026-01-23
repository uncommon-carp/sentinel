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
 * - Configuration defaults are resolved here (e.g. undefined → enabled),
 *   keeping individual suites free of config branching.
 */

import type { Suite } from "../core/types.js";
import { headersSuite } from "./headers.js";
import { corsSuite } from "./cors.js";

export function buildSuites(enabled: {
  headers: boolean;
  cors: boolean;
}): Suite[] {
  const suites: Suite[] = [];
  if (enabled.headers) suites.push(headersSuite());
  if (enabled.cors) suites.push(corsSuite());
  return suites;
}
