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
