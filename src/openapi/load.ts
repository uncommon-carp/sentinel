
import fs from "node:fs";
import path from "node:path";
import SwaggerParser from "@apidevtools/swagger-parser";
import YAML from "yaml";
import type { LoadedApiSpec } from "./types.js";

function isUrl(input: string): boolean {
  try {
    new URL(input);
    return true;
  } catch {
    return false;
  }
}

async function readText(source: string): Promise<string> {
  if (isUrl(source)) {
    const res = await fetch(source);
    if (!res.ok) throw new Error(`Failed to fetch OpenAPI spec: ${res.status} ${res.statusText}`);
    return await res.text();
  }

  const p = path.resolve(process.cwd(), source);
  return fs.readFileSync(p, "utf-8");
}

function parseSpecText(text: string, source: string): unknown {
  // Try JSON first, then YAML
  try {
    return JSON.parse(text);
  } catch {
    try {
      return YAML.parse(text);
    } catch (err) {
      throw new Error(`Failed to parse OpenAPI spec as JSON or YAML: ${source}`);
    }
  }
}

function extractEndpoints(spec: any): { method: string; path: string }[] {
  const paths = spec?.paths;
  if (!paths || typeof paths !== "object") return [];

  const out: { method: string; path: string }[] = [];
  for (const [p, methods] of Object.entries(paths)) {
    if (!methods || typeof methods !== "object") continue;

    for (const [m, op] of Object.entries(methods as Record<string, unknown>)) {
      // Ignore non-operation keys
      const method = m.toLowerCase();
      if (!["get", "post", "put", "patch", "delete", "head", "options"].includes(method)) continue;
      if (!op || typeof op !== "object") continue;

      out.push({ method, path: p });
    }
  }

  return out;
}

/**
 * Loads, validates, and dereferences an OpenAPI/Swagger spec, then extracts endpoints.
 * Returns a normalized structure suitable for suites.
 */
export async function loadOpenApi(source: string): Promise<LoadedApiSpec> {
  const text = await readText(source);
  const raw = parseSpecText(text, source);

  // Validate + dereference ($ref) for suite-friendly consumption.
  const deref = (await SwaggerParser.dereference(raw as any)) as Record<string, unknown>;
  const endpoints = extractEndpoints(deref);

  return { source, spec: deref, endpoints };
}
