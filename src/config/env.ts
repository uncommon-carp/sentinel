const ENV_PATTERN = /^\$\{([A-Z0-9_]+)\}$/i;

/**
 * Recursively expands "${VAR}" strings using process.env.VAR.
 * Only exact-string matches are expanded (no partial templating).
 */
export function expandEnvPlaceholders(value: unknown): unknown {
  if (typeof value === "string") {
    const m = value.match(ENV_PATTERN);
    if (!m) return value;

    const key = m[1]!;
    const envVal = process.env[key];
    if (envVal === undefined) {
      throw new Error(`Missing required environment variable: ${key}`);
    }
    return envVal;
  }

  if (Array.isArray(value)) {
    return value.map(expandEnvPlaceholders);
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([k, v]) => [
        k,
        expandEnvPlaceholders(v)
      ])
    );
  }

  return value;
}
