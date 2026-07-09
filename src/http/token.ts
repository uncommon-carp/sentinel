/**
 * Auth token fetch (Tier-1 dynamic auth)
 *
 * When `auth.tokenUrl` is configured, Sentinel fetches a token from that
 * endpoint once, before scanning, and uses it as a bearer credential for the
 * rest of the run (see cli/commands/scan.ts).
 *
 * Design notes:
 * - Kept separate from HttpClient: this runs before the scan client exists and
 *   has different failure semantics (a failure here is fatal — the user asked
 *   for authenticated scanning and we cannot honor it).
 * - The token value is never logged.
 */

import type { Logger } from '../core/logger.js';

export type FetchAuthTokenArgs = {
  tokenUrl: string;
  method: 'GET' | 'POST';
  field: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs: number;
};

export async function fetchAuthToken(args: FetchAuthTokenArgs, logger: Logger): Promise<string> {
  const { tokenUrl, method, field, headers, body, timeoutMs } = args;

  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);

  logger.debug('Fetching auth token', {
    event: 'auth.token.fetch',
    tokenUrl,
    method,
    field
  });

  try {
    const init: RequestInit = {
      method,
      signal: controller.signal,
      ...(headers ? { headers } : {}),
      ...(body !== undefined ? { body } : {})
    };

    let res: Response;
    let bodyText: string;
    try {
      res = await fetch(tokenUrl, init);
      bodyText = await res.text();
    } catch (err) {
      // fetch()/AbortController throw before the checks below, with messages
      // ("The operation was aborted", "fetch failed") that mention neither the
      // URL nor that this was the auth-token step — unhelpful in CI logs.
      if (err instanceof Error && err.name === 'AbortError') {
        throw new Error(
          `Failed to fetch auth token from ${tokenUrl}: request timed out after ${timeoutMs}ms`
        );
      }
      const reason = err instanceof Error ? err.message : String(err);
      throw new Error(`Failed to fetch auth token from ${tokenUrl}: ${reason}`);
    }

    if (res.status < 200 || res.status >= 300) {
      throw new Error(`Failed to fetch auth token from ${tokenUrl}: HTTP ${res.status}`);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(bodyText);
    } catch {
      throw new Error(`Failed to fetch auth token from ${tokenUrl}: response was not valid JSON`);
    }

    if (typeof parsed !== 'object' || parsed === null) {
      throw new Error(
        `Failed to fetch auth token from ${tokenUrl}: response has no string field "${field}"`
      );
    }

    const value = (parsed as Record<string, unknown>)[field];
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error(
        `Failed to fetch auth token from ${tokenUrl}: response has no string field "${field}"`
      );
    }

    return value;
  } finally {
    clearTimeout(t);
  }
}
