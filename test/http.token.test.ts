import { describe, it, expect, afterEach, vi } from 'vitest';
import { fetchAuthToken } from '../src/http/token.js';
import { mockFetchQueue } from './helpers/fetchMock.js';
import { createLogger } from '../src/core/logger.js';

const logger = createLogger({ verbose: false });

function baseArgs(overrides: Partial<Parameters<typeof fetchAuthToken>[0]> = {}) {
  return {
    tokenUrl: 'http://localhost:3000/api/v2/auth',
    method: 'GET' as const,
    field: 'token',
    timeoutMs: 8000,
    ...overrides
  };
}

describe('fetchAuthToken', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('extracts the default `token` field on a 200 JSON response', async () => {
    mockFetchQueue([{ status: 200, bodyText: JSON.stringify({ token: 'jwt-abc', user: 'demo' }) }]);
    const token = await fetchAuthToken(baseArgs(), logger);
    expect(token).toBe('jwt-abc');
  });

  it('extracts a custom field when tokenField is set', async () => {
    mockFetchQueue([{ status: 200, bodyText: JSON.stringify({ access_token: 'oauth-xyz' }) }]);
    const token = await fetchAuthToken(baseArgs({ field: 'access_token' }), logger);
    expect(token).toBe('oauth-xyz');
  });

  it('passes method, headers, and body through to fetch', async () => {
    const fetchMock = mockFetchQueue([{ status: 200, bodyText: JSON.stringify({ token: 't' }) }]);
    await fetchAuthToken(
      baseArgs({
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{"grant_type":"client_credentials"}'
      }),
      logger
    );
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('http://localhost:3000/api/v2/auth');
    expect(init).toMatchObject({
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"grant_type":"client_credentials"}'
    });
  });

  it('throws on a non-2xx response', async () => {
    mockFetchQueue([{ status: 401, bodyText: 'nope' }]);
    await expect(fetchAuthToken(baseArgs(), logger)).rejects.toThrow(/HTTP 401/);
  });

  it('throws when the body is not valid JSON', async () => {
    mockFetchQueue([{ status: 200, bodyText: 'not json' }]);
    await expect(fetchAuthToken(baseArgs(), logger)).rejects.toThrow(/not valid JSON/);
  });

  it('throws when the token field is missing', async () => {
    mockFetchQueue([{ status: 200, bodyText: JSON.stringify({ user: 'demo' }) }]);
    await expect(fetchAuthToken(baseArgs(), logger)).rejects.toThrow(/no string field "token"/);
  });

  it('throws when the token field is present but not a string', async () => {
    mockFetchQueue([{ status: 200, bodyText: JSON.stringify({ token: 12345 }) }]);
    await expect(fetchAuthToken(baseArgs(), logger)).rejects.toThrow(/no string field "token"/);
  });

  it('wraps a network error with the tokenUrl for context', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new Error('fetch failed')) as unknown as typeof fetch
    );
    await expect(fetchAuthToken(baseArgs(), logger)).rejects.toThrow(
      'Failed to fetch auth token from http://localhost:3000/api/v2/auth: fetch failed'
    );
  });

  it('reports a timeout (AbortError) with the tokenUrl and duration', async () => {
    const abortErr = new Error('The operation was aborted');
    abortErr.name = 'AbortError';
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(abortErr) as unknown as typeof fetch);
    await expect(fetchAuthToken(baseArgs({ timeoutMs: 1234 }), logger)).rejects.toThrow(
      'Failed to fetch auth token from http://localhost:3000/api/v2/auth: request timed out after 1234ms'
    );
  });
});
