import { describe, it, expect } from 'vitest';
import { buildIdentitySessions, resolveIdentityToken } from '../src/cli/commands/scan.js';
import { mockFetchQueue } from './helpers/fetchMock.js';
import { createLogger } from '../src/core/logger.js';
import type { NamedIdentity } from '../src/config/schema.js';

const logger = createLogger({ verbose: false });

function identity(overrides: Partial<NamedIdentity> & { name: string }): NamedIdentity {
  return { type: 'none', tokenMethod: 'GET', tokenField: 'token', ...overrides };
}

const sessionOpts = {
  baseUrl: 'https://api.example.com',
  timeoutMs: 8000,
  defaultHeaders: {},
  logger
};

describe('resolveIdentityToken', () => {
  it('fetches and folds in a bearer token when tokenUrl is set', async () => {
    mockFetchQueue([{ status: 200, bodyText: JSON.stringify({ token: 'alice-jwt' }) }]);

    const resolved = await resolveIdentityToken(
      identity({ name: 'alice', tokenUrl: 'https://api.example.com/auth?user=alice' }),
      { logger, timeoutMs: 8000 }
    );

    expect(resolved.type).toBe('bearer');
    expect(resolved.bearerToken).toBe('alice-jwt');
  });

  it('returns the credential unchanged when no tokenUrl is set', async () => {
    const cred = identity({ name: 'static', type: 'bearer', bearerToken: 'static-tok' });
    const resolved = await resolveIdentityToken(cred, { logger, timeoutMs: 8000 });
    expect(resolved).toEqual(cred);
  });

  it('throws (fatal) when the token endpoint fails', async () => {
    mockFetchQueue([{ status: 500, bodyText: 'nope' }]);
    await expect(
      resolveIdentityToken(identity({ name: 'x', tokenUrl: 'https://api.example.com/auth' }), {
        logger,
        timeoutMs: 8000
      })
    ).rejects.toThrow(/Failed to fetch auth token/);
  });
});

describe('buildIdentitySessions', () => {
  it('gives each identity its own session carrying its own token', async () => {
    // Two token fetches (alice, bob), then one request per session below.
    const fetchMock = mockFetchQueue([
      { status: 200, bodyText: JSON.stringify({ token: 'alice-jwt' }) },
      { status: 200, bodyText: JSON.stringify({ token: 'bob-jwt' }) },
      { status: 200, bodyText: '{}' },
      { status: 200, bodyText: '{}' }
    ]);

    const sessions = await buildIdentitySessions(
      [
        identity({ name: 'alice', tokenUrl: 'https://api.example.com/auth?user=alice' }),
        identity({ name: 'bob', tokenUrl: 'https://api.example.com/auth?user=bob' })
      ],
      sessionOpts
    );

    expect(sessions.map((s) => s.name)).toEqual(['alice', 'bob']);

    await sessions[0].http.request({ method: 'GET', path: '/x' });
    await sessions[1].http.request({ method: 'GET', path: '/x' });

    // calls[0]/[1] are the token fetches; [2]/[3] are the session requests.
    const headersOf = (i: number) =>
      (fetchMock.mock.calls[i]?.[1] as RequestInit).headers as Record<string, string>;
    expect(headersOf(2)['authorization']).toBe('Bearer alice-jwt');
    expect(headersOf(3)['authorization']).toBe('Bearer bob-jwt');
  });

  it('returns an empty list when no identities are configured', async () => {
    const sessions = await buildIdentitySessions([], sessionOpts);
    expect(sessions).toEqual([]);
  });
});
