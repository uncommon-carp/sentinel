import { describe, it, expect, vi } from 'vitest';
import { authSuite } from '../src/suites/auth.js';
import { mockFetchQueue } from './helpers/fetchMock.js';
import { makeSuiteCtx, makeConfig } from './helpers/makeConfig.js';
import { HttpClient } from '../src/http/client.js';
import { createLogger } from '../src/core/logger.js';
import type { SuiteContext } from '../src/core/types.js';
import type { LoadedApiSpec } from '../src/openapi/types.js';

// Default signature is a realistic 32-byte value (43 base64url chars) so tokens
// don't incidentally trip auth.jwt_weak_signature; pass a shorter one to test it.
function makeJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  signature: string = 'x'.repeat(43)
): string {
  const b64u = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b64u(header)}.${b64u(payload)}.${signature}`;
}

describe('auth suite', () => {
  it('emits a finding when a 401 missing WWW-Authenticate is received', async () => {
    mockFetchQueue([{ status: 401, headers: {} }]);

    const findings = await authSuite().run(makeSuiteCtx());

    expect(findings).toHaveLength(1);
    const finding = findings.find((f) => f.id === 'auth.401_missing_www_authenticate');
    expect(finding).toBeDefined();
    expect(finding?.suite).toBe('auth');
    expect(finding?.severity).toBe('low');
    expect(finding?.evidence).toMatchObject({ status: 401 });
  });

  it('emits possible_bypass_probe when valid, invalid, and no credential all succeed', async () => {
    // Enforcement probe order per path: valid, invalid, none.
    mockFetchQueue([
      { status: 200, bodyText: 'ok' },
      { status: 200, bodyText: 'ok' },
      { status: 200, bodyText: 'ok' }
    ]);

    const findings = await authSuite().run(makeSuiteCtx('https://api.example.com', 'bearer'));

    const finding = findings.find((f) => f.id === 'auth.possible_bypass_probe');
    expect(finding).toBeDefined();
    expect(finding?.suite).toBe('auth');
    expect(finding?.severity).toBe('medium');
    expect(finding?.evidence).toMatchObject({
      authedStatus: 200,
      invalidStatus: 200,
      unauthedStatus: 200
    });
    // The fully-open case is reported once, not also as invalid_token_accepted.
    expect(findings.find((f) => f.id === 'auth.invalid_token_accepted')).toBeUndefined();
  });

  it('emits invalid_token_accepted when an invalid token succeeds but no credential is rejected', async () => {
    // valid ok, invalid ok, none rejected — the endpoint checks presence, not validity.
    mockFetchQueue([
      { status: 200, bodyText: 'ok' },
      { status: 200, bodyText: 'ok' },
      { status: 401, bodyText: 'unauthorized' }
    ]);

    const findings = await authSuite().run(makeSuiteCtx('https://api.example.com', 'bearer'));

    const finding = findings.find((f) => f.id === 'auth.invalid_token_accepted');
    expect(finding).toBeDefined();
    expect(finding?.suite).toBe('auth');
    expect(finding?.severity).toBe('high');
    expect(finding?.evidence).toMatchObject({
      validStatus: 200,
      invalidStatus: 200,
      noneStatus: 401
    });
    expect(findings.find((f) => f.id === 'auth.possible_bypass_probe')).toBeUndefined();
  });

  it('emits invalid_token_accepted for basic auth using a Basic-scheme invalid credential', async () => {
    // Same verdict as the bearer case, but the invalid probe must carry a
    // Basic-scheme header — a Bearer header would be rejected for the wrong
    // reason on a server that gates on the Basic scheme (false negative).
    const fetchMock = mockFetchQueue([
      { status: 200, bodyText: 'ok' },
      { status: 200, bodyText: 'ok' },
      { status: 401, bodyText: 'unauthorized' }
    ]);

    const findings = await authSuite().run(makeSuiteCtx('https://api.example.com', 'basic'));

    const finding = findings.find((f) => f.id === 'auth.invalid_token_accepted');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');

    // The invalid probe (2nd request) must send a Basic-scheme authorization header.
    const invalidReqInit = fetchMock.mock.calls[1]?.[1] as RequestInit;
    const invalidAuth = (invalidReqInit.headers as Record<string, string>)['authorization'];
    expect(invalidAuth).toMatch(/^Basic /);
  });

  it('emits no bypass finding when auth is properly enforced', async () => {
    // valid ok, invalid rejected, none rejected — enforcement is real.
    mockFetchQueue([
      { status: 200, bodyText: 'ok' },
      { status: 401, bodyText: 'unauthorized' },
      { status: 401, bodyText: 'unauthorized' }
    ]);

    const findings = await authSuite().run(makeSuiteCtx('https://api.example.com', 'bearer'));

    expect(findings.find((f) => f.id === 'auth.possible_bypass_probe')).toBeUndefined();
    expect(findings.find((f) => f.id === 'auth.invalid_token_accepted')).toBeUndefined();
  });

  it('emits a finding when a cross-origin redirect is received', async () => {
    mockFetchQueue([{ status: 302, headers: { location: 'https://example2.com' } }]);

    const ctx = makeSuiteCtx('https://api.example.com', 'bearer');
    ctx.config.auth.compareUnauthed = false;

    const findings = await authSuite().run(ctx);

    const finding = findings.find((f) => f.id === 'auth.redirect_cross_origin');
    expect(finding).toBeDefined();
    expect(finding?.suite).toBe('auth');
    expect(finding?.severity).toBe('medium');
    expect(finding?.evidence?.location).toBe('https://example2.com/');
  });

  it('emits auth.jwt_alg_none when a response body contains a JWT with alg:none', async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = makeJwt({ alg: 'none', typ: 'JWT' }, { sub: '1', iat: now, exp: now + 3600 });
    mockFetchQueue([{ status: 200, bodyText: JSON.stringify({ token: jwt }) }]);

    const findings = await authSuite().run(makeSuiteCtx());

    const finding = findings.find((f) => f.id === 'auth.jwt_alg_none');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.suite).toBe('auth');
    expect(finding?.tags).toContain('jwt');
  });

  it('emits auth.jwt_weak_signature when a non-none JWT has a trivially short signature', async () => {
    const now = Math.floor(Date.now() / 1000);
    // Anemone's actual stub: base64url('sig') → 'c2ln', decodes to 3 bytes.
    const stubSig = Buffer.from('sig').toString('base64url');
    const jwt = makeJwt(
      { alg: 'HS256', typ: 'JWT' },
      { sub: '1', iat: now, exp: now + 3600 },
      stubSig
    );
    mockFetchQueue([{ status: 200, bodyText: JSON.stringify({ token: jwt }) }]);

    const findings = await authSuite().run(makeSuiteCtx());

    const finding = findings.find((f) => f.id === 'auth.jwt_weak_signature');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.suite).toBe('auth');
    expect(finding?.tags).toContain('jwt');
    expect(finding?.evidence).toMatchObject({ signatureBytes: 3, alg: 'hs256' });
    // alg is not "none", so jwt_alg_none must not fire.
    expect(findings.find((f) => f.id === 'auth.jwt_alg_none')).toBeUndefined();
  });

  it('does not emit auth.jwt_weak_signature for a normal-length signature', async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: '1', iat: now, exp: now + 3600 });
    mockFetchQueue([{ status: 200, bodyText: JSON.stringify({ token: jwt }) }]);

    const findings = await authSuite().run(makeSuiteCtx());

    expect(findings.find((f) => f.id === 'auth.jwt_weak_signature')).toBeUndefined();
  });

  it('emits auth.jwt_missing_exp when a response body contains a JWT with no exp claim', async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: '1', iat: now });
    mockFetchQueue([{ status: 200, bodyText: JSON.stringify({ token: jwt }) }]);

    const findings = await authSuite().run(makeSuiteCtx());

    const finding = findings.find((f) => f.id === 'auth.jwt_missing_exp');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
    expect(finding?.suite).toBe('auth');
  });

  it('emits auth.jwt_expired_accepted when a 2xx response contains an already-expired JWT', async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = makeJwt(
      { alg: 'HS256', typ: 'JWT' },
      { sub: '1', iat: now - 7200, exp: now - 3600 }
    );
    mockFetchQueue([{ status: 200, bodyText: JSON.stringify({ token: jwt }) }]);

    const findings = await authSuite().run(makeSuiteCtx());

    const finding = findings.find((f) => f.id === 'auth.jwt_expired_accepted');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.evidence).toMatchObject({ status: 200 });
  });

  it('emits auth.jwt_long_ttl when a response contains a JWT valid for more than 24h', async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: '1', iat: now, exp: now + 86401 });
    mockFetchQueue([{ status: 200, bodyText: JSON.stringify({ token: jwt }) }]);

    const findings = await authSuite().run(makeSuiteCtx());

    const finding = findings.find((f) => f.id === 'auth.jwt_long_ttl');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('low');
    expect(finding?.evidence?.ttlSeconds as number).toBeGreaterThan(86400);
  });
});

describe('auth suite — BOLA probe', () => {
  const baseUrl = 'https://api.example.com';

  // A spec advertising one object endpoint (integer id) under /api/v2.
  const bolaSpec: LoadedApiSpec = {
    source: 'test',
    spec: {
      servers: [{ url: `${baseUrl}/api/v2` }],
      paths: {
        '/users/{id}': {
          get: {
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
            responses: { 200: {} }
          }
        }
      }
    },
    endpoints: [{ method: 'get', path: '/users/{id}' }]
  };

  // probePaths [] so the only requests the suite makes are the BOLA probe's,
  // keeping the order-based fetch mock queue easy to reason about. cap is a
  // request budget: a two-identity unit costs 3 requests (identityA, identityB,
  // unauth guard), so cap 3 buys exactly one candidate id.
  const API_KEY_HEADER = 'x-api-key';

  function bolaCtx(opts: {
    identityNames: string[];
    cap?: number;
    api?: LoadedApiSpec | undefined;
    authType?: 'bearer' | 'apiKey';
  }): SuiteContext {
    const logger = createLogger({ verbose: false });
    const authType = opts.authType ?? 'bearer';
    const mkHttp = (name: string) =>
      new HttpClient(
        {
          baseUrl,
          timeoutMs: 8000,
          authHeader: () =>
            authType === 'apiKey'
              ? { [API_KEY_HEADER]: `${name}-key` }
              : { authorization: `Bearer ${name}-token` },
          authType
        },
        logger
      );
    const identities = opts.identityNames.map((name) => ({ name, http: mkHttp(name) }));
    const config = makeConfig(baseUrl, authType, {
      auth: {
        identities: opts.identityNames.map((name) =>
          authType === 'apiKey'
            ? {
                name,
                type: 'apiKey',
                apiKeyHeader: API_KEY_HEADER,
                apiKeyValue: `${name}-key`,
                tokenMethod: 'GET',
                tokenField: 'token'
              }
            : {
                name,
                type: 'bearer',
                bearerToken: `${name}-token`,
                tokenMethod: 'GET',
                tokenField: 'token'
              }
        ),
        probePaths: [],
        compareUnauthed: false
      },
      active: { maxRequestsPerSuite: opts.cap ?? 40, timeoutMs: 8000 }
    });
    return {
      http: identities[0]!.http,
      config,
      logger,
      identities,
      ...('api' in opts ? { api: opts.api } : { api: bolaSpec })
    };
  }

  it('flags BOLA when two identities read the same object and unauth is rejected', async () => {
    // Order per id: identityA, identityB, unauth.
    mockFetchQueue([
      { status: 200, bodyText: '{"id":1,"owner":"alice"}' },
      { status: 200, bodyText: '{"id":1,"owner":"alice"}' },
      { status: 401, bodyText: 'unauthorized' }
    ]);

    const findings = await authSuite().run(bolaCtx({ identityNames: ['alice', 'bob'], cap: 3 }));

    const finding = findings.find((f) => f.id === 'auth.bola_object_access');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.owasp).toContain('API1');
    const accesses = (finding?.evidence as { accesses: Array<Record<string, unknown>> }).accesses;
    expect(accesses[0]).toMatchObject({
      endpoint: 'GET /api/v2/users/1',
      resourceId: 1,
      unauthStatus: 401,
      bodiesMatch: true
    });
    expect(accesses[0]!.identities).toEqual(expect.arrayContaining(['alice', 'bob']));
    // The leaked record body must not be copied into the report.
    expect(JSON.stringify(finding?.evidence)).not.toContain('owner');
  });

  it('does not flag when each identity only accesses its own object', async () => {
    // Secure fixture: alice reads id=1 (200), bob is forbidden (403), unauth 401.
    mockFetchQueue([
      { status: 200, bodyText: '{"id":1,"owner":"alice"}' },
      { status: 403, bodyText: 'forbidden' },
      { status: 401, bodyText: 'unauthorized' }
    ]);

    const findings = await authSuite().run(bolaCtx({ identityNames: ['alice', 'bob'], cap: 3 }));

    expect(findings.find((f) => f.id === 'auth.bola_object_access')).toBeUndefined();
  });

  it('does not flag a public object when the unauthenticated request also succeeds', async () => {
    mockFetchQueue([
      { status: 200, bodyText: 'public' },
      { status: 200, bodyText: 'public' },
      { status: 200, bodyText: 'public' }
    ]);

    const findings = await authSuite().run(bolaCtx({ identityNames: ['alice', 'bob'], cap: 3 }));

    expect(findings.find((f) => f.id === 'auth.bola_object_access')).toBeUndefined();
  });

  it('skips the probe (no requests) when fewer than two identities are configured', async () => {
    mockFetchQueue([]);

    const findings = await authSuite().run(bolaCtx({ identityNames: ['alice'], cap: 1 }));

    expect(findings.find((f) => f.id === 'auth.bola_object_access')).toBeUndefined();
  });

  it('skips the probe when no OpenAPI spec is available', async () => {
    mockFetchQueue([]);

    const findings = await authSuite().run(
      bolaCtx({ identityNames: ['alice', 'bob'], cap: 1, api: undefined })
    );

    expect(findings.find((f) => f.id === 'auth.bola_object_access')).toBeUndefined();
  });

  it('strips an apiKey credential in the unauthenticated guard, not just Authorization', async () => {
    // Header-aware server: serves the object for any request carrying a non-empty
    // X-API-Key, 401 otherwise. Both identities carry a key, so if the guard only
    // cleared `authorization` (the pre-fix behaviour) its request would still be
    // authenticated, read as 2xx/public, and suppress the finding. A correct guard
    // strips the primary identity's *actual* scheme (the apiKey header) → 401.
    const OBJECT = '{"id":1,"owner":"alice"}';
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url: string, init: RequestInit) => {
        const headers = (init.headers ?? {}) as Record<string, string>;
        const key = headers[API_KEY_HEADER];
        const authed = typeof key === 'string' && key.length > 0;
        return {
          status: authed ? 200 : 401,
          headers: { forEach() {} } as unknown as Headers,
          text: async () => (authed ? OBJECT : 'unauthorized')
        } as unknown as Response;
      })
    );

    const findings = await authSuite().run(
      bolaCtx({ identityNames: ['alice', 'bob'], cap: 3, authType: 'apiKey' })
    );

    expect(findings.find((f) => f.id === 'auth.bola_object_access')).toBeDefined();
  });

  it('charges the real per-unit request cost against the cap (never exceeds maxRequestsPerSuite)', async () => {
    // Two object endpoints, but cap 3 only affords a single two-identity unit
    // (3 requests: identityA, identityB, unauth guard). The responses are all
    // 401 so nothing is flagged and nothing early-outs — if the budget were
    // charged one-per-id instead of per-unit it would start a second unit and
    // the 4th request would exhaust the mocked queue and throw.
    const twoEndpointSpec: LoadedApiSpec = {
      source: 'test',
      spec: {
        servers: [{ url: `${baseUrl}/api/v2` }],
        paths: {
          '/users/{id}': {
            get: {
              parameters: [{ name: 'id', in: 'path', schema: { type: 'integer' } }],
              responses: { 200: {} }
            }
          },
          '/orders/{id}': {
            get: {
              parameters: [{ name: 'id', in: 'path', schema: { type: 'integer' } }],
              responses: { 200: {} }
            }
          }
        }
      },
      endpoints: [
        { method: 'get', path: '/users/{id}' },
        { method: 'get', path: '/orders/{id}' }
      ]
    };
    const fetchMock = mockFetchQueue([
      { status: 401, bodyText: 'no' },
      { status: 401, bodyText: 'no' },
      { status: 401, bodyText: 'no' }
    ]);

    const findings = await authSuite().run(
      bolaCtx({ identityNames: ['alice', 'bob'], cap: 3, api: twoEndpointSpec })
    );

    expect(findings.find((f) => f.id === 'auth.bola_object_access')).toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});

describe('auth suite — mass assignment probe', () => {
  const baseUrl = 'https://api.example.com';

  // A spec advertising one writable object endpoint (integer id, PATCH) under
  // /api/v2, documenting only `email` as settable — so the probe's canary
  // field (first undeclared candidate: `role`) is guaranteed absent.
  const massAssignmentSpec: LoadedApiSpec = {
    source: 'test',
    spec: {
      servers: [{ url: `${baseUrl}/api/v2` }],
      paths: {
        '/users/{id}': {
          patch: {
            parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
            requestBody: {
              content: {
                'application/json': {
                  schema: { type: 'object', properties: { email: { type: 'string' } } }
                }
              }
            },
            responses: { 200: {} }
          }
        }
      }
    },
    endpoints: [{ method: 'patch', path: '/users/{id}' }]
  };

  // probePaths [] and compareUnauthed false so the only requests the suite
  // makes are the mass assignment probe's, keeping the order-based fetch mock
  // queue easy to reason about.
  function massAssignmentCtx(opts: {
    identityNames?: string[];
    cap?: number;
    api?: LoadedApiSpec | undefined;
    massAssignmentProbe?: boolean;
  }): SuiteContext {
    const logger = createLogger({ verbose: false });
    const names = opts.identityNames ?? ['alice'];
    const mkHttp = (name: string) =>
      new HttpClient(
        {
          baseUrl,
          timeoutMs: 8000,
          authHeader: () => ({ authorization: `Bearer ${name}-token` }),
          authType: 'bearer'
        },
        logger
      );
    const identities = names.map((name) => ({ name, http: mkHttp(name) }));
    const config = makeConfig(baseUrl, 'bearer', {
      auth: {
        identities: names.map((name) => ({
          name,
          type: 'bearer' as const,
          bearerToken: `${name}-token`,
          tokenMethod: 'GET' as const,
          tokenField: 'token'
        })),
        probePaths: [],
        compareUnauthed: false,
        massAssignmentProbe: opts.massAssignmentProbe ?? true
      },
      active: { maxRequestsPerSuite: opts.cap ?? 40, timeoutMs: 8000 }
    });
    return {
      http: identities[0]!.http,
      config,
      logger,
      identities,
      ...('api' in opts ? { api: opts.api } : { api: massAssignmentSpec })
    };
  }

  it('flags mass assignment when the canary field persists after a write', async () => {
    // Order: write (PATCH), read-back (GET).
    mockFetchQueue([
      {
        status: 200,
        bodyText: '{"id":1,"email":"alice@example.com","role":"sentinel-canary-9f2b1e"}'
      },
      {
        status: 200,
        bodyText: '{"id":1,"email":"alice@example.com","role":"sentinel-canary-9f2b1e"}'
      }
    ]);

    const findings = await authSuite().run(massAssignmentCtx({ cap: 2 }));

    const finding = findings.find((f) => f.id === 'auth.mass_assignment_accepted');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
    expect(finding?.owasp).toContain('API3');
    const accepted = (finding?.evidence as { accepted: Array<Record<string, unknown>> }).accepted;
    expect(accepted[0]).toMatchObject({
      endpoint: 'PATCH /api/v2/users/1',
      identity: 'alice',
      resourceId: 1,
      field: 'role',
      value: 'sentinel-canary-9f2b1e'
    });
  });

  it('does not flag when the write is rejected', async () => {
    mockFetchQueue([{ status: 403, bodyText: 'forbidden' }]);

    const findings = await authSuite().run(massAssignmentCtx({ cap: 1 }));

    expect(findings.find((f) => f.id === 'auth.mass_assignment_accepted')).toBeUndefined();
  });

  it('does not flag when the write succeeds but the canary field is stripped server-side', async () => {
    // Secure fixture: write accepted (200) but the read-back shows no `role`.
    mockFetchQueue([
      { status: 200, bodyText: '{"id":1,"email":"alice@example.com"}' },
      { status: 200, bodyText: '{"id":1,"email":"alice@example.com"}' }
    ]);

    const findings = await authSuite().run(massAssignmentCtx({ cap: 2 }));

    expect(findings.find((f) => f.id === 'auth.mass_assignment_accepted')).toBeUndefined();
  });

  it('does not probe when auth.massAssignmentProbe is off (default)', async () => {
    // Only base requests (none, since probePaths is []) are queued; a stray
    // probe would throw "no more mocked responses".
    mockFetchQueue([]);

    const findings = await authSuite().run(
      massAssignmentCtx({ cap: 2, massAssignmentProbe: false })
    );

    expect(findings.find((f) => f.id === 'auth.mass_assignment_accepted')).toBeUndefined();
  });

  it('does not probe when no OpenAPI spec is available', async () => {
    mockFetchQueue([]);

    const findings = await authSuite().run(massAssignmentCtx({ cap: 2, api: undefined }));

    expect(findings.find((f) => f.id === 'auth.mass_assignment_accepted')).toBeUndefined();
  });

  it('works with a single configured identity (no Tier-2 required)', async () => {
    mockFetchQueue([
      { status: 200, bodyText: '{"id":1,"role":"sentinel-canary-9f2b1e"}' },
      { status: 200, bodyText: '{"id":1,"role":"sentinel-canary-9f2b1e"}' }
    ]);

    const findings = await authSuite().run(massAssignmentCtx({ identityNames: ['alice'], cap: 2 }));

    expect(findings.find((f) => f.id === 'auth.mass_assignment_accepted')).toBeDefined();
  });

  it("never mutates another identity's object — probes each identity only against its own session", async () => {
    // Two identities, cap only affords one id attempt each (2 requests per
    // identity: write + read). alice's write persists; bob's is rejected.
    // Confirms each identity's session issues its own requests independently.
    mockFetchQueue([
      { status: 200, bodyText: '{"id":1,"role":"sentinel-canary-9f2b1e"}' }, // alice write
      { status: 200, bodyText: '{"id":1,"role":"sentinel-canary-9f2b1e"}' }, // alice read
      { status: 403, bodyText: 'forbidden' } // bob write (id 1 isn't bob's)
    ]);

    const findings = await authSuite().run(
      massAssignmentCtx({ identityNames: ['alice', 'bob'], cap: 3 })
    );

    const finding = findings.find((f) => f.id === 'auth.mass_assignment_accepted');
    expect(finding).toBeDefined();
    const accepted = (finding?.evidence as { accepted: Array<Record<string, unknown>> }).accepted;
    expect(accepted).toHaveLength(1);
    expect(accepted[0]).toMatchObject({ identity: 'alice' });
  });

  it('charges the real per-unit request cost against the cap (never exceeds maxRequestsPerSuite)', async () => {
    // cap 2: alice's unit costs exactly 2 (write + read, both succeed and
    // confirm). No budget remains for bob's identity — if the budget weren't
    // checked before starting a new identity, a third request would fire and
    // exhaust the mocked queue, throwing.
    const fetchMock = mockFetchQueue([
      { status: 200, bodyText: '{"id":1,"role":"sentinel-canary-9f2b1e"}' },
      { status: 200, bodyText: '{"id":1,"role":"sentinel-canary-9f2b1e"}' }
    ]);

    await authSuite().run(massAssignmentCtx({ identityNames: ['alice', 'bob'], cap: 2 }));

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
