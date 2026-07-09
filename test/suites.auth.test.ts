import { describe, it, expect } from 'vitest';
import { authSuite } from '../src/suites/auth.js';
import { mockFetchQueue } from './helpers/fetchMock.js';
import { makeSuiteCtx } from './helpers/makeConfig.js';

function makeJwt(header: Record<string, unknown>, payload: Record<string, unknown>): string {
  const b64u = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b64u(header)}.${b64u(payload)}.fakesignaturepadding`;
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
