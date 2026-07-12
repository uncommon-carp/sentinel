import { describe, it, expect } from 'vitest';
import { buildAuthHeader } from '../src/cli/commands/scan.js';
import type { Credential } from '../src/config/schema.js';

function makeAuth(overrides: Partial<Credential>): Credential {
  return {
    type: 'none',
    tokenMethod: 'GET',
    tokenField: 'token',
    ...overrides
  };
}

describe('buildAuthHeader', () => {
  it('returns no headers when auth type is none', () => {
    const auth = makeAuth({ type: 'none' });
    expect(buildAuthHeader(auth)).toEqual({});
  });

  it('builds a Bearer header when type is bearer and a token is set', () => {
    const auth = makeAuth({ type: 'bearer', bearerToken: 'test-token' });
    expect(buildAuthHeader(auth)).toEqual({ authorization: 'Bearer test-token' });
  });

  it('returns no headers for bearer type when token is missing', () => {
    const auth = makeAuth({ type: 'bearer' });
    expect(buildAuthHeader(auth)).toEqual({});
  });

  it('builds a custom header when type is apiKey and header/value are set', () => {
    const auth = makeAuth({
      type: 'apiKey',
      apiKeyHeader: 'x-api-key',
      apiKeyValue: 'secret-key'
    });
    expect(buildAuthHeader(auth)).toEqual({ 'x-api-key': 'secret-key' });
  });

  it('returns no headers for apiKey type when header or value is missing', () => {
    const missingValue = makeAuth({ type: 'apiKey', apiKeyHeader: 'x-api-key' });
    const missingHeader = makeAuth({ type: 'apiKey', apiKeyValue: 'secret-key' });
    expect(buildAuthHeader(missingValue)).toEqual({});
    expect(buildAuthHeader(missingHeader)).toEqual({});
  });

  it('builds a base64-encoded Basic header when type is basic and credentials are set', () => {
    const auth = makeAuth({ type: 'basic', basicUser: 'admin', basicPass: 'secret123' });
    const expected = Buffer.from('admin:secret123').toString('base64');
    expect(buildAuthHeader(auth)).toEqual({ authorization: `Basic ${expected}` });
  });

  it('returns no headers for basic type when user or pass is missing', () => {
    const missingPass = makeAuth({ type: 'basic', basicUser: 'admin' });
    const missingUser = makeAuth({ type: 'basic', basicPass: 'secret123' });
    expect(buildAuthHeader(missingPass)).toEqual({});
    expect(buildAuthHeader(missingUser)).toEqual({});
  });

  it('produces a header decodable back to the original credentials', () => {
    const auth = makeAuth({ type: 'basic', basicUser: 'someuser', basicPass: 'p@ss:with:colons' });
    const { authorization } = buildAuthHeader(auth);
    const encoded = authorization!.replace('Basic ', '');
    const decoded = Buffer.from(encoded, 'base64').toString('utf-8');
    expect(decoded).toBe('someuser:p@ss:with:colons');
  });
});
