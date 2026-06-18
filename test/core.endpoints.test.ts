import { describe, it, expect } from 'vitest';
import { selectEndpoints } from '../src/core/endpoints.js';
import type { LoadedApiSpec } from '../src/openapi/types.js';
import { createLogger } from '../src/core/logger.js';
import { makeConfig } from './helpers/makeConfig.js';

function makeApi(): LoadedApiSpec {
  return {
    source: 'test',
    spec: {},
    endpoints: [
      { method: 'get', path: '/users/{id}' },
      { method: 'delete', path: '/users/{id}' },
      { method: 'head', path: '/health' },
      { method: 'get', path: '/me' },
      { method: 'get', path: '/' }
    ]
  };
}

describe('selectEndpoints', () => {
  const logger = createLogger({ verbose: false });

  it('falls back to GET / when scope disabled or api missing', () => {
    const config = makeConfig('https://api.example.com', 'none');

    expect(selectEndpoints({ config, logger })).toEqual([{ method: 'get', path: '/' }]);
  });

  it('filters methods, applies prefer ordering, and caps', () => {
    const config = makeConfig('https://api.example.com', 'none', {
      scope: {
        enabled: true,
        methods: ['get', 'head'],
        maxEndpoints: 3,
        includePaths: [],
        excludePaths: [],
        prefer: ['^/health', '^/me'],
        seed: 0
      }
    });
    const api = makeApi();

    const selected = selectEndpoints({ config, logger, api });
    const keys = selected.map((e) => `${e.method} ${e.path}`);

    expect(keys).toEqual(expect.arrayContaining(['head /health', 'get /me']));

    const firstNonPreferredIndex = keys.findIndex(
      (k) => !k.includes('/health') && !k.includes('/me')
    );
    if (firstNonPreferredIndex !== -1) {
      const preferredAfter = keys
        .slice(firstNonPreferredIndex)
        .some((k) => k.includes('/health') || k.includes('/me'));
      expect(preferredAfter).toBe(false);
    }
  });

  it('supports include/exclude regex filters', () => {
    const config = makeConfig('https://api.example.com', 'none', {
      scope: {
        enabled: true,
        methods: ['get', 'head'],
        maxEndpoints: 3,
        includePaths: ['^/users'],
        excludePaths: ['\\{id\\}'], //exclude param path
        prefer: ['^/health', '^/me'],
        seed: 0
      }
    });

    const api = makeApi();
    const selected = selectEndpoints({ config, logger, api });

    // includePaths narrows to /users..., then exclude removes /users/{id} leaving fallback
    // Because selection becomes empty after filters, we guarantee GET /
    expect(selected).toEqual([{ method: 'get', path: '/' }]);
  });
});
