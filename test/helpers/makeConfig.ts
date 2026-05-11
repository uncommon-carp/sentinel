import { SentinelConfig } from '../../src/config/schema';

export function makeConfig(
  baseUrl: string,
  authType: 'none' | 'basic' | 'bearer' | 'apiKey' = 'none'
): SentinelConfig {
  return {
    target: { baseUrl },
    auth: {
      type: authType,
      probePaths: ['/'],
      compareUnauthed: authType !== 'none',
      bearerToken: authType === 'bearer' ? 'test-token' : undefined
    },
    suites: { headers: true, cors: true, auth: true, ratelimit: true, inventory: true, injection: false },
    ratelimit: { burstCount: 10, delayMs: 0 },
    scope: {
      enabled: false,
      methods: ['get', 'head'],
      maxEndpoints: 20,
      includePaths: [],
      excludePaths: [],
      prefer: ['^/health', '^/status', '^/me', '^/api/health'],
      seed: 0
    },
    active: { enabled: true, maxRequestsPerSuite: 40, timeoutMs: 8000 },
    output: { dir: './sentinel-out', json: true, markdown: true },
    verbose: false
  };
}
