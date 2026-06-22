import { SentinelConfig } from '../../src/config/schema';
import { HttpClient } from '../../src/http/client';
import { createLogger } from '../../src/core/logger';
import type { SuiteContext } from '../../src/core/types';

export function makeConfig(
  baseUrl: string,
  authType: 'none' | 'basic' | 'bearer' | 'apiKey' = 'none',
  overrides?: Partial<SentinelConfig>
): SentinelConfig {
  return {
    target: { baseUrl },
    auth: {
      type: authType,
      probePaths: ['/'],
      compareUnauthed: authType !== 'none',
      bearerToken: authType === 'bearer' ? 'test-token' : undefined
    },
    suites: {
      headers: true,
      cors: true,
      auth: true,
      ratelimit: true,
      inventory: true,
      injection: false
    },
    injection: { paramTypes: ['query', 'body'], categories: ['sql', 'template'] },
    ratelimit: { burstCount: 10, delayMs: 0 },
    scope: {
      enabled: false,
      methods: ['get', 'head'],
      maxEndpoints: 20,
      includePaths: [],
      excludePaths: [],
      prefer: ['^/health', '^/status', '^/me', '^/api/health']
    },
    active: { maxRequestsPerSuite: 40, timeoutMs: 8000 },
    output: { dir: './sentinel-out', json: true, markdown: true },
    verbose: false,
    ...overrides
  };
}

export function makeSuiteCtx(
  baseUrl: string = 'https://api.example.com',
  authType: 'none' | 'basic' | 'bearer' | 'apiKey' = 'none'
): SuiteContext {
  const logger = createLogger({ verbose: false });
  const config = makeConfig(baseUrl, authType);
  const http = new HttpClient(
    {
      baseUrl: config.target.baseUrl,
      timeoutMs: config.active.timeoutMs
    },
    logger
  );
  return { http, config, logger };
}
