import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { loadOpenApi } from '../src/openapi/load.js';
import { classifyOpenApiError } from '../src/cli/commands/scan.ts';

describe('openapi/load', () => {
  it('loads a local spec and extracts endpoints', async () => {
    const source = path.resolve('test/fixtures/openapi.min.json');
    const loaded = await loadOpenApi(source);

    expect(loaded.source).toBe(source);
    expect(Array.isArray(loaded.endpoints)).toBe(true);

    // Exact set (order doesn't matter)
    const set = new Set(loaded.endpoints.map((e) => `${e.method} ${e.path}`));

    expect(set.has('get /')).toBe(true);
    expect(set.has('get /users/{id}')).toBe(true);
    expect(set.has('delete /users/{id}')).toBe(true);
    expect(set.has('head /health')).toBe(true);
  });

  it('throws a readable error for invalid spec input', async () => {
    const source = path.resolve('test/fixtures/openapi.invalid.txt');
    await expect(loadOpenApi(source)).rejects.toThrow(/Failed to parse OpenAPI spec/i);
  });
});

describe('classifyOpenApiError', () => {
  it('handles ENOENT', () => {
    const err = Object.assign(new Error('ENOENT: no such file'), { code: 'ENOENT' });
    expect(classifyOpenApiError('/tmp/missing.json', err)).toMatch(
      /OpenAPI spec not found: '\/tmp\/missing.json'/
    );
  });

  it('handles fetch failure', () => {
    const err = new Error('Failed to fetch OpenAPI spec: 404 Not Found');
    expect(classifyOpenApiError('http://x/openapi.json', err)).toMatch(
      /Failed to fetch OpenAPI spec: 404/
    );
  });

  it('handles parse failure', () => {
    const err = new Error('Failed to parse OpenAPI spec as JSON or YAML: spec.yaml');
    expect(classifyOpenApiError('spec.yaml', err)).toMatch(
      /Failed to parse OpenAPI spec as JSON or YAML/
    );
  });

  it('catches SwaggerParser or unknown errors', () => {
    const err = new Error('Circular $ref detected');
    expect(classifyOpenApiError('spec.json', err)).toMatch(
      /OpenAPI spec could not be loaded: Circular \$ref/
    );
  });

  it('appends degradation notice to all cases', () => {
    const err = Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    expect(classifyOpenApiError('x.json', err)).toMatch(
      /endpoint selection and injection suite will be skipped/
    );
  });
});
