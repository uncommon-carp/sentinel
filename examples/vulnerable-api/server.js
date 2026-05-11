'use strict';

const express = require('express');

const app = express();
app.use(express.json());

// ── Configuration ──────────────────────────────────────────────────────────────
// Flags default to the misconfigured state so Sentinel finds everything out of
// the box. Set env vars to fix individual issues and verify findings disappear.

const PORT                  = parseInt(process.env.PORT                  ?? '3000', 10);
const ADD_SECURITY_HEADERS  = process.env.ADD_SECURITY_HEADERS           === 'true'; // default: missing
const CORS_STRICT           = process.env.CORS_STRICT                    === 'true'; // default: reflect origin
const CORS_WILDCARD         = process.env.CORS_WILDCARD                  === 'true'; // default: off
const EXPOSE_SWAGGER        = process.env.EXPOSE_SWAGGER                 !== 'false'; // default: exposed
const LEGACY_API            = process.env.LEGACY_API                     !== 'false'; // default: alive
const GRAPHQL_INTROSPECTION = process.env.GRAPHQL_INTROSPECTION          !== 'false'; // default: enabled
const JWT_ALG               = process.env.JWT_ALG                        ?? 'none';   // default: alg:none
const JWT_TTL_SECONDS       = parseInt(process.env.JWT_TTL_SECONDS       ?? '99999', 10); // default: ~27h
const JWT_MISSING_EXP       = process.env.JWT_MISSING_EXP               === 'true';  // default: exp included
const AUTH_REQUIRED         = process.env.AUTH_REQUIRED                  === 'true';  // default: no enforcement

// ── Security headers ───────────────────────────────────────────────────────────
// Disabled by default — triggers headers.missing_hsts, missing_xcto, missing_referrer_policy.
// Set ADD_SECURITY_HEADERS=true to add them and verify those findings disappear.

if (ADD_SECURITY_HEADERS) {
  app.use((_req, res, next) => {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });
}

// ── CORS ───────────────────────────────────────────────────────────────────────
// Default: reflects any origin + sets Allow-Credentials → cors.origin_reflection.
// CORS_WILDCARD=true: uses * with credentials → cors.wildcard_with_credentials.
// CORS_STRICT=true: allows only same-host origin → no CORS findings.

app.use((req, res, next) => {
  const origin = req.headers['origin'];
  if (!origin) return next();

  if (CORS_STRICT) {
    if (origin === `http://localhost:${PORT}`) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
  } else if (CORS_WILDCARD) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  } else {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  next();
});

// ── JWT helper ─────────────────────────────────────────────────────────────────

function b64u(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

function makeJwt() {
  const now = Math.floor(Date.now() / 1000);
  const header  = { alg: JWT_ALG, typ: 'JWT' };
  const payload = { sub: 'demo', iat: now };
  if (!JWT_MISSING_EXP) payload.exp = now + JWT_TTL_SECONDS;
  const sig = JWT_ALG === 'none' ? '' : Buffer.from('sig').toString('base64url');
  return `${b64u(header)}.${b64u(payload)}.${sig}`;
}

// ── Auth middleware ────────────────────────────────────────────────────────────
// When AUTH_REQUIRED=true, endpoints return 401 without WWW-Authenticate
// (triggers auth.401_missing_www_authenticate if Sentinel probes without credentials).

function requireAuth(req, res, next) {
  if (!AUTH_REQUIRED) return next();
  if (!req.headers['authorization']?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ── Routes ─────────────────────────────────────────────────────────────────────

app.get('/', (_req, res) => {
  res.json({ name: 'sentinel-vulnerable-api', version: '2.0.0' });
});

app.get('/api/v2/health', (_req, res) => {
  res.json({ status: 'ok', version: 'v2' });
});

app.get('/api/v2/users', requireAuth, (_req, res) => {
  res.json({ users: [{ id: 1, name: 'Alice' }, { id: 2, name: 'Bob' }] });
});

// Auth probe endpoint — returns a JWT in the body.
// The auth suite inspects this response, triggering JWT findings based on config.
app.get('/api/v2/auth', (_req, res) => {
  res.json({ token: makeJwt(), user: 'demo' });
});

// ── Legacy endpoint ────────────────────────────────────────────────────────────
// Triggers inventory.stale_version_responding when the OpenAPI spec declares v2
// and this endpoint (version < 2) still responds 200.
// Set LEGACY_API=false to disable.

if (LEGACY_API) {
  app.get('/api/v1/', (_req, res) => {
    res.json({ version: 'v1', _warning: 'deprecated' });
  });
  app.get('/api/v1/users', (_req, res) => {
    res.json({ users: [{ id: 1, name: 'Alice' }], _warning: 'deprecated' });
  });
}

// ── Debug endpoint ─────────────────────────────────────────────────────────────
// Always exposed — triggers inventory.sensitive_endpoint_exposed.
// Conveniently shows the active server config for verification.

app.get('/debug', (_req, res) => {
  res.json({
    config: {
      ADD_SECURITY_HEADERS, CORS_STRICT, CORS_WILDCARD, EXPOSE_SWAGGER,
      LEGACY_API, GRAPHQL_INTROSPECTION, JWT_ALG,
      JWT_TTL_SECONDS, JWT_MISSING_EXP, AUTH_REQUIRED
    }
  });
});

// ── Swagger / OpenAPI ──────────────────────────────────────────────────────────
// Triggers inventory.sensitive_endpoint_exposed (/swagger, /openapi.json).
// The OpenAPI spec declares servers[0] as /api/v2, enabling the stale-version check.
// Set EXPOSE_SWAGGER=false to disable both.

if (EXPOSE_SWAGGER) {
  app.get('/openapi.json', (_req, res) => {
    res.json({
      openapi: '3.0.0',
      info: { title: 'Vulnerable API', version: '2.0.0' },
      servers: [{ url: `http://localhost:${PORT}/api/v2` }],
      paths: {
        '/health': { get: { summary: 'Health check',   responses: { '200': { description: 'OK' } } } },
        '/users':  { get: { summary: 'List users',     responses: { '200': { description: 'OK' } } } },
        '/auth':   { get: { summary: 'Get auth token', responses: { '200': { description: 'Returns a JWT' } } } }
      }
    });
  });

  app.get('/swagger', (_req, res) => {
    res.type('html').send('<html><body><h1>Swagger UI (dev fixture)</h1></body></html>');
  });
}

// ── GraphQL ────────────────────────────────────────────────────────────────────
// GET /graphql → 200  triggers inventory.sensitive_endpoint_exposed.
// POST /graphql with __schema query triggers inventory.graphql_introspection_enabled.
// Set GRAPHQL_INTROSPECTION=false to disable both.

if (GRAPHQL_INTROSPECTION) {
  app.get('/graphql', (_req, res) => {
    res.json({ message: 'GraphQL endpoint — use POST for queries.' });
  });

  app.post('/graphql', (req, res) => {
    const query = req.body?.query ?? '';
    if (query.includes('__schema')) {
      res.json({ data: { __schema: { queryType: { name: 'Query' } } } });
    } else {
      res.status(400).json({ errors: [{ message: 'Unknown query' }] });
    }
  });
}

// ── Start ──────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  const mark = (active) => active ? '[✓]' : '[ ]';
  console.log(`\nVulnerable API  →  http://localhost:${PORT}\n`);
  console.log('Misconfigurations  ([✓] = active, will trigger a Sentinel finding)');
  console.log(`  ${mark(!ADD_SECURITY_HEADERS)} Missing security headers       ADD_SECURITY_HEADERS=true        to fix`);
  console.log(`  ${mark(!CORS_STRICT && !CORS_WILDCARD)} CORS reflects arbitrary origin  CORS_STRICT=true                 to fix`);
  console.log(`  ${mark(CORS_WILDCARD)}  CORS wildcard + credentials    CORS_WILDCARD=true               to trigger`);
  console.log(`  ${mark(EXPOSE_SWAGGER)} Swagger / OpenAPI exposed      EXPOSE_SWAGGER=false             to hide`);
  console.log(`  ${mark(LEGACY_API)} Legacy /api/v1/ responding     LEGACY_API=false                 to disable`);
  console.log(`  ${mark(GRAPHQL_INTROSPECTION)} GraphQL introspection enabled  GRAPHQL_INTROSPECTION=false      to disable`);
  console.log(`  ${mark(JWT_ALG === 'none')} JWT alg:none                   JWT_ALG=HS256                    to fix`);
  console.log(`  ${mark(JWT_TTL_SECONDS > 86400)} JWT long TTL (${Math.round(JWT_TTL_SECONDS / 3600)}h)            JWT_TTL_SECONDS=3600             to shorten`);
  console.log(`  ${mark(JWT_MISSING_EXP)} JWT missing exp claim          JWT_MISSING_EXP=true             to trigger`);
  console.log(`  ${mark(!AUTH_REQUIRED)} Auth enforcement disabled      AUTH_REQUIRED=true               to enforce`);
  console.log('');
  console.log(`Run against this target:`);
  console.log(`  npx sentinel scan --url http://localhost:${PORT} --config sentinel.example.json\n`);
});
