# Sentinel

Sentinel is an OWASP API Security Top 10 scanner for HTTP APIs. Point it at any API — with or without an OpenAPI spec — and get structured findings across misconfiguration, auth weaknesses, injection surface, and inventory drift. Runs in seconds from the CLI, gates pull requests as a Fargate sidecar, or slots into any CI pipeline. No proxy setup, no traffic interception.

---

## Part of the Sentinel pipeline

| Repo                                                | Role                                                                              |
| --------------------------------------------------- | --------------------------------------------------------------------------------- |
| **sentinel** (this)                                 | OWASP API scanner — the tool                                                      |
| [anemone](https://github.com/uncommon-carp/anemone) | Deliberately vulnerable target API — scan fixture and regression harness          |
| [weir](https://github.com/uncommon-carp/weir)       | Ephemeral DAST gate — provisions isolated Fargate tasks, runs Sentinel, gates PRs |

---

## What's new in 0.4.0

- **Pipeline mode** — S3 report upload via env-var config (`RESULTS_BUCKET`, `RUN_ID`). Designed for [Weir](https://github.com/uncommon-carp/weir) but works with any S3-compatible pipeline.
- **Docker image** — Sentinel ships as a container image for use as a Fargate sidecar or standalone pipeline component.
- **[`FINDINGS.md`](./FINDINGS.md)** — canonical finding ID registry. All IDs, severities, OWASP mappings, and remediation guidance in one place.
- **Finding ID alignment** — JWT finding IDs corrected to `auth.jwt_*` prefix throughout.

---

## Features

**Implemented suites:**

- HTTP security headers (HSTS, X-Content-Type-Options, Referrer-Policy)
- CORS misconfiguration detection (wildcard + credentials, origin reflection)
- Auth behavior (401 + WWW-Authenticate semantics, cross-origin redirect detection, auth enforcement heuristics — including definitive invalid-token-accepted detection, JWT inspection — alg:none, weak/stub signatures, missing exp, expired tokens, excessive TTL); with authenticated identities configured, Tier-1 mass assignment detection and Tier-2 cross-identity BOLA detection
- Rate limiting detection (header inspection, burst probe, Retry-After coverage, opt-in throttling checks on declared sensitive business flows)
- API inventory (sensitive endpoint exposure, stale version detection, SSRF surface detection, excessive data exposure, GraphQL introspection)
- Injection probes (SQL, NoSQL, template error-string detection; command injection with explicit opt-in), requires OpenAPI spec

**Infrastructure:**

- 📦 Typed, validated configuration (Zod schema, runtime validation)
- 🧱 Clean internal architecture (CLI → runner → suites → reporters)
- 📝 JSON + Markdown report output
- ☁️ S3 report upload for pipeline mode (env-var driven, additive)
- 🐳 Docker image for CI and Fargate sidecar use
- 🧪 Designed for testability and CI integration
- 🗂️ OpenAPI-driven endpoint selection with configurable scope
- ⚠️ Guardrails for active checks (timeouts, request caps, safe defaults)

---

## OWASP API Top 10 Coverage

Full finding ID registry: [`FINDINGS.md`](./FINDINGS.md)

| #          | Category                                        | Current Coverage                                                                                                                                                                                  |
| ---------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| API1:2023  | Broken Object Level Authorization               | **Auth suite** (Tier-2, requires ≥2 configured identities): cross-identity BOLA detection on object-level endpoints (`auth.bola_object_access`)                                                   |
| API2:2023  | Broken Authentication                           | **Auth suite**: 401 semantics, auth bypass heuristic, definitive invalid-token-accepted detection, cross-origin redirect risk, JWT inspection (alg:none, weak/stub signatures, missing exp, expired issuance, excessive TTL); **CORS suite**: wildcard + credentials |
| API3:2023  | Broken Object Property Level Authorization      | **Auth suite** (opt-in): mass assignment detection on writable object endpoints (`auth.mass_assignment_accepted`); **Inventory suite**: excessive data exposure on GET responses                 |
| API4:2023  | Unrestricted Resource Consumption               | **Rate limit suite**: header inspection, sequential burst probe, missing Retry-After detection                                                                                                    |
| API5:2023  | Broken Function Level Authorization             | Partial — auth suite detects unprotected endpoints (heuristic); no dedicated function-level authorization check                                                                                   |
| API6:2023  | Unrestricted Access to Sensitive Business Flows | **Rate limit suite**: throttling check on declared sensitive flows (`ratelimit.sensitive_flow_unthrottled`, requires `businessFlow.sensitivePaths`)                                               |
| API7:2023  | Server Side Request Forgery                     | **Inventory suite**: SSRF surface detection on URL-shaped parameters (`inventory.ssrf_surface`); opt-in active probing of write operations (`inventory.ssrfActiveProbe`)                          |
| API8:2023  | Security Misconfiguration                       | **Headers suite**: HSTS, X-Content-Type-Options, Referrer-Policy; **CORS suite**: misconfiguration; **Injection suite**: error disclosure, template/command injection signal detection            |
| API9:2023  | Improper Inventory Management                   | **Inventory suite**: sensitive endpoint exposure (/debug, /actuator, /swagger, etc.), stale version detection cross-referenced against OpenAPI spec, GraphQL introspection detection              |
| API10:2023 | Unsafe Consumption of APIs                      | —                                                                                                                                                                                                 |

---

## Quickstart

### Install globally from npm

```bash
npm install -g @uncommon-carp/sentinel
```

### Run a scan

```bash
sentinel scan -u https://api.example.com
```

Reports will be written to:

```
./sentinel-out/
  ├─ sentinel-report.json
  └─ sentinel-report.md
```

---

## Pipeline mode (Weir)

Sentinel runs as a container sidecar in [Weir](https://github.com/uncommon-carp/weir), an ephemeral DAST gate that provisions isolated Fargate tasks per pull request. When `RESULTS_BUCKET` and `RUN_ID` are set, Sentinel uploads its JSON report to S3 and exits — Weir reads the report and fails the PR check on high or critical findings.

To use Sentinel as a standalone container:

```bash
# Build from source
docker build -t sentinel .

# Run against a local target
docker run --rm \
  -e TARGET_URL=http://host.docker.internal:3000 \
  sentinel scan

# Pipeline mode — S3 upload
docker run --rm \
  -e TARGET_URL=http://host.docker.internal:3000 \
  -e RESULTS_BUCKET=my-bucket \
  -e RUN_ID=my-run \
  sentinel scan

# With a config file
docker run --rm \
  -v $(pwd)/sentinel.config.json:/app/sentinel.config.json \
  -e TARGET_URL=http://host.docker.internal:3000 \
  sentinel scan
```

See [Weir](https://github.com/uncommon-carp/weir) for the full pipeline setup.

---

## Run from source

```bash
git clone https://github.com/uncommon-carp/sentinel.git
cd sentinel
npm install
npm run build
node dist/cli/index.js scan -u https://api.example.com
```

---

## Usage

```bash
sentinel scan [options]
```

| Flag            | Description                                              |
| --------------- | -------------------------------------------------------- |
| `-u, --url`     | Base URL of the target API (or set `TARGET_URL` env var) |
| `-c, --config`  | Path to config file (default: `sentinel.config.json`)    |
| `--openapi`     | OpenAPI file path or URL for endpoint enumeration        |
| `-o, --out`     | Output directory. Falls back to `output.dir` in the config file, then `./sentinel-out` |
| `-v, --verbose` | Enable verbose logging. Falls back to `verbose` in the config file, then `false`        |

CLI flags override config file values; an omitted flag falls back to the config file, then the schema default. The `--openapi` flag is equivalent to setting `target.openapi` in the config file.

### Environment variables

| Variable         | Description                                                                                            |
| ---------------- | ------------------------------------------------------------------------------------------------------ |
| `TARGET_URL`     | Sets `target.baseUrl`. Equivalent to `-u`; the CLI flag takes precedence if both are provided.         |
| `RESULTS_BUCKET` | S3 bucket name for pipeline mode. Both `RESULTS_BUCKET` and `RUN_ID` must be set to trigger an upload. |
| `RUN_ID`         | Run identifier used as the S3 object key: `results/<RUN_ID>.json`.                                     |
| `AUTH_TOKEN_URL` | Sets `auth.tokenUrl` (creating a `primary` identity if none is configured). How the CI pipeline (Weir) supplies a target's token endpoint without a config file — see [Auth](#auth). |

When `RESULTS_BUCKET` and `RUN_ID` are both present, Sentinel uploads the JSON report to S3 after the scan using the task's IAM role — no credentials required. Local file output is unaffected. If only one of the two is set, a warning is logged and the upload is skipped.

---

## Configuration

Sentinel supports an optional `sentinel.config.json` file. All fields are optional except `target.baseUrl`.

Example:

```json
{
  "target": {
    "baseUrl": "https://api.example.com",
    "openapi": "./openapi.json"
  },
  "auth": {
    "identities": [
      { "name": "primary", "type": "bearer", "bearerToken": "${API_TOKEN}" }
    ],
    "probePaths": ["/me"],
    "compareUnauthed": true
  },
  "suites": {
    "headers": true,
    "cors": true,
    "auth": true
  },
  "active": {
    "maxRequestsPerSuite": 40,
    "timeoutMs": 8000
  },
  "scope": {
    "enabled": true,
    "methods": ["get", "head"],
    "maxEndpoints": 20,
    "includePaths": [],
    "excludePaths": ["^/admin", "^/internal"],
    "prefer": ["^/health", "^/status", "^/me"]
  },
  "injection": {
    "categories": ["sql", "template"],
    "paramTypes": ["query", "body"]
  },
  "output": {
    "dir": "./sentinel-out",
    "json": true,
    "markdown": true
  },
  "verbose": false
}
```

- Config is validated with a Zod schema at runtime.
- Secrets are sanitized before being written to reports.
- CLI flags override config file values.
- Environment variables can be interpolated using `"${VAR_NAME}"` syntax. The entire string value must be the placeholder — partial interpolation (e.g. `"Bearer ${TOKEN}"`) is not supported; use `type: "bearer"` with `bearerToken: "${TOKEN}"` instead.

### Auth

`auth.identities` is an ordered array of named credentials. `identities[0]` is
the primary/default session every suite uses; a second (or later) entry opts
into multi-identity checks (Tier-2 — cross-identity BOLA detection). An empty
or omitted `identities` array means unauthenticated (Tier-0).

| Option (per identity) | Description                                                                           |
| ---------------------- | --------------------------------------------------------------------------------------- |
| `name`                 | Identity label, must be unique across the array                                       |
| `type`                 | Auth scheme: `none`, `bearer`, `basic`, `apiKey` (default: `none`)                     |
| `bearerToken`          | Token value for `bearer` auth                                                          |
| `basicUser`            | Username for `basic` auth                                                              |
| `basicPass`            | Password for `basic` auth                                                              |
| `apiKeyHeader`         | Header name for `apiKey` auth (e.g. `x-api-key`)                                       |
| `apiKeyValue`          | Header value for `apiKey` auth                                                         |
| `tokenUrl`             | Endpoint to fetch a token from before scanning; the token is used as a bearer credential for all requests (Tier-1 dynamic auth). Overrides a statically-set `type`. |
| `tokenMethod`          | HTTP method for the token fetch: `GET` or `POST` (default: `GET`)                      |
| `tokenField`           | JSON field in the token response holding the token (default: `token`)                  |
| `tokenRequestHeaders`  | Static headers sent on the token fetch (e.g. a `content-type`, or a client secret). Redacted in reports. |
| `tokenRequestBody`     | Raw request body sent on the token fetch (for `POST` token endpoints). Redacted in reports. |

| Option (on `auth` itself) | Description                                                                        |
| --------------------------- | -------------------------------------------------------------------------------------- |
| `identities`                 | Array of named credentials, see above (default: `[]` — unauthenticated)               |
| `probePaths`                 | Endpoints used by the auth suite for probing (default: `["/"]`)                       |
| `compareUnauthed`            | Compare authed vs. unauthed responses to detect missing enforcement (default: `true`) |
| `massAssignmentProbe`        | Opt-in: also probe writable object endpoints for mass assignment (default: `false`) — sends a real write, see [`auth.mass_assignment_accepted`](./FINDINGS.md) |

The `AUTH_TOKEN_URL` environment variable maps to `auth.identities[0].tokenUrl`, creating a `primary` identity if none is configured (this is how the CI pipeline — Weir — supplies a target's token endpoint without Sentinel needing a config file). A fetch failure (unreachable endpoint, non-2xx, or a missing/non-string token field) is fatal: the scan exits with code `3` rather than silently scanning unauthenticated.

Dynamic-token example (fetch a bearer token from a login endpoint, then scan):

```json
{
  "target": { "baseUrl": "https://api.example.com" },
  "auth": {
    "identities": [
      {
        "name": "primary",
        "tokenUrl": "https://api.example.com/auth/login",
        "tokenMethod": "POST",
        "tokenField": "access_token",
        "tokenRequestHeaders": { "content-type": "application/json" },
        "tokenRequestBody": "${TOKEN_BODY}"
      }
    ],
    "probePaths": ["/me"]
  }
}
```

Note the whole-string `${VAR}` interpolation rule (above) applies to `tokenRequestBody` and `tokenRequestHeaders` values too: put the entire body in one env var (`TOKEN_BODY='{"user":"scanner","password":"..."}'`), not a partial placeholder like `"{\"password\":\"${SCAN_PASSWORD}\"}"` — that would be sent literally.

Multi-identity (Tier-2) example — a second identity enables cross-identity BOLA
detection (`auth.bola_object_access`) when an OpenAPI spec is loaded:

```json
{
  "auth": {
    "identities": [
      { "name": "userA", "type": "bearer", "bearerToken": "${USER_A_TOKEN}" },
      { "name": "userB", "type": "bearer", "bearerToken": "${USER_B_TOKEN}" }
    ]
  }
}
```

### Scope

When an OpenAPI spec is provided (`--openapi` or `target.openapi`), Scope controls which endpoints are tested:

| Option         | Description                                                             |
| -------------- | ----------------------------------------------------------------------- |
| `enabled`      | Enable scoped endpoint selection (default: `false`)                     |
| `methods`      | HTTP methods to include (default: `["get", "head"]`)                    |
| `maxEndpoints` | Cap on endpoints to test per suite (default: `20`)                      |
| `includePaths` | Regex patterns to include (empty = include all)                         |
| `excludePaths` | Regex patterns to exclude                                               |
| `prefer`       | Regex patterns for preferred endpoints — tested first (e.g. `^/health`) |

When scope is disabled or no OpenAPI spec is provided, suites fall back to probing `GET /`.

### Suites

The `suites` block enables or disables individual test suites. All suites are enabled by default except `injection`, which defaults to `false` and requires `--openapi` or `target.openapi` to run.

### Inventory

| Option           | Description                                                                                          |
| ----------------- | ----------------------------------------------------------------------------------------------------- |
| `ssrfActiveProbe` | Opt-in: also probe `POST`/`PUT`/`PATCH` operations and JSON body parameters for SSRF surface (default: `false`) — these requests may create or mutate resources on the target, see [`inventory.ssrf_surface`](./FINDINGS.md) |

By default the always-on inventory suite only probes `GET` query parameters for SSRF surface, since it must not send state-changing requests to the target.

### Injection

Requires an OpenAPI spec. When enabled, probes parameters extracted from the spec.

| Option       | Description                                                                                       |
| ------------ | ------------------------------------------------------------------------------------------------- |
| `categories` | Payload categories to use: `sql`, `nosql`, `template`, `command` (default: `["sql", "template"]`) |
| `paramTypes` | Parameter locations to probe: `query`, `body` (default: `["query", "body"]`)                      |

> **Note:** `command` injection probing must be explicitly added to `categories` — it is not enabled by default. All injection checks are output-based only; no time-based payloads are used.

### Business Flow (API6 groundwork)

Black-box path/name guessing can't reliably tell a sensitive business flow (checkout, coupon redemption, password reset) from an ordinary endpoint, so Sentinel doesn't try to guess — you declare which endpoints are sensitive flows explicitly, the same way `auth.probePaths` and `auth.identities` already ask you to tell Sentinel something the spec alone can't reveal.

| Option           | Description                                                                                          |
| ----------------- | ----------------------------------------------------------------------------------------------------- |
| `sensitivePaths` | Method+path pairs (e.g. `"POST /api/v2/coupons/redeem"`) or operationIds naming sensitive business-flow endpoints (default: `[]`) |

Empty or unset (the default) means no business-flow check runs at all.

```json
{
  "businessFlow": {
    "sensitivePaths": ["POST /api/v2/coupons/redeem"]
  }
}
```

### Rate Limiting

| Option       | Description                                                      |
| ------------ | ---------------------------------------------------------------- |
| `burstCount` | Number of sequential requests in the burst probe (default: `10`) |
| `delayMs`    | Delay in milliseconds between burst requests (default: `75`)     |

The burst is capped at `min(ratelimit.burstCount, active.maxRequestsPerSuite)`.

### Active

| Option                | Description                                                    |
| --------------------- | -------------------------------------------------------------- |
| `maxRequestsPerSuite` | Hard cap on requests any single suite may send (default: `40`) |
| `timeoutMs`           | Per-request timeout in milliseconds (default: `8000`)          |

---

## Architecture overview

```
CLI
 └─ config loader + validation (env vars: TARGET_URL, RESULTS_BUCKET, RUN_ID)
     └─ runner
         ├─ HTTP client wrapper
         ├─ security suites
         │    ├─ headers
         │    ├─ cors
         │    ├─ auth
         │    ├─ ratelimit
         │    ├─ inventory
         │    └─ injection
         └─ reporters
              ├─ JSON  (local file)
              ├─ Markdown  (local file)
              └─ S3  (pipeline mode, when RESULTS_BUCKET + RUN_ID are set)
```

- **Suites** are pluggable modules that return structured findings.
- **Runner** orchestrates suites and reporters.
- **Reporters** transform scan results into output formats.
- **HTTP client** centralizes request behavior, auth injection, and timeouts.

---

## Exit codes

| Code | Meaning                                                                             |
| ---- | ----------------------------------------------------------------------------------- |
| 0    | Scan completed, no high or critical findings                                        |
| 1    | Scan ran but one or more suites failed; report is partial                           |
| 2    | Scan completed, high or critical findings present                                   |
| 3    | Fatal error — invalid config, bad arguments, or unexpected crash before/during the scan |

Exit code precedence is `2 > 1 > 0`: high/critical findings take priority over partial-run signalling. Reporter failures — including a failed S3 upload in pipeline mode — are recorded in the report (`reporterErrors`) but do not change the exit code; findings computed by a completed scan still gate the pipeline correctly even if the upload itself failed.

---

## Safety and scope

Sentinel is designed to be non-destructive by default:

- Active checks are rate-limited and capped per suite
- Injection testing is disabled by default
- No state-changing requests are sent unless explicitly enabled
- Redirects are not followed

**Scanner scope:** Sentinel performs passive black-box surface scanning by default (Tier-0, no `auth.identities` configured). Configuring one identity opts into authenticated scanning (Tier-1 — definitive JWT/token enforcement probing, mass assignment); configuring two or more opts into multi-identity testing (Tier-2 — cross-identity BOLA detection, `auth.bola_object_access`). Function-level authorization (BFLA) has no dedicated check yet and remains out of scope regardless of tier.

Sentinel is intended for authorized testing only.
