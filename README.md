# Sentinel

Sentinel is a CLI-based API security scanner written in TypeScript. It runs a curated set of **passive** and **controlled active** checks against HTTP APIs and produces **structured JSON** and **human-readable Markdown** reports.

The goal is to provide a fast, repeatable first-pass security signal for backend teams — locally during development or automatically in CI.

---

## Features

**Implemented suites:**
- HTTP security headers (HSTS, X-Content-Type-Options, Referrer-Policy)
- CORS misconfiguration detection (wildcard + credentials, origin reflection)
- Auth behavior (401 + WWW-Authenticate semantics, cross-origin redirect detection, auth enforcement heuristics)

**Planned suites:**
- Rate limiting detection
- Injection probes

**Infrastructure:**
- 📦 Typed, validated configuration (Zod schema, runtime validation)
- 🧱 Clean internal architecture (CLI → runner → suites → reporters)
- 📝 JSON + Markdown report output
- 🧪 Designed for testability and CI integration
- 🗂️ OpenAPI-driven endpoint selection with configurable scope
- ⚠️ Guardrails for active checks (timeouts, request caps, safe defaults)

---

## OWASP API Top 10 Coverage

| # | Category | Current Coverage | Planned |
|---|----------|-----------------|---------|
| API1:2023 | Broken Object Level Authorization | — | Injection/fuzzing probes |
| API2:2023 | Broken Authentication | **Auth suite**: 401 semantics, auth bypass heuristic, cross-origin redirect risk; **CORS suite**: wildcard + credentials | Broader auth scheme coverage |
| API3:2023 | Broken Object Property Level Authorization | — | Response body analysis |
| API4:2023 | Unrestricted Resource Consumption | — | Rate limiting suite |
| API5:2023 | Broken Function Level Authorization | Partial — auth suite detects unprotected endpoints (heuristic) | Method-level fuzzing |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | — | Out of scope (requires business context) |
| API7:2023 | Server Side Request Forgery | — | Injection probes |
| API8:2023 | Security Misconfiguration | **Headers suite**: HSTS, X-Content-Type-Options, Referrer-Policy; **CORS suite**: misconfiguration detection | Additional header/TLS checks |
| API9:2023 | Improper Inventory Management | Partial — OpenAPI-driven scanning surfaces the intended API surface | Spec drift detection |
| API10:2023 | Unsafe Consumption of APIs | — | Out of scope (outbound traffic analysis) |

---

## Quickstart

### Install globally from NPM

```bash
npm install -g @uncommon-carp/sentinel
```

### Run a scan

```bash
sentinel scan -u https://example.com
```

Reports will be written to:

```
./sentinel-out/
  ├─ sentinel-report.json
  └─ sentinel-report.md
```

## Run From Source

### Clone the repo and install dependencies

```bash
git clone https://github.com/uncommon-carp/sentinel.git
cd sentinel
npm install
```

### Build the project

```bash
npm run build
```

### Run a scan

```bash
node dist/cli/index.js scan -u https://example.com
```

---

## Usage

```bash
sentinel scan -u <baseUrl> [options]
```

| Flag            | Description                                        |
| --------------- | -------------------------------------------------- |
| `-u, --url`     | Base URL of the target API (required)              |
| `-c, --config`  | Path to config file (default: `sentinel.config.json`) |
| `--openapi`     | OpenAPI file path or URL for endpoint enumeration  |
| `-o, --out`     | Output directory (default: `./sentinel-out`)       |
| `-v, --verbose` | Enable verbose logging                             |

CLI flags override values from the config file. The `--openapi` flag is equivalent to setting `target.openapi` in the config file.

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
    "type": "bearer",
    "bearerToken": "${API_TOKEN}",
    "probePath": "/me",
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

| Option           | Description                                                                    |
| ---------------- | ------------------------------------------------------------------------------ |
| `type`           | Auth scheme: `none`, `bearer`, `apiKey` (default: `none`)                     |
| `bearerToken`    | Token value for `bearer` auth                                                  |
| `apiKeyHeader`   | Header name for `apiKey` auth (e.g. `x-api-key`)                              |
| `apiKeyValue`    | Header value for `apiKey` auth                                                 |
| `probePath`      | Endpoint used by the auth suite for probing (default: `/`)                     |
| `compareUnauthed`| Compare authed vs. unauthed responses to detect missing enforcement (default: `true`) |

> **Note:** `basic` auth (`basicUser` / `basicPass`) is accepted by the config schema but header injection is not yet implemented.

### Scope

When an OpenAPI spec is provided (`--openapi` or `target.openapi`), Scope controls which endpoints are tested:

| Option         | Description                                                              |
| -------------- | ------------------------------------------------------------------------ |
| `enabled`      | Enable scoped endpoint selection (default: `false`)                      |
| `methods`      | HTTP methods to include (default: `["get", "head"]`)                     |
| `maxEndpoints` | Cap on endpoints to test per suite (default: `20`)                       |
| `includePaths` | Regex patterns to include (empty = include all)                          |
| `excludePaths` | Regex patterns to exclude                                                |
| `prefer`       | Regex patterns for preferred endpoints — tested first (e.g. `^/health`)  |

When scope is disabled or no OpenAPI spec is provided, suites fall back to probing `GET /`.

### Suites

The `suites` block enables or disables individual test suites. Only `headers`, `cors`, and `auth` have active implementations. The `ratelimit` and `injection` keys are accepted by the config parser but are no-ops pending suite implementation.

---

## Architecture Overview

```
CLI
 └─ config loader + validation
     └─ runner
         ├─ HTTP client wrapper
         ├─ security suites
         │    ├─ headers
         │    ├─ cors
         │    └─ auth
         └─ reporters
              ├─ JSON
              └─ Markdown
```

### Key Concepts

- Suites are pluggable modules that return structured findings.
- Runner orchestrates suites and reporters.
- Reporters transform scan results into output formats.
- HTTP client centralizes request behavior, auth injection, and timeouts.

---

## Exit Codes

| Code | Meaning                            |
| ---- | ---------------------------------- |
| `0`  | No high or critical findings       |
| `2`  | One or more high/critical findings |
| `1`  | Execution or configuration error   |

This makes Sentinel easy to integrate into CI pipelines.

---

## Safety and Scope

Sentinel is designed to be non-destructive by default:

- Active checks are rate-limited and capped per suite
- Injection testing is disabled by default
- No state-changing requests are sent unless explicitly enabled
- Redirects are not followed

It is intended for authorized testing only.
