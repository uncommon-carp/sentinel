# Sentinel

Sentinel is a CLI-based API security scanner written in TypeScript. It runs a curated set of **passive** and **controlled active** checks against HTTP APIs and produces **structured JSON** and **human-readable Markdown** reports.

The goal is to provide a fast, repeatable first-pass security signal for backend teams — locally during development or automatically in CI.

---

## Features

- 🔍 Modular security test suites
  - HTTP security headers
  - CORS misconfiguration detection
  - Auth behavior (401 semantics, cross-origin redirects, enforcement heuristics)
  - (Planned) Rate limiting, injection probes
- 📦 Typed, validated configuration
- 🧱 Clean internal architecture (CLI → runner → suites → reporters)
- 📝 JSON + Markdown report output
- 🧪 Designed for testability and CI integration
- ⚠️ Guardrails for active checks (timeouts, request caps, safe defaults)

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

```pgsql
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

| Flag            | Description                                  |
| --------------- | -------------------------------------------- |
| `-u, --url`     | Base URL of the target API (required)        |
| `-c, --config`  | Path to `sentinel.config.json`               |
| `--openapi`     | OpenAPI file path or URL (planned usage)     |
| `-o, --out`     | Output directory (default: `./sentinel-out`) |
| `-v, --verbose` | Enable verbose logging                       |

---

## Configuration

Sentinel supports an optional `sentinel.config.json` file.

Example:

```json
{
  "target": {
    "baseUrl": "https://api.example.com"
  },
  "auth": {
    "type": "none"
  },
  "suites": {
    "headers": true,
    "cors": true,
    "auth": true,
    "ratelimit": true,
    "injection": false
  },
  "active": {
    "enabled": true,
    "maxRequestsPerSuite": 40,
    "timeoutMs": 8000
  },
  "scope": {
    "enabled": true,
    "methods": ["get", "head"],
    "maxEndpoints": 20,
    "includePaths": [],
    "excludePaths": ["/admin", "/internal"],
    "prefer": ["/health", "/status", "/ping"]
  },
  "output": {
    "dir": "./sentinel-out",
    "json": true,
    "markdown": true
  },
  "verbose": false
}
```

- Config is validated with a schema at runtime.
- Secrets are sanitized before being written to reports.
- CLI flags override config file values.
- Environment variables can be interpolated using `${VAR}` syntax.

### Scope

When an OpenAPI spec is provided (`--openapi`), Scope controls which endpoints are tested:

| Option         | Description                                           |
| -------------- | ----------------------------------------------------- |
| `enabled`      | Enable scoped endpoint selection (default: false)     |
| `methods`      | HTTP methods to include (default: `["get", "head"]`)  |
| `maxEndpoints` | Cap on endpoints to test per suite (default: 20)      |
| `includePaths` | Regex patterns to include (empty = include all)       |
| `excludePaths` | Regex patterns to exclude                             |
| `prefer`       | Regex patterns for preferred endpoints (tested first) |

When disabled or no OpenAPI spec is available, suites fall back to probing `GET /`.

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
  This design keeps Sentinel extensible, testable, and suitable for real-world use

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

- Active checks are rate-limited and capped
- Injection testing is disabled by default
- No state-changing requests are sent unless explicitly enabled

It is intended for authorized testing only.
