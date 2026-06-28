# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [Unreleased]

## [0.4.0] — 2026-06-27

### Added

- **S3 report upload (pipeline / Fargate mode)**: When `RESULTS_BUCKET` and `RUN_ID` are both set, Sentinel uploads its JSON report to `s3://<RESULTS_BUCKET>/results/<RUN_ID>.json` after the scan completes, using the task's IAM role. Upload failure exits nonzero so a broken upload gates the pipeline. Local file output is unaffected — S3 is purely additive.
- **`TARGET_URL` env var**: Sets `target.baseUrl` from the environment, equivalent to `-u`. The CLI flag still wins if both are provided, making `-u` optional when running as a sidecar container.
- **Partial pipeline config warning**: If only one of `RESULTS_BUCKET` / `RUN_ID` is set, Sentinel logs a warning and skips the upload rather than failing — a misconfigured sidecar shouldn't silently suppress the exit code.
- **Dockerfile**: Sentinel ships as a container image for use as a Fargate sidecar or standalone pipeline component. See README for usage.
- **`FINDINGS.md`**: Canonical finding ID registry — all emitted IDs, severities, OWASP mappings, and remediation guidance in one place. Downstream repos (Anemone, Weir) reference this as the source of truth.

### Fixed

- **JWT finding ID prefixes**: `jwt.alg_none`, `jwt.long_ttl`, and `jwt.missing_exp` corrected to `auth.jwt_alg_none`, `auth.jwt_long_ttl`, and `auth.jwt_missing_exp` throughout. Consumers relying on the old prefixes will need to update.
- **S3 client endpoint handling**: `AWS_ENDPOINT_URL` and `forcePathStyle` are now conditionally applied only when the env var is present. Previously an empty-string endpoint was passed to the SDK in production, breaking real S3 URL construction.

## [0.3.2] - 2026-06-22

### Added

- **Per-suite error handling**: The runner now catches and surfaces errors within suite runs, instead of early-outing with no indications.
- **Top level error handling**: The command now more effectively surfaces scan errors outside of suites, including in the reporters, which
  now have their own field on RunResult
- **Expanded Zod validation error messaging**: Config errors are now better surfaced and more readable
- **OpenAPI spec error handling**: OpenAPI spec errors are handled more gracefully, defaulting to specless runs in the absence of a spec
  or if a spec is broken

### Removed

- **Vulnerable API fixture**: The API testing fixture has been removed to become its own project. @uncommon-carp/anemone

## [0.3.1] - 2026-06-18

### Added

- **Verbose mode** (`--verbose`): suite execution flow, HTTP request/response detail, endpoint selection decisions, and per-payload injection probing are now logged via `logger.debug()`. Each debug entry includes a namespaced `event` field for log filtering/aggregation (e.g. `http.request`, `injection.hit`, `ratelimit.burst.throttled`).
  - Non-verbose output reduced to scan lifecycle signal only — suite start/finish narration and report output paths moved from `info` to `debug`
  - Injection suite logs a truncated response snippet (200 chars) on confirmed hits only, never on payload misses
  - New test coverage for `core/logger.ts` (verbose gating, structured data serialization)

### Fixed

- **Missing basic auth wiring**: `basic` is a configurable option but was not wired to anything in the scanner. It's now a fully operational option, with added tests
  for authHeader construction.

- **Test helper drift**: Removed a local definition of `makeConfig()` from `core.endpoints.test.ts` in favor of an expansion on the `makeConfig()` helper, allowing it
  to accept config overrides.

## [0.3.0] - 2026-06-12

### Added

- **Injection suite** (`src/suites/injection.ts`): probes OpenAPI-defined query and body parameters for SQL error disclosure, NoSQL error disclosure, template injection (expression evaluation), and command injection signals. Requires an OpenAPI spec; skips with a logged message if none is provided. Maps to OWASP API8.
  - Defaults to `["sql", "template"]` categories; `command` requires explicit opt-in
  - Defaults to probing both `query` and `body` parameter types
  - Early-out per parameter on first confirmed hit; hard cap via `maxRequestsPerSuite`

- **Review workflow** (`.github/workflows/review.yml`): linting, formatting, and usage checks

## [0.2.2] - 2026-05-11

### Changed

- **Publish workflow** (`.github/workflows/publish.yml`): automated npm publish and GitHub Release creation on version tag push (`v*`). Uses npm OIDC trusted publishing — no stored access token required.

## [0.2.1] - 2026-05-11

### Changed

- **Suite registry refactor**: `buildSuites` now accepts `config.suites` directly instead of a parallel named-boolean object. Adding a new suite requires touching one file (`suites/index.ts`) rather than four. `REGISTRY` uses `Record<SuiteName, ...>` so TypeScript errors if a schema suite key has no factory.
- **Removed phantom `injection` suite config**: `injection` was declared in the config schema but had no factory and silently did nothing. Removed until the suite exists.
- **`resolveEndpoints` helper** (`core/endpoints.ts`): extracts the shared "use selectedEndpoints or fall back to GET /" logic that was duplicated across the CORS, headers, and rate limit suites.
- **Removed dead config fallbacks**: all suites were applying `?? 20` / `Math.max(1, ...)` guards to `maxRequestsPerSuite`, and the rate limit suite had similar guards on `burstCount` and `delayMs`. The Zod schema already enforces these bounds; the fallbacks are removed.

## [0.2.0] - 2026-05-11

### Added

- **Auth suite – JWT inspection**: responses are scanned for JWTs in headers and body; findings cover `alg:none`, missing `exp` claim, already-expired issuance, and long TTL (>24h). Maps to OWASP API2.
- **Rate limit suite**: header inspection across selected endpoints and a sequential burst probe; flags missing 429, missing `Retry-After`, and absence of standard rate-limit headers. Maps to OWASP API4.
- **Inventory suite**: probes for sensitive endpoint exposure (`/debug`, `/swagger`, `/openapi.json`, etc.), GraphQL introspection, and stale API version endpoints cross-referenced against the loaded OpenAPI spec. Maps to OWASP API9.
- **Report polish**: Markdown report now includes a severity summary table with total, OWASP coverage table, and per-finding sections with description, "why it matters" explanation, and remediation. JSON report includes `owasp` and `whyItMatters` fields on each finding.
- **Vulnerable API fixture** (`examples/vulnerable-api/`): deliberately misconfigured Express server for development testing, with all misconfigurations individually toggled via environment variables.

### Fixed

- `suites` field in JSON report no longer appears as an empty object when suite flags are not explicitly set in config.

## [0.1.1] - 2026-01-28

### Fixed

- NPM name and documentation errors

## [0.1.0] - 2026-01-27

### Added

- CLI scan command, config loader, HTTP client, suite framework, JSON/Markdown reporters.
- Scope-based endpoint selection for multi-endpoint probing.
- OpenAPI loader (file/URL) with dereferencing and endpoint extraction.
- Config env interpolation (`${VAR}`) for secrets.
- Suites: headers, CORS, auth.
- Test suite with deterministic HTTP mocking.
- Architecture documentation.
