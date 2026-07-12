# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [Unreleased]

### Changed

- **BREAKING: auth config is now a named-identities array.** The flat credential
  fields on `auth` (`type`, `bearerToken`, `basic*`, `apiKey*`, `tokenUrl`, and the
  `token*` knobs) have moved into `auth.identities: [{ name, …credentials }]`.
  `identities[0]` is the primary/default session every suite uses; additional
  entries are held as separate authenticated sessions for multi-identity checks
  (Tier-2 — BOLA/BFLA). `probePaths`/`compareUnauthed` stay at the `auth` level.
  Migrate `auth: { type: 'bearer', bearerToken: 'x' }` to
  `auth: { identities: [{ name: 'primary', type: 'bearer', bearerToken: 'x' }] }`.
  The `AUTH_TOKEN_URL` env var (Weir pipeline contract) is unchanged in behavior —
  it now maps to `identities[0].tokenUrl`, creating a `primary` identity if none is
  configured. Duplicate identity names are rejected.

### Fixed

- **A failed S3 report upload (pipeline mode) no longer crashes an otherwise-complete
  scan.** `uploadReportToS3` was called directly from `scanCommand` with no error
  isolation, unlike the json/markdown reporters, which are already wrapped by
  `runScan` so a failure lands in `reporterErrors` instead of throwing. A transient
  S3 error (throttling, a momentary network blip) on a scan that had already run to
  completion would propagate all the way to the top-level CLI handler and exit code
  3 ("fatal pre-scan error") — indistinguishable from a genuinely broken config, even
  though findings were computed correctly and a local report exists on disk. The
  upload is now wrapped the same way (new `uploadPipelineReport` helper in
  `cli/commands/scan.ts`): a failure is logged and recorded in
  `result.reporterErrors` (`{ reporter: 's3', message, stack? }`), and no longer
  affects the scan's exit code.

- **`output.dir` and `verbose` in the config file are now honored.** The `scan`
  command gave `--out` and `--verbose` hardcoded commander defaults
  (`./sentinel-out` / `false`), so those options were never absent and always
  shadowed the config file — a `sentinel.config.json` setting `output.dir` or
  `verbose` had no effect unless the matching flag was also passed. The defaults
  were removed; an omitted flag now falls back to the config value (and, failing
  that, the schema default `./sentinel-out` / `false`), while an explicit flag
  still overrides. No change when neither flag nor config sets them.

### Added

- **`auth.bola_object_access` (OWASP API1 — first BOLA coverage)**: when two or more
  identities are configured (`auth.identities`, Tier-2) and an OpenAPI spec is loaded,
  the auth suite discovers object-level endpoints (GET paths keyed by a single
  enumerable/integer id, e.g. `/users/{id}`) and probes each candidate id with every
  identity plus one unauthenticated request. A resource returned byte-identically to
  two or more distinct identities while the unauthenticated request is rejected is
  flagged as broken object-level authorization. GET-only and non-mutating; evidence
  omits response bodies so the leaked sensitive fields aren't copied into the report.
- **Tier-2 multi-identity sessions**: each configured identity is resolved (static
  or `tokenUrl`) into its own `HttpClient` session and exposed to suites on
  `ctx.identities` (`[{ name, http }]`), so a check can hold two authenticated
  identities at once — the foundation for the BOLA probe. Resolved tokens for every
  identity are redacted in the report's sanitized config.

- **Dynamic token auth (`auth.tokenUrl`)**: Sentinel can fetch a bearer token from an endpoint before scanning and use it for all authenticated requests, instead of requiring a static `bearerToken`. Configurable via `tokenMethod` (`GET`/`POST`, default `GET`), `tokenField` (JSON field holding the token, default `token`), and optional `tokenRequestHeaders` / `tokenRequestBody` for token endpoints that need a POST with a client secret. Enables Tier-1 authenticated scanning without credentials leaving the scanner.
- **`AUTH_TOKEN_URL` env var**: Maps to `auth.tokenUrl` (env wins over config file), mirroring `TARGET_URL`. This is how the CI pipeline supplies a target's token endpoint without a config file, keeping the orchestrator credential-free.
- **`inventory.ssrf_surface` finding (API7)**: When an OpenAPI spec is loaded, the inventory suite now finds query parameters that accept a URL (by name — `url`/`uri`/`callback`/`webhook`/`redirect`/… — or `format: uri`) and probes each with a benign non-resolving URL (`http://ssrf-probe.sentinel.invalid/`). Parameters the server accepts without a validation/rejection signal are flagged as SSRF surface (medium). Sentinel's first OWASP API7 coverage; surface detection only (confirms acceptance, not an actual fetch). Registered in `FINDINGS.md`.
- **`inventory.ssrfActiveProbe` config (opt-in active SSRF probing)**: Default `false` keeps the SSRF check to `GET` query parameters only (the always-on inventory suite must not issue state-changing requests). Setting it `true` widens the same check to `POST`/`PUT`/`PATCH` operations and JSON body parameters — the common webhook / resource-creation SSRF vector — with `method` and `paramType` recorded in the finding evidence.
- **`auth.jwt_weak_signature` finding**: The auth suite now inspects the signature of every non-`none` JWT it observes and flags tokens whose signature decodes to fewer than 32 bytes — shorter than the minimum any standard algorithm (HS256) produces, i.e. a stub or placeholder rather than a real cryptographic signature. High severity; catches trivially forgeable tokens that `auth.jwt_alg_none` misses because the algorithm is not `none`. Registered in `FINDINGS.md`.
- **`auth.invalid_token_accepted` finding (Tier-1)**: The auth suite's enforcement probe is now three-way — it compares a protected endpoint's response to a valid credential, a deliberately invalid one (a token with a broken signature), and no credential. When the endpoint rejects the no-credential request but accepts the invalid one, it checks token presence rather than validity, and this high-severity finding is emitted. Unlike `auth.possible_bypass_probe` it is definitive, not heuristic — a genuinely public route would also serve the no-credential request. Registered in `FINDINGS.md`.

### Security

- Token-endpoint request material (`tokenRequestHeaders`, `tokenRequestBody`) and the resolved bearer token are redacted in the report's sanitized config. `tokenUrl` itself is left visible (it is not a secret).

### Changed

- A configured `tokenUrl` that fails to resolve (unreachable endpoint, non-2xx response, or a missing/non-string token field) is a **fatal pre-scan error (exit code 3)**, rather than silently scanning unauthenticated — an unauthenticated scan of an endpoint that was supposed to be authenticated produces misleading auth findings.
- **`auth.possible_bypass_probe` evidence** now includes `invalidStatus` alongside `authedStatus`/`unauthedStatus`, reflecting the new three-way enforcement probe. The finding's trigger (success both with and without any credential) is unchanged; the fully-open case is reported here and not double-counted as `auth.invalid_token_accepted`.

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
