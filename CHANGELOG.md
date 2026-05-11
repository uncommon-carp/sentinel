# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [Unreleased]

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
