# Sentinel Finding IDs — Source of Truth

All finding IDs emitted by Sentinel. Each entry is stable — downstream repos (anemone, weir) reference these IDs directly.

Severities: `critical` › `high` › `medium` › `low` › `info`

---

## auth

Checks HTTP auth semantics and basic auth enforcement behavior. Probes configurable `auth.probePaths` (default `["/"]`). With two or more configured identities (`auth.identities`, Tier-2) it also runs a cross-identity BOLA probe against object-level endpoints discovered from the OpenAPI spec.

| ID                                  | Severity | Title                                                   | OWASP                       |
| ----------------------------------- | -------- | ------------------------------------------------------- | --------------------------- |
| `auth.jwt_alg_none`                 | critical | JWT with alg:none detected in response                  | API2: Broken Authentication |
| `auth.bola_object_access`           | high     | Object-level endpoint served the same resource to multiple identities | API1: Broken Object Level Authorization |
| `auth.invalid_token_accepted`       | high     | Protected endpoint accepted an invalid token            | API2: Broken Authentication |
| `auth.jwt_weak_signature`           | high     | JWT with a weak or stub signature detected in response  | API2: Broken Authentication |
| `auth.jwt_expired_accepted`         | high     | Server issued an already-expired JWT                    | API2: Broken Authentication |
| `auth.jwt_missing_exp`              | medium   | JWT with no expiration claim (exp) detected in response | API2: Broken Authentication |
| `auth.redirect_cross_origin`        | medium   | Cross-origin redirect observed on auth probe            | API2: Broken Authentication |
| `auth.possible_bypass_probe`        | medium   | Auth probe succeeded with and without credentials       | API2: Broken Authentication |
| `auth.jwt_long_ttl`                 | low      | JWT with unusually long TTL detected in response        | API2: Broken Authentication |
| `auth.401_missing_www_authenticate` | low      | 401 response missing WWW-Authenticate header            | API2: Broken Authentication |

### Finding details

#### `auth.jwt_alg_none` — critical

A JWT using the `alg:none` algorithm was found in a response. Tokens with `alg:none` carry no cryptographic signature; servers that accept them can be trivially bypassed. An attacker can forge arbitrary JWT claims — including elevated roles — and gain unauthorized access with no cryptographic barrier.  
**Remediation:** Reject JWTs with `alg:none` server-side and enforce an explicit algorithm allowlist.

#### `auth.bola_object_access` — high

An object-level endpoint (a GET path keyed by a single enumerable resource id, e.g. `/users/{id}`, discovered from the OpenAPI spec) returned a byte-identical resource to two or more distinct authenticated identities while rejecting the unauthenticated request. The endpoint authenticates the caller but never checks that the caller is authorized for the *specific* object, so any authenticated identity can read another identity's records by enumerating the id (BOLA / IDOR — OWASP API1). The unauthenticated request being rejected is what separates this from a fully public route (`auth.possible_bypass_probe`): auth is present, but object-level authorization is missing.  
**Remediation:** Enforce object-level authorization on every request — verify the authenticated identity may access the specific object before returning it, not just that the caller is authenticated. Use non-enumerable identifiers as defense-in-depth.

**Requires** at least two configured identities (`auth.identities`, Tier-2) so the probe can compare cross-identity access, and an OpenAPI spec advertising the object endpoint. v1 covers integer/number path ids only; opaque/UUID ids are not yet synthesized. Evidence omits the response bodies on purpose — the leaked records carry the sensitive fields (emails, API keys) the finding is about.

#### `auth.invalid_token_accepted` — high

A protected probe path returned success for a structurally invalid credential (a token with a broken signature) while rejecting the request with no credential at all. The endpoint checks that a token is present but never validates it, so any token-shaped value is accepted — a full authentication bypass with a trivially forgeable credential. Unlike `auth.possible_bypass_probe` this is definitive rather than heuristic: a genuinely public route would also serve the no-credential request, whereas here the no-credential request is rejected.  
**Remediation:** Validate the token server-side (signature, issuer, and expiry) on every protected endpoint, not just the presence of an `Authorization` header. Requires a configured credential (`auth.tokenUrl` or a static `bearer`/`basic`/`apiKey`) so the probe has a valid token to contrast against.

#### `auth.jwt_weak_signature` — high

A JWT whose algorithm is not `none` but whose signature decodes to fewer than 32 bytes — the minimum any standard JWS algorithm (HS256) produces — was found in a response. Such a signature is consistent with a stub or placeholder rather than a real cryptographic one, so the token is effectively unsigned: an attacker who knows or guesses the placeholder can forge arbitrary claims even though the algorithm is not `none`.  
**Remediation:** Sign tokens with a real secret or key using a standard algorithm, never a constant/placeholder signature. Enforce an algorithm allowlist and verify signatures server-side.

#### `auth.jwt_expired_accepted` — high

A JWT with an `exp` claim in the past was present in a successful (2xx) response. If the server issues or accepts expired tokens, expiry-based revocation is not enforced.  
**Remediation:** Validate JWT expiry server-side and ensure issued tokens have `exp` set in the future.

**Note**: Sentinel checks whether the issued token already has an expired exp claim, not whether the server accepts an expired token presented by a client. The latter requires an authenticated resend probe and is out of scope for Tier-0.

#### `auth.jwt_missing_exp` — medium

A JWT without an `exp` claim was found in a response. Non-expiring tokens cannot be automatically invalidated and remain valid indefinitely if leaked.  
**Remediation:** Always include an `exp` claim in issued JWTs and reject tokens that lack one on the server side.

#### `auth.redirect_cross_origin` — medium

Auth probe returned a redirect to a different origin. Some HTTP clients forward `Authorization` headers on redirects without checking the destination origin, silently exfiltrating credentials.  
**Remediation:** Avoid redirecting authenticated endpoints across origins, or ensure clients do not forward credentials across origins.

#### `auth.possible_bypass_probe` — medium

The configured auth probe endpoint returned success both with configured credentials and with credentials cleared, suggesting the endpoint may not enforce authentication. The enforcement probe is three-way — it compares a valid credential, a deliberately invalid one, and no credential; this finding covers the "succeeds with no credential" case (no auth enforced at all), while the "rejects no credential but accepts an invalid one" case is reported separately and definitively as `auth.invalid_token_accepted`.  
**Remediation:** Verify the probe path points to a protected endpoint and ensure auth is enforced server-side. This is a heuristic — false positives occur when `auth.probePaths` includes unprotected routes.

#### `auth.jwt_long_ttl` — low

A JWT valid for more than 24 h was found in a response. Long-lived access tokens extend the window of opportunity if a token is compromised.  
**Remediation:** Issue short-lived access tokens (ideally ≤1 h) and use refresh tokens for long-lived sessions.

#### `auth.401_missing_www_authenticate` — low

Endpoint returned 401 Unauthorized but did not include a `WWW-Authenticate` header, obscuring the intended auth scheme from spec-compliant clients.  
**Remediation:** Return a `WWW-Authenticate` header on 401 responses (e.g. `Bearer realm=...`).

---

## cors

Performs basic CORS misconfiguration checks by sending a GET with a synthetic `Origin` header to selected endpoints.

| ID                               | Severity | Title                                        | OWASP                           |
| -------------------------------- | -------- | -------------------------------------------- | ------------------------------- |
| `cors.wildcard_with_credentials` | high     | CORS allows credentials with wildcard origin | API8: Security Misconfiguration |
| `cors.origin_reflection`         | medium   | CORS reflects arbitrary Origin               | API8: Security Misconfiguration |

### Finding details

#### `cors.wildcard_with_credentials` — high

`Access-Control-Allow-Origin` is `*` while `Access-Control-Allow-Credentials` is `true`. Any website can make credentialed cross-origin requests to this API on behalf of a logged-in user.  
**Remediation:** Do not use wildcard ACAO with credentials. Reflect only trusted origins.

#### `cors.origin_reflection` — medium

The server reflected the `Origin` header value back in `Access-Control-Allow-Origin`. Combined with user credentials, this allows malicious sites to make authenticated API calls on behalf of a victim.  
**Remediation:** Validate `Origin` against an explicit allowlist; avoid reflecting arbitrary origins.

---

## headers

Checks for baseline HTTP security headers across selected endpoints. Multiple affected endpoints are collapsed into one finding per missing header.

| ID                                | Severity | Title                                    | OWASP                           |
| --------------------------------- | -------- | ---------------------------------------- | ------------------------------- |
| `headers.missing_hsts`            | medium   | Missing Strict-Transport-Security (HSTS) | API8: Security Misconfiguration |
| `headers.missing_xcto`            | low      | Missing X-Content-Type-Options           | API8: Security Misconfiguration |
| `headers.missing_referrer_policy` | low      | Missing Referrer-Policy                  | API8: Security Misconfiguration |

### Finding details

#### `headers.missing_hsts` — medium

`Strict-Transport-Security` header absent. Without HSTS, browsers may connect over plain HTTP on subsequent visits, enabling downgrade attacks that allow credential and session token interception on the local network.  
**Remediation:** Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses.

#### `headers.missing_xcto` — low

`X-Content-Type-Options` header absent. MIME sniffing can cause browsers to interpret non-HTML API responses as executable content.  
**Remediation:** Add `X-Content-Type-Options: nosniff`.

#### `headers.missing_referrer_policy` — low

`Referrer-Policy` header absent. Without it, sensitive data in URL paths — tokens, IDs, search terms — can be silently leaked to third-party domains via the `Referer` header.  
**Remediation:** Add `Referrer-Policy: no-referrer` or `strict-origin-when-cross-origin`.

---

## injection

Probes API query and body parameters for injection signals using error-string and output-based detection. Requires an OpenAPI spec (`--openapi`). One finding per parameter per category — no stacking. No time-based payloads.

| ID                                      | Severity | Title                                             | OWASP           |
| --------------------------------------- | -------- | ------------------------------------------------- | --------------- |
| `injection.possible_command_injection`  | critical | Possible command injection detected               | API3: Injection |
| `injection.sql_error_disclosure`        | high     | SQL injection error string detected in response   | API3: Injection |
| `injection.nosql_error_disclosure`      | high     | NoSQL injection error string detected in response | API3: Injection |
| `injection.possible_template_injection` | high     | Possible template injection detected              | API3: Injection |

### Finding details

#### `injection.possible_command_injection` — critical

A command injection payload (`;echo sentinel9` / backtick form) was reflected in the response, suggesting server-side shell execution. This typically leads to full system compromise.  
**Remediation:** Never pass user input directly to shell commands. Use allowlisted values or parameterized APIs that do not invoke the shell. Requires `command` in `injection.categories` config.

#### `injection.sql_error_disclosure` — high

A SQL injection payload produced a response containing SQL error strings (e.g. `sql syntax`, `ORA-`, `pg_query`). Confirms an exploitable injection point and reveals internal database details.  
**Remediation:** Use parameterized queries or prepared statements. Never surface raw database errors to clients.

#### `injection.nosql_error_disclosure` — high

A NoSQL injection payload produced a response containing NoSQL error strings (e.g. `mongo`, `$where`, `bson`). Confirms an exploitable injection point and reveals internal database details.  
**Remediation:** Sanitize and validate all user input. Never expose raw database errors to clients.

#### `injection.possible_template_injection` — high

A template expression payload (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`) produced output containing `49`, consistent with server-side expression evaluation. Can allow arbitrary code execution via the template engine.  
**Remediation:** Sanitize all user input before passing it to template engines. Use sandboxed evaluation or disable expression processing.

---

## inventory

Probes common API paths for sensitive endpoint exposure, GraphQL introspection, and stale version endpoints. Primarily OWASP API9; the SSRF surface check maps to API7. Multiple paths triggering the same class of issue are collapsed into one finding.

| ID                                        | Severity | Title                                             | OWASP                               |
| ----------------------------------------- | -------- | ------------------------------------------------- | ----------------------------------- |
| `inventory.sensitive_endpoint_exposed`    | medium   | Sensitive endpoint(s) responding with 2xx         | API9: Improper Inventory Management |
| `inventory.stale_version_responding`      | medium   | Deprecated API version endpoint is responding     | API9: Improper Inventory Management |
| `inventory.ssrf_surface`                  | medium   | Parameter(s) accept an external URL without validation | API7: Server Side Request Forgery |
| `inventory.graphql_introspection_enabled` | low      | GraphQL introspection is enabled                  | API9: Improper Inventory Management |

### Finding details

#### `inventory.sensitive_endpoint_exposed` — medium

One or more of `/swagger`, `/openapi.json`, `/api-docs`, `/graphql`, `/debug`, `/actuator`, `/metrics` returned a 2xx response. Debug, admin, and documentation endpoints reveal internal API structure that attackers use to map attack surface.  
**Remediation:** Disable or restrict access to these endpoints in production. If public docs are intentional, verify the spec does not expose sensitive implementation details.

#### `inventory.stale_version_responding` — medium

The API spec declares a current version (e.g. `v2`) but an older version prefix (`/v1/`, `/api/v1/`) is still returning success responses. Old versions often lack security patches present in the current version.  
**Remediation:** Decommission or block deprecated version endpoints. If parallel versioning is intentional, ensure older versions receive equivalent security updates. Only emitted when an OpenAPI spec is loaded.

#### `inventory.ssrf_surface` — medium

One or more parameters that accept a URL (by name — e.g. `url`, `uri`, `callback`, `webhook`, `redirect` — or OpenAPI `format: uri`; includes path-level parameters) took a benign external probe URL (`http://ssrf-probe.sentinel.invalid/`) without returning a validation or rejection signal. Requires a loaded OpenAPI spec. By default only `GET` query parameters are probed — the check is in the always-on inventory suite and must not send state-changing requests to the target. Setting `inventory.ssrfActiveProbe: true` opts into active probing of `POST`/`PUT`/`PATCH` operations and JSON body parameters (the common webhook / resource-creation SSRF vector); these requests may create or mutate resources on the target, so they are off by default. The `method` and `paramType` (`query`/`body`) of each accepted parameter are recorded in the evidence. An endpoint that fetches a user-supplied URL can be steered at internal-only services or cloud metadata endpoints (e.g. `169.254.169.254`) the caller should never reach — the core SSRF condition. This is surface detection: it confirms the parameter is accepted, not that a fetch is actually performed.  
**Remediation:** Validate and allowlist outbound URL destinations, reject internal and link-local ranges, and avoid fetching user-supplied URLs directly. Resolve and check the target host before connecting.

#### `inventory.graphql_introspection_enabled` — low

The `/graphql` endpoint responded to an introspection query and returned schema data. Introspection gives attackers a complete, machine-readable map of every query, mutation, type, and field.  
**Remediation:** Disable introspection in production (e.g. `introspection: false` in Apollo Server). Expose schema documentation through controlled channels instead.

---

## ratelimit

Checks for HTTP rate limiting via header inspection across selected endpoints, then a sequential burst probe (default 10 requests, 75 ms apart) against the first selected endpoint.

| ID                              | Severity | Title                                   | OWASP                                   |
| ------------------------------- | -------- | --------------------------------------- | --------------------------------------- |
| `ratelimit.no_429_on_burst`     | medium   | No rate limiting observed after burst   | API4: Unrestricted Resource Consumption |
| `ratelimit.no_headers`          | low      | No rate limit headers observed          | API4: Unrestricted Resource Consumption |
| `ratelimit.missing_retry_after` | low      | 429 response missing Retry-After header | API4: Unrestricted Resource Consumption |

### Finding details

#### `ratelimit.no_429_on_burst` — medium

A burst of sequential requests completed without triggering a 429 or returning rate-limit headers. HTTP-layer rate limiting may not be enforced on the probed endpoint. Unthrottled endpoints are vulnerable to brute-force, credential stuffing, scraping, and denial-of-service. Emitted only when no rate-limit headers were seen during the burst either.  
**Remediation:** Implement rate limiting at the API gateway or application layer. Return 429 when limits are exceeded and include standard rate-limit headers.

#### `ratelimit.no_headers` — low

None of the probed endpoints returned standard rate-limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, etc.). Rate limiting may still be enforced at the infrastructure level but is not communicated to clients.  
**Remediation:** Return standard rate-limit headers so clients can observe and adapt to quota constraints before being throttled.

#### `ratelimit.missing_retry_after` — low

Rate limiting was triggered (HTTP 429) but the response omitted a `Retry-After` header. Clients with no retry guidance typically resort to aggressive polling, worsening load on an already-throttled endpoint.  
**Remediation:** Include a `Retry-After` header on 429 responses — either a delay in seconds or an HTTP-date.

---

## Summary table

| Suite     | ID                                        | Severity |
| --------- | ----------------------------------------- | -------- |
| auth      | `auth.jwt_alg_none`                       | critical |
| injection | `injection.possible_command_injection`    | critical |
| auth      | `auth.invalid_token_accepted`             | high     |
| auth      | `auth.jwt_weak_signature`                 | high     |
| auth      | `auth.jwt_expired_accepted`               | high     |
| cors      | `cors.wildcard_with_credentials`          | high     |
| injection | `injection.sql_error_disclosure`          | high     |
| injection | `injection.nosql_error_disclosure`        | high     |
| injection | `injection.possible_template_injection`   | high     |
| auth      | `auth.jwt_missing_exp`                    | medium   |
| auth      | `auth.redirect_cross_origin`              | medium   |
| auth      | `auth.possible_bypass_probe`              | medium   |
| cors      | `cors.origin_reflection`                  | medium   |
| headers   | `headers.missing_hsts`                    | medium   |
| inventory | `inventory.sensitive_endpoint_exposed`    | medium   |
| inventory | `inventory.stale_version_responding`      | medium   |
| inventory | `inventory.ssrf_surface`                  | medium   |
| ratelimit | `ratelimit.no_429_on_burst`               | medium   |
| auth      | `auth.jwt_long_ttl`                       | low      |
| auth      | `auth.401_missing_www_authenticate`       | low      |
| headers   | `headers.missing_xcto`                    | low      |
| headers   | `headers.missing_referrer_policy`         | low      |
| inventory | `inventory.graphql_introspection_enabled` | low      |
| ratelimit | `ratelimit.no_headers`                    | low      |
| ratelimit | `ratelimit.missing_retry_after`           | low      |
