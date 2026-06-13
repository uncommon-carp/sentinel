# Contributing to Sentinel

Thanks for your interest in contributing. Sentinel is a CLI API security scanner
built in TypeScript. This guide covers everything you need to get started.

## Before you start

- Check open issues before starting work: comment on the issue to claim it
- For anything beyond a bug fix or good-first-issue, open an issue to discuss
  the approach before writing code

## Setup

```bash
git clone https://github.com/uncommon-carp/sentinel.git
cd sentinel
npm install
```

Run the test suite to confirm everything is working:

```bash
npm test
```

## Development workflow

Sentinel uses a suite-based architecture. Each security check lives in
`src/suites/` as an isolated module. Before touching anything, read
`docs/ARCHITECTURE.md`, it's short and will save you time.

### Key commands

| Command                  | What it does                       |
| ------------------------ | ---------------------------------- |
| `npm test`               | Run all tests                      |
| `npm run typecheck`      | TypeScript type check (src)        |
| `npm run typecheck:test` | TypeScript type check (test files) |
| `npm run lint`           | ESLint                             |
| `npm run format`         | Prettier format                    |
| `npm run format:check`   | Check formatting without writing   |
| `npm run build`          | Compile to `dist/`                 |

All of these must pass before opening a PR, the CI workflow will check them.

## Making changes

### Tests

Every change needs tests. Sentinel uses [Vitest](https://vitest.dev/) with
deterministic HTTP mocking: no live network requests in tests.

- Suite tests live in `test/suites.<name>.test.ts`
- Use `makeSuiteCtx()` from `test/helpers/makeConfig.ts` to build suite context
- Use `mockFetch()` from `test/helpers/fetchMock.ts` to mock HTTP responses
- Do not hand-roll suite context or call `fetch` directly in tests

Run tests with coverage before submitting:

```bash
npx vitest run --coverage
```

Coverage thresholds are enforced, your changes should not drop coverage below
the current baseline.

### Adding a suite

If you're adding a new security suite:

1. Create `src/suites/<name>.ts` — export a factory function returning `{ name, description, run(ctx) }`
2. Use `resolveEndpoints(ctx.selectedEndpoints)` to iterate endpoints (unless your suite has its own probe path logic: see `auth.ts` and `inventory.ts` for reference)
3. Register it in `src/suites/index.ts`
4. Add config schema in `src/config/schema.ts` if needed
5. Create `test/suites.<name>.test.ts`
6. Update `README.md` (Features, OWASP table, config docs) and `docs/ARCHITECTURE.md`

### CHANGELOG

Update the `[Unreleased]` section in `CHANGELOG.md` with a summary of your
change. Follow the existing format — Added / Changed / Fixed.

## Pull requests

- Target the `main` branch
- Keep PRs focused — one concern per PR
- The PR template checklist must be completed before review

CI runs automatically on your PR. Fix any failures before requesting review.

## Code style

- TypeScript strict mode — no `any`, no type assertions without justification
- No `console.log` in production code — use `ctx.logger`
- Findings should have stable IDs, meaningful `whyItMatters`, and actionable
  `remediation` guidance
- Active checks must respect `config.active.maxRequestsPerSuite`

## Questions

Open a discussion or comment on the relevant issue.
