# AGENTS.md

Guidance for AI coding agents working in `cli-extension-secrets`.

## What this repo is

A Snyk CLI extension plugin that implements the `snyk secrets test` command. It is a Go
library, not a standalone binary: the real Snyk CLI imports `pkg/secrets` and calls
`secrets.Init(engine)` to register workflows with the
[go-application-framework](https://github.com/snyk/go-application-framework) (GAF) engine.

- Module: `github.com/snyk/cli-extension-secrets`, Go `1.26.5`
- Workflow ID: `secrets.test`
- Owned by `@snyk/code_code-iac-secrets`; closed to public contributions

The scan flow is: validate org and feature enablement → resolve git context → filter local
files → upload them as a revision → trigger a scan through the test API → format findings
as CLI/JSON/SARIF output.

## Layout

| Path | Contents |
| --- | --- |
| `pkg/secrets/` | Public `Init()`. Entry point the Snyk CLI loads. |
| `pkg/filefilter/` | Public concurrent file-filtering pipeline (size, text-only, glob, `.gitignore`/`.snyk`). |
| `internal/commands/secretstest/` | The workflow itself: registration, flags, validation, git detection, orchestration, errors, UI. |
| `internal/commands/cmdctx/` | Typed `context.Context` accessors for the invocation context and instrumentation. |
| `internal/clients/` | HTTP clients: `upload` (file revisions), `testshim` (test API), `settings` (org Secrets setting), `snykclient` (shared wrapper). |
| `internal/instrumentation/` | GAF analytics timing/size metrics. |
| `cmd/develop/` | Local dev runner built on `devtools.Cmd`. |

Key files to read first when changing behavior: `internal/commands/secretstest/workflow.go`
(entry point and config registration) and `internal/commands/secretstest/command.go`
(the filter → upload → scan → output pipeline).

## Commands

Build, test, and vet work with plain Go and no extra setup:

```bash
go build ./...
go test ./...
go vet ./...
```

Run a single package or test:

```bash
go test ./internal/commands/secretstest -v
go test ./internal/commands/secretstest -run TestValidateFlagValue -v
```

Run the extension locally against a real org (requires an authenticated Snyk CLI config):

```bash
go run ./cmd/develop secrets test .
```

Make targets exist in `common.mk` (`make test`, `make lint`, `make cover`, `make format`),
but they depend on tools that are not installed by default. **`make install-tools` currently
fails**: it reads `tools.go` and runs `npm clean-install`, and neither `tools.go` nor
`package.json` exists in this repo. `make format` likewise needs `prettier`. Prefer the plain
`go` commands above unless you have already installed the tooling yourself.

Linting matches CI with:

```bash
golangci-lint run ./...   # golangci-lint v2.11.3
```

## Conventions

**Linting is strict.** `.golangci.yaml` enables a large linter set including `wrapcheck`,
`ireturn`, `gosec`, `gocritic` (all tags), `gocyclo` (max complexity 15), `godot`, `revive`
with `exported`, and `lll` at 160 columns. Practical consequences:

- Every returned error must be wrapped with context (`fmt.Errorf("...: %w", err)`).
- Every exported symbol needs a doc comment, and every package needs a package comment.
- Comments must end in a period.
- Returning an interface requires a `//nolint:ireturn` with an explanation — `nolintlint` is
  configured to require both a specific linter name and a reason.
- Formatting is `gofumpt` with extra rules, plus `goimports` with local prefix
  `github.com/snyk/cli-extension-secrets`, so local imports go in their own trailing group.

**Errors go through the error catalog.** User-facing errors are created by `ErrorFactory` in
`internal/commands/secretstest/errors.go`, which wraps
`github.com/snyk/error-catalog-golang-public`. Do not return bare `fmt.Errorf` values out of
the workflow. Note `ensureCatalogError`: an error that is already a `snyk_errors.Error` is
returned unwrapped, because the CLI displays only the outermost catalog message and wrapping
would hide the specific, actionable one. User-facing message strings are declared as
constants at the top of that file.

**Flags** are declared as `Flag*` constants and registered in `flags.go`, then validated in
`validate.go`. When adding a flag, add the constant, register it in `GetSecretsTestFlagSet`,
add validation, and add a table-driven test case in `validate_test.go`. Flags that only apply
with `--report` must be rejected when `--report` is absent (see
`validateFlagsWithoutReportConfig`).

**Config values** are read from the GAF `configuration.Configuration`, not from globals.
Feature enablement is resolved lazily through registered default-value functions in
`workflow.go`; `SecretsSettingsEnabled` performs a network call on first read, so its errors
(often auth failures) must be surfaced rather than treated as "feature disabled".

## Testing

- `testify` (`assert`/`require`) for assertions, `github.com/golang/mock/gomock` for mocks.
- GAF supplies mocks for the invocation context and test results:
  `go-application-framework/pkg/mocks` and `pkg/apiclients/mocks`.
- Repo mocks are generated by MockGen and **checked in**. There are no `go:generate`
  directives, so regenerate manually and commit the result. Live mocks:
  `internal/clients/upload/mocks/`, `internal/clients/testshim/mocks/`, and
  `internal/commands/secretstest/testdata/mocks/`. `internal/mocks/clients/` is stale and
  referenced by nothing — do not add to it.
- The `testpackage` linter is on, so tests for public packages use an external test package
  (`filefilter_test`, `secrets_test`). `secretstest` is tested white-box in-package, which is
  an intentional exception permitted by the `_test.go` exclusion rules.
- Table-driven tests are the norm; `validate_test.go` is the best model to copy.
- Use `t.TempDir()` for filesystem fixtures. Static fixtures live in
  `internal/commands/secretstest/testdata/`. There are no golden files.
- Path handling is platform-sensitive. `paths_windows_test.go` is `//go:build windows` and CI
  runs a dedicated Windows job, so changes to `paths.go` or `gitrepo.go` cannot be validated
  on macOS/Linux alone.

## CI

CircleCI only (`.circleci/config.yml`) — there are no GitHub Actions. The pipeline runs
`go test ./...` on Linux, `go test ./...` on Windows Server 2022, `golangci-lint run ./...`,
Snyk security scans, and a secrets scan. Before pushing, at minimum run `go test ./...` and
`golangci-lint run ./...`.

`gitleaks` runs both in CI and as a pre-commit hook (`.pre-commit-config.yaml`). Since this
is a secrets-scanning tool, test fixtures that look like credentials will trip it; use
obviously fake values and check `.gitleaks.toml` if a scan blocks you.

## Commits and PRs

Conventional commits with the Jira ticket in brackets, matching existing history:

```
feat: dotsnyk excludes [PS-715]
fix: surface auth error when secrets feature flag check fails [PS-698]
chore: bump gaf version [PS-751]
```

Fill in `.github/PULL_REQUEST_TEMPLATE.md`, including the relevant tickets. Keep PRs small
and focused.

## Gotchas

- `go.mod` has a commented-out `replace` for GAF pointing at `../go-application-framework`.
  Uncomment it to test against a local GAF checkout, but never commit it uncommented.
- GAF is the main source of churn. Version bumps often change the `testapi` interfaces used
  in `command.go`, so expect mock and test updates alongside them.
- `test/` is gitignored — `make test` writes coverage and JUnit output there.
- Update `README.md` when you change user-facing flag behavior.
