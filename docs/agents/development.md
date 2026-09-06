# Development workflow for agents

Apply [AGENTS.md](../../AGENTS.md) first. The commands below are a reference,
not an instruction to execute every command for every task. If the user asks
for file creation only or explicitly forbids checks, honor that scope and
finish without tests, builds, linters, or post-edit inspections.

## Work in small, complete changes

1. Identify the requested outcome and affected packages using the
   [project map](project-map.md). Read nearby implementation and existing tests.
2. Follow the existing abstractions and error handling. Avoid mutable global
   state, generic `utils`/`helpers`/`common` packages, and speculative frameworks.
3. Make the smallest change that completes the requested behavior across the
   relevant layers. Do not add a dependency when existing code or the standard
   library provides the needed behavior.
4. For behavior changes, add or adapt meaningful deterministic tests when in
   scope. Documentation-only edits do not require implementation-shaped tests.
5. When allowed, run focused validation, then broader relevant checks for
   shared contracts or cross-package changes. Stop repeating successful checks
   unless new edits or unresolved failures justify another run.
6. Report the outcome and actual validation status, including skipped checks.

## Setup and command reference

Use the Go version declared in `go.mod`. Desktop builds and broad package
checks can require native Fyne development libraries and a C toolchain; the
[README](../../README.md) lists platform-specific packages. Do not assume a
missing native dependency is a Go code defect, or change build tags merely to
hide it. `golangci-lint` is a separate tool configured by `.golangci.yml`.

Run commands from the repository root when they are relevant and permitted.

| Purpose | Command | Notes |
| --- | --- | --- |
| Download modules | `go mod download` | Setup step; may access the network and module cache |
| Verify modules | `go mod verify` | Used by CI |
| Detect module-file drift | `go mod tidy -diff` | Used by CI; may resolve dependencies |
| Format changed Go files | `gofmt -w path/to/changed.go` | Mutates only the explicitly selected files |
| Check Go formatting | `make fmt-check` | Does not rewrite source |
| Static analysis | `make vet` | Runs `go vet ./...` |
| Configured lint | `make lint` | Requires `golangci-lint`; consult its installed version if incompatible |
| Unit tests | `make test` | Runs `go test ./...` |
| Race detector | `make test-race` | Useful for concurrent behavior; requires a supported toolchain |
| Coverage | `make coverage` | Creates `coverage.out`; use when coverage is relevant |
| Diagnostic integration | `go test -tags=integration ./internal/diagnostics` | Existing integration tests use local servers and proxies |
| CI test invocation | `go test -tags="integration wayland migrated_fynedo" ./...` | Match the current workflow and native prerequisites |
| CLI build | `make build-cli` | Produces `bin/orynelo` with CGO disabled |
| Desktop build | `make build-gui` | Uses `migrated_fynedo` by default |
| Wayland desktop build | `make build-gui GUI_TAGS=wayland,migrated_fynedo` | Platform-specific build option |
| Both binaries | `make build` | Requires desktop prerequisites |

`make fmt` formats the entire repository; prefer formatting only changed files
for a focused task. `make clean` deletes generated output and is not a routine
validation step. Builds and coverage create artifacts; do not add those files
to the change. Starting the desktop or running a diagnosis can create local
application data. Use isolated paths or the CLI's `--persistence ephemeral`
when exercising behavior that should not persist runtime state. Ephemeral
persistence does not suppress network requests from a diagnosis.

The current CI verifies dependencies, formatting, vetting, integration-tagged
tests, both builds, and CLI version JSON. Lint, race detection, and coverage
have local Make targets but are not all steps in that workflow. Re-read the
workflow when changing CI or reproducing a CI failure.

## Select tests by behavior

These are starting points, not a claim that one package test proves every
downstream contract. Add affected consumers when changing shared types.

| Changed behavior | Focused command |
| --- | --- |
| Option precedence, application errors, configuration | `go test ./internal/application ./internal/config ./internal/cli` |
| Checks, engine, paths, summaries | `go test ./internal/diagnostics/...` |
| End-to-end diagnostic path | `go test -tags=integration ./internal/diagnostics` |
| Privacy and output | `go test ./internal/privacy ./internal/redaction ./internal/report ./internal/storage` |
| Storage, migrations, degraded startup | `go test ./internal/storage ./internal/bootstrap ./internal/application` |
| GUI, presentation, localization | `go test ./internal/gui/...` |
| Task scheduling and event concurrency | `go test -race ./internal/gui/taskrunner ./internal/application ./internal/diagnostics/...` |
| File export | `go test ./internal/secureio ./internal/cli ./internal/gui` |
| Build metadata and CLI startup | `go test ./internal/buildinfo ./cmd/orynelo` |

Use table-driven cases when they express related behavior clearly. Prefer
`httptest` servers, loopback listeners, fake resolvers/dialers, controlled
clocks, and temporary directories. Unit tests must not require public Internet
access, user DNS configuration, fixed external services, or timing races.
Restore modified environment variables with the existing test helpers or
`t.Setenv`; avoid parallel tests that compete over process-global state.

## Change recipes

### Add a diagnostic option or CLI flag

Trace the field through model options, application overrides, normalization,
validation, and relevant adapters. Preserve explicit false/zero overrides and
centralized precedence. Add configuration/profile persistence only if the
setting belongs there; one-run secrets do not. Review privacy projection,
safe previews, report behavior, and applicable documentation together.

### Add a check or evidence field

Use the relevant check package or add a focused package under
`internal/diagnostics/checks/`. Register a new stage in `checks/default.go`
only when required by the diagnostic plan. Carry cancellation, limits, stable
codes, and network references through the result. Consider summary rules,
privacy projection, report rendering, storage snapshots, and GUI presenters.
Preserve old JSON readers when adding optional fields.

### Change GUI behavior or text

Keep business logic in the application layer and domain-to-display conversion
in presenters. Use coordinators/task scopes for asynchronous work and
`fyne.Do` for widget mutations. Update English and Russian catalog entries
together, preserving key parity. Layout snapshots cover both languages,
light/dark themes, and narrow/wide viewports in
`internal/gui/screens/testdata/layout/`. Change a golden only for an intended
layout change; do not invent an update flag or overwrite expected output just
to suppress a failure.

### Change persistence or serialized contracts

Read [runtime resilience](../runtime-resilience.md) and the
[guardrails](guardrails.md). Add an ordered forward migration and compatibility
coverage for SQLite changes. Keep normalized rows and the complete snapshot
consistent in one transaction. Treat SQLite, configuration, snapshot, and
report versions as separate contracts. Preserve released fixtures and add new
fixtures for newly supported schemas.

### Change documentation or agent instructions

Edit the relevant shared document and keep tool adapters short. Document
implemented behavior separately from planned work. Create only requested
artifacts; do not introduce code changes, tests, generated reports, or
automatically maintained task diaries to accompany a documentation-only task.

## Handoff

A final response should state what changed, which checks actually ran or were
skipped, and any material remaining limitation. For longer interrupted work,
record the requested outcome, files changed, current evidence, and next step
in the conversation or an explicitly requested handoff artifact. Do not store
credentials or raw diagnostic data in agent memory files.

For a requested pull request, follow
[the repository template](../../.github/pull_request_template.md) and describe
the final behavior and actual validation. Release tags and publication are
separate from ordinary editing; use the maintainer flow only when that work
is authorized.
