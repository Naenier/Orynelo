# Orynelo: instructions for coding agents

These instructions apply throughout this repository. Follow the active task
and higher-priority agent instructions first. More specific repository guidance
applies within its directory. This file is the shared entry point; tool-specific
instruction files should refer here instead of maintaining separate policies.

## Start with the task

- Respect the requested scope. A request to create documentation authorizes
  documentation changes, not implementation changes or dependency upgrades.
- Read the affected code and nearby tests before editing. Use `rg` and focused
  file reads; do not load the entire repository into context.
- Preserve existing user changes. Make focused edits without unrelated cleanup,
  bulk formatting, generated output, or changes to release metadata.
- Continue routine, reversible work already authorized by the user. Ask only
  when a missing decision materially affects the requested result.
- If the user says not to run checks, do not run tests, linters, builds, or
  post-edit inspection commands. Report that checks were not run. The command
  reference below does not override that instruction.
- Answer in the user's language. Follow the surrounding English conventions
  for code identifiers, comments, and repository documentation unless asked
  otherwise. Product UI text belongs in the localization catalogs.

## Project in brief

Orynelo is a local, evidence-based network reachability diagnostic tool.
It has a Cobra CLI and a Fyne desktop application over one Go application
layer. Configuration is YAML; history and profiles use SQLite through
`modernc.org/sqlite`. Linux is the primary development and CI platform;
macOS and Windows are manual preview targets.

Read versions from `go.mod`, build commands from `Makefile`, and CI requirements
from `.github/workflows/ci.yml`. Do not infer implemented features from the
roadmap. Kubernetes diagnosis is planned work, not an existing subsystem.

## Architecture and behavior to preserve

- `cmd/*` owns process startup and shutdown; `internal/bootstrap` assembles
  concrete infrastructure. CLI and GUI call `internal/application`; the GUI
  never shells out to the CLI.
- Keep `internal/diagnostics/model` independent of presentation, persistence,
  and concrete infrastructure. Put checks in `internal/diagnostics/checks/*`
  and conclusions in `internal/diagnostics/summary`.
- Use `DiagnoseRequest` with explicit `DiagnoseOverrides` for adapter input.
  Resolve defaults, configuration, profile, and overrides in the application
  layer. Preserve omitted versus explicit false/zero values.
- `ResolveDiagnoseOptions` returns request-capable execution data.
  `PreviewDiagnoseOptions` returns privacy-projected display data. Never
  serialize the execution value or execute the redacted preview.
- Propagate `context.Context`; bound deadlines, concurrency, redirects,
  buffers, and response reads. Keep final results in deterministic plan order.
- Preserve distinct direct, proxy, origin, redirect, and attempt identities.
  A direct preflight is not proof about the actual HTTP transport route.
  Conclusions must reference observations, not assert unobserved causes.
- Use `internal/privacy` and `internal/redaction` before data reaches logs,
  events, reports, history, profiles, or clipboard output. Raw request URLs,
  credentials, request-header values, CA contents, and response bodies must
  not cross those boundaries.
- Preserve typed application errors, stable codes, `errors.Is`/`errors.As`,
  and the private wrapped cause. Keep canonical JSON language-neutral.
- Dispatch GUI widget changes through `fyne.Do`. Use existing task scopes
  for cancellation, stale-response suppression, and serialized mutations.
- Preserve optional-adapter degradation and the `default`, `no-history`, and
  `ephemeral` persistence policies. Use `internal/secureio` for file exports.
- Keep report/snapshot compatibility and add forward SQLite migrations when
  needed. Do not rewrite released migrations or compatibility fixtures to
  make a change appear compatible.

## Read only the relevant supporting material

| Need | Read |
| --- | --- |
| Agent files and how they fit together | [Agent guide](docs/agents/README.md) |
| Locate implementation and affected layers | [Project map](docs/agents/project-map.md) |
| Commands, test selection, and task recipes | [Development workflow](docs/agents/development.md) |
| Privacy, network, storage, and lifecycle invariants | [Guardrails](docs/agents/guardrails.md) |
| Architectural design | [Architecture](docs/architecture.md) |
| Evidence, schema, and summary semantics | [Diagnostic model](docs/diagnostic-model.md) |
| Persistence failure and shutdown behavior | [Runtime resilience](docs/runtime-resilience.md) |
| Security design and contribution conventions | [Security](docs/security.md), [Contributing](.github/CONTRIBUTING.md) |

When code and documentation disagree, identify the discrepancy relevant to the
task. Do not silently broaden the work or treat a documentation claim as proof
that an implementation exists.

## Finishing a task

When checks are allowed, choose meaningful checks for the changed behavior
using the development guide. Distinguish passed, failed, blocked, and skipped
checks; never claim an unexecuted check passed. Summarize the outcome, changed
files, and any remaining limitation. Do not commit, push, tag, or publish merely
because a local edit is complete; follow the user's requested delivery scope.
