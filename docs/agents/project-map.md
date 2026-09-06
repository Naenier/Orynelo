# Project map

Orynelo diagnoses one explicitly selected network target and explains the
observed connection path. Its interfaces are `orynelo` (Cobra CLI) and
`orynelo-desktop` (Fyne). Both use the same application service and diagnostic
model. The Go module is `github.com/Naenier/orynelo`.

## Where to work

Paths in this table are relative to the repository root. Tests generally live
beside the implementation as `*_test.go`.

| Area | Implementation | Responsibility |
| --- | --- | --- |
| CLI process | `cmd/orynelo/` | Lazy runtime initialization, process exit, cancellation, platform signals |
| Desktop process | `cmd/orynelo-desktop/` | Fyne startup, runtime ownership, shutdown |
| Composition | `internal/bootstrap/` | Concrete adapters, safe logging, startup warnings, persistence policy |
| Application | `internal/application/` | Service and owned interfaces, option precedence, validation, typed errors |
| CLI adapter | `internal/cli/` | Commands, flags, explicit overrides, output and exit-code mapping |
| GUI adapter | `internal/gui/` | Backend boundary, coordinators, asynchronous actions, recovery, export |
| GUI lifecycle | `internal/gui/taskrunner/` | Operation scopes, cancellation, stale-result suppression, read/mutation scheduling |
| GUI presentation | `internal/gui/screens/`, `components/`, `presenter/`, `theme/` | Screens, reusable widgets, view models, appearance |
| Localization | `internal/gui/localization/` | English/Russian catalogs, formatting, stable message keys |
| Diagnostic runner | `internal/diagnostics/` | Run orchestration, network paths, event delivery, integration tests |
| Diagnostic engine | `internal/diagnostics/engine/` | Plan execution, stage deadlines, deterministic results |
| Domain model | `internal/diagnostics/model/` | Options, typed results, evidence, state, network references, JSON behavior |
| Checks | `internal/diagnostics/checks/` | Target, environment/proxy, DNS, route, TCP, TLS, HTTP |
| Conclusions | `internal/diagnostics/summary/` | Evidence-based summary ranking and recommendations |
| Privacy | `internal/privacy/`, `internal/redaction/` | Typed projection and low-level sanitization |
| Reports | `internal/report/` | Text, Markdown, canonical JSON, localized human reports |
| Configuration | `internal/config/` | Strict YAML loading and private atomic saves; types live in the application layer |
| Storage | `internal/storage/` | SQLite history/profiles, snapshots, migrations, backups, retention |
| File export | `internal/secureio/` | Atomic local export, destination checks, OS-specific replacement |
| Platform and trust | `internal/platform/`, `internal/trust/` | Application paths, shutdown signals, bounded additive CA bundles |
| Build and packaging | `internal/buildinfo/`, `Makefile`, `Dockerfile`, `scripts/`, `.github/workflows/` | Build metadata, CLI container, desktop packaging, CI and releases |
| Assets | `assets/` | Embedded application icons |

## Follow a diagnosis

1. An adapter sends `application.DiagnoseRequest` with an optional profile and
   only explicitly supplied `DiagnoseOverrides`.
2. The application resolves model defaults, one configuration snapshot, the
   profile, and run overrides, then validates request-capable execution options.
3. The runner creates run-local state and a global deadline. The production
   plan in `internal/diagnostics/checks/default.go` runs target, environment,
   DNS, route, TCP, TLS, and HTTP stages with appropriate applicability rules.
4. Checks collect bounded observations and correlated network references.
   The runner builds a summary from the completed evidence. Events provide
   progress; the final diagnosis is authoritative.
5. The application projects the diagnosis for privacy before it crosses
   presentation and persistence boundaries. Reports and storage also sanitize
   at their own boundaries.

Presentation must not introduce another diagnostic engine or independent option
merge rules. Keep new concrete adapter wiring in bootstrap and interface-driven
orchestration in the application layer.

## Sources of truth

| Fact | Consult |
| --- | --- |
| Go requirement and module versions | `go.mod`; dependency checksums in `go.sum` |
| Build targets and desktop build tags | `Makefile` |
| Actual CI commands | `.github/workflows/ci.yml` |
| Linter selection | `.golangci.yml` |
| Option defaults and validation | `internal/diagnostics/model/model.go`, `internal/application/diagnose_options.go`, `internal/application/configuration.go` |
| Machine statuses and error codes | `internal/diagnostics/model/`, `internal/application/errors.go`, the relevant check |
| JSON report envelope | `internal/report/report.go`, `docs/diagnostic-model.md` |
| SQLite migration version | `internal/storage/migrations.go` |
| Snapshot version and reconstruction | `internal/storage/store.go`, `internal/storage/history.go` |
| Configuration schema | `internal/application/configuration.go`, `internal/config/config.go` |
| Build version and fallbacks | `Makefile`, `internal/buildinfo/buildinfo.go` |

The CLI container represents its own network namespace, not necessarily the
host's connectivity. Linux is the primary tested platform; platform-specific
source files alone do not establish verified macOS or Windows support.
Kubernetes commands, `client-go` integration, and in-cluster probes remain
roadmap items. Do not add their dependencies or placeholder screens during
unrelated endpoint-diagnostic work.
