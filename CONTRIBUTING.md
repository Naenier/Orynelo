# Contributing to OpsDoctor

Thank you for helping make network diagnosis safer and more useful. This guide
covers changes to code, tests, documentation, build tooling, and releases.

## Before starting

Search existing issues and pull requests before beginning a large change. For
behavioral or architectural work, open a feature request that describes the
problem, the evidence users need, and the proposed effect on the diagnostic
model. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

By participating, you agree to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

The module requires Go 1.26.5 or newer. Clone the existing repository and
download verified module dependencies:

```bash
git clone https://github.com/Naenier/opsdoctor.git
cd opsdoctor
go mod download
go mod verify
```

Desktop development requires the native libraries used by Fyne. On Ubuntu:

```bash
sudo apt-get update
sudo apt-get install --no-install-recommends \
  gcc \
  libgl1-mesa-dev \
  libxkbcommon-dev \
  libwayland-dev \
  xorg-dev
```

Use `make help` to list project targets. Native Windows development can use
the Go commands shown in the README when GNU Make is unavailable.

## Architecture expectations

- Keep the diagnostic domain independent of Cobra, Fyne, SQLite, and concrete
  loggers.
- Put orchestration in the application layer, network checks in focused
  diagnostic packages, and operating-system enrichment behind interfaces.
- Pass `context.Context` through network and storage boundaries.
- Use bounded timeouts, response sizes, redirect counts, goroutines, and
  channels.
- Do not add mutable global state, generic `utils` packages, or shell command
  interpolation.
- Redact secrets before values reach logs, events, reports, or persistence.
- Treat evidence as observation, not proof of an unobserved cause.

More detail is available in [docs/architecture.md](docs/architecture.md) and
[docs/security.md](docs/security.md).

## Testing

Run the checks relevant to your change:

```bash
make fmt-check
make vet
make lint
make test
make test-race
make coverage
make build
make version-test
```

Tests should be table driven when several input/output cases share behavior.
Use `httptest.Server`, `httptest.NewTLSServer`, fake resolvers, fake dialers,
and fake clocks rather than public endpoints. Unit tests must not depend on
Internet access or timing races.

Optional tests that require a host integration belong behind the `integration`
build tag:

```bash
go test -tags=integration ./...
```

If a change alters SQLite data, add a forward migration and migration tests.
If it alters exported JSON, preserve the schema version or document and test a
schema transition.

## Commit and pull request titles

Use Conventional Commits:

```text
feat: add functionality
fix: correct a defect
docs: documentation only
test: tests only
refactor: internal restructuring
perf: performance improvement
build: build system
ci: CI configuration
chore: maintenance
```

Scopes are encouraged when they improve clarity:

```text
feat(dns): add separate IPv4 and IPv6 results
fix(tls): report hostname mismatch correctly
docs: explain proxy environment detection
test(http): cover redirect loops
```

Use `!` or a `BREAKING CHANGE:` footer for an intentional incompatible change.
The repository uses squash merge, so the pull request title must itself be a
valid Conventional Commit title.

## Pull request checklist

Before requesting review:

1. Keep the change focused and explain user-visible behavior.
2. Add or update deterministic tests.
3. Run and report the checks you actually executed.
4. Update documentation for flags, reports, storage, or security behavior.
5. Confirm that logs, fixtures, and screenshots contain no secrets.
6. Confirm that new network work is cancellable and bounded.
7. Avoid committing binaries, coverage profiles, databases, or local editor
   settings.

Maintainers may ask for smaller commits during review, but the final merge is
squashed using the pull request title.

## Releases

Do not edit a source file merely to record a version and do not create release
tags manually as part of a feature pull request. Release Please prepares the
release pull request and tag from Conventional Commits. The release workflow
then builds assets from the exact release SHA.

Repository maintainers should configure a fine-grained
`RELEASE_PLEASE_TOKEN` Actions secret so release pull requests trigger the
normal pull-request CI workflow. It needs repository contents, issues, and
pull-request write access. The workflow falls back to `GITHUB_TOKEN` for
initial setup, but GitHub suppresses downstream workflow events created by
that built-in token.
