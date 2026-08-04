# Contributing to Orynelo

Thank you for helping make network diagnosis safer and more useful. This guide
covers changes to code, tests, documentation, and build tooling.

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
git clone https://github.com/Naenier/orynelo.git
cd orynelo
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

## Maintainer release flow

Release assets are automated, while the tag and all release metadata remain
under manual maintainer control. Select a commit that is already present on
the repository's default branch, prepare the release notes, and then create and
push an annotated `v<SemVer>` tag:

```bash
git fetch origin
git tag -a vX.Y.Z <release-commit-sha> -m "Orynelo vX.Y.Z"
git push origin vX.Y.Z
```

Immediately create the GitHub Release for that existing tag, either in the
GitHub interface or with `gh`. The title, notes, and prerelease/latest state
are chosen manually:

```bash
gh release create vX.Y.Z \
  --repo Naenier/orynelo \
  --verify-tag \
  --title "Orynelo vX.Y.Z" \
  --notes-file /path/to/release-notes.md \
  --prerelease
```

The tag workflow waits briefly for the release, then attaches the two Linux
x86_64 archives and `SHA256SUMS.txt`. It does not create or edit the release.
If the release was created too late, rerun the failed workflow after it exists.
An existing asset is accepted only when its GitHub SHA-256 digest matches the
newly built file; a name collision with different bytes fails closed.
Build timestamps and archive metadata come from the tagged commit so the time
of a rerun alone does not change the assets. Force-updating a release tag
cancels an older run and the tag target is checked again during upload;
repository rules should still protect release tags from modification.

Repositories with immutable releases should create the release as a draft,
let the workflow attach its assets, and publish it afterward.

If a change alters SQLite data, add a forward migration and migration tests.
If it alters exported JSON, preserve the schema version or document and test a
schema transition.

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

Maintainers may ask for smaller commits during review.
