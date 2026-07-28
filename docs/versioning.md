# Versioning and releases

OpsDoctor uses Semantic Versioning for releases and descriptive SemVer build
versions for local, branch, and pull request artifacts. No build changes a
tracked source file.

## Version calculation

Run:

```bash
./scripts/version.sh
```

The script finds the highest reachable strict `vMAJOR.MINOR.PATCH` tag. Before
the first tag, the base version is `0.1.0`.

| Context | Formula | Example |
| --- | --- | --- |
| Exact release tag | tag without `v` | `0.2.1` |
| Pull request | `<base>-pr.<PR>.<run>+g<sha>` | `0.2.1-pr.17.143+g9c7e123` |
| Branch push in CI | `<base>-dev.<run>+g<sha>` | `0.2.1-dev.143+g9c7e123` |
| Clean local tree | `<base>-dev+g<sha>` | `0.2.1-dev+g9c7e123` |
| Dirty local tree | `<base>-dev+g<sha>.dirty` | `0.2.1-dev+g9c7e123.dirty` |

`PR_NUMBER`, `GITHUB_RUN_NUMBER`, `GITHUB_EVENT_NAME`, and `GITHUB_ACTIONS`
provide CI context. When `PR_NUMBER` is absent, a standard
`refs/pull/<number>/...` GitHub ref is parsed. The script fails rather than
inventing a pull request number.

Changes to tracked files and non-ignored untracked files mark a local build
dirty. Ignored editor state does not make an otherwise reproducible build
dirty.

Use `--base` to print only the base version and `--oci` for an image-safe tag:

```bash
./scripts/version.sh --base
./scripts/version.sh --oci
```

OCI output preserves the three dots in the base release and replaces SemVer
prerelease/build separators:

```text
0.2.1-pr-17-143-g9c7e123
```

The algorithm is covered by `scripts/version_test.sh` in temporary Git
repositories. The same test verifies that `make snapshot` passes the calculated
version into GoReleaser; its snapshot template then uses that value for archive
names and linker metadata.

## Runtime build metadata

The `internal/buildinfo` package exposes:

```go
type Info struct {
    Version   string
    Commit    string
    BuildDate string
    Dirty     bool
    GoVersion string
    OS        string
    Arch      string
}
```

Release and Make builds set the unexported variables with linker flags:

```text
-X github.com/Naenier/opsdoctor/internal/buildinfo.version=<version>
-X github.com/Naenier/opsdoctor/internal/buildinfo.commit=<commit>
-X github.com/Naenier/opsdoctor/internal/buildinfo.buildDate=<RFC3339 time>
```

When a value is not injected, `runtime/debug.ReadBuildInfo` supplies a module
version, VCS revision, VCS time, and modified flag when the Go tool recorded
them. `runtime.Version`, `runtime.GOOS`, and `runtime.GOARCH` always supply the
toolchain and platform.

The CLI `version` and `version --json`, desktop About screen, and stored history
all use this package.

## Conventional Commits

Release Please derives version bumps and changelog sections from squash-merge
commit titles:

- `fix:` produces a patch candidate;
- `feat:` produces a minor candidate;
- `type!:` or a `BREAKING CHANGE:` footer produces a major candidate;
- documentation, test, build, CI, and maintenance commits normally appear in
  the configured changelog without forcing a feature bump.

The repository is pre-1.0; incompatible changes can still occur, but must be
declared and documented.

## Release workflow

On each push to `main`, one workflow:

1. Runs Release Please with `release-type: go`.
2. Creates or updates the release pull request from Conventional Commits.
3. When that pull request is merged, creates the SemVer tag and GitHub Release.
4. Checks out the exact `sha` reported by Release Please.
5. Uses GoReleaser to build CLI archives for Linux, macOS, and Windows.
6. Builds native desktop binaries on Linux, macOS, and Windows runners. Linux
   and macOS feed those exact binaries to the pinned Fyne packager for desktop
   metadata and icons; the packaging check rejects a changed executable.
7. Generates SHA-256 checksums and uploads assets to the existing release.
8. Builds and pushes the non-root CLI image to GHCR.

This is deliberately one workflow. Tags created with the standard
`GITHUB_TOKEN` do not start a second workflow, so release packaging does not
depend on a tag-triggered run.

Maintainers configure the optional `RELEASE_PLEASE_TOKEN` secret with a
fine-grained token so release pull requests trigger the ordinary
`pull_request` CI workflow. Limit it to this repository with `Contents:
write`, `Pull requests: write`, and `Issues: write`. The built-in
`GITHUB_TOKEN` remains a setup fallback, but GitHub intentionally suppresses
downstream workflow events created with it.

Stable container releases receive:

```text
ghcr.io/naenier/opsdoctor:<version>
ghcr.io/naenier/opsdoctor:v<major>
ghcr.io/naenier/opsdoctor:v<major>.<minor>
ghcr.io/naenier/opsdoctor:latest
```

Prereleases receive only their exact version tag; they do not move the
major/minor channels or `latest`.

Fyne tools 1.7.2 always rebuilds a Windows executable while injecting its
resource object, even when an existing executable is supplied, and exposes no
stable linker-flag input for that rebuild. The Windows release therefore keeps
the explicitly version-stamped executable in its ZIP instead of risking lost
build metadata. It does not yet receive Fyne-generated Windows icon/version
resources.

## Reproducibility notes

Builds use `-trimpath`, disable implicit VCS stamping where explicit metadata
is injected, and clear the Go build ID. GoReleaser also sets CLI archive
timestamps from the release commit. Given the same source, toolchain,
dependencies, and build metadata, this removes common host-path and timestamp
variation from those CLI artifacts. Native desktop archives are built on
platform runners and are not currently claimed to be bit-for-bit
reproducible. Container base images and tool actions are updated by Dependabot
and are reviewed as supply-chain changes.
