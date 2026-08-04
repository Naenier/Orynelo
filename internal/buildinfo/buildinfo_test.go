package buildinfo

import (
	"runtime/debug"
	"testing"
)

func TestResolveUsesInjectedBuildMetadata(t *testing.T) {
	originalVersion, originalCommit, originalDate, originalModified := version, commit, buildDate, modified
	t.Cleanup(func() {
		version, commit, buildDate, modified = originalVersion, originalCommit, originalDate, originalModified
	})

	version = "v0.2.1"
	commit = "abc123"
	buildDate = "2026-07-28T10:00:00Z"
	modified = "true"

	got := resolve(&debug.BuildInfo{
		Main: debug.Module{Version: "v9.9.9"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "fallback"},
			{Key: "vcs.time", Value: "2020-01-01T00:00:00Z"},
		},
	})

	if got.Version != "0.2.1" || got.Commit != commit || got.BuildDate != buildDate {
		t.Fatalf("resolve() did not preserve build metadata: %#v", got)
	}
	if !got.Dirty {
		t.Fatal("resolve() did not preserve the injected modified state")
	}
}

func TestResolveFallsBackToModuleAndVCSSettings(t *testing.T) {
	originalVersion, originalCommit, originalDate, originalModified := version, commit, buildDate, modified
	t.Cleanup(func() {
		version, commit, buildDate, modified = originalVersion, originalCommit, originalDate, originalModified
	})

	version = ""
	commit, buildDate, modified = "unknown", "unknown", "unknown"
	got := resolve(&debug.BuildInfo{
		Main: debug.Module{Version: "v0.4.2"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef"},
			{Key: "vcs.time", Value: "2026-07-28T10:00:00Z"},
			{Key: "vcs.modified", Value: "true"},
		},
	})

	if got.Version != "0.4.2" {
		t.Fatalf("Version = %q, want %q", got.Version, "0.4.2")
	}
	if got.Commit != "0123456789abcdef" {
		t.Fatalf("Commit = %q, want VCS revision", got.Commit)
	}
	if got.BuildDate != "2026-07-28T10:00:00Z" {
		t.Fatalf("BuildDate = %q, want VCS time", got.BuildDate)
	}
	if !got.Dirty {
		t.Fatal("Dirty = false, want true")
	}
}

func TestResolveUsesStageVersionAsLocalFallback(t *testing.T) {
	originalVersion := version
	t.Cleanup(func() { version = originalVersion })
	version = ""

	if got := resolve(nil).Version; got != "0.2.1" {
		t.Fatalf("local fallback version = %q, want 0.2.1", got)
	}
}
