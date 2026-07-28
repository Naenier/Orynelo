package buildinfo

import (
	"runtime/debug"
	"testing"
)

func TestResolveUsesLinkerValues(t *testing.T) {
	originalVersion, originalCommit, originalDate := version, commit, buildDate
	t.Cleanup(func() {
		version, commit, buildDate = originalVersion, originalCommit, originalDate
	})

	version = "1.2.3"
	commit = "abc123"
	buildDate = "2026-07-28T10:00:00Z"

	got := resolve(&debug.BuildInfo{
		Main: debug.Module{Version: "v9.9.9"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "fallback"},
			{Key: "vcs.time", Value: "2020-01-01T00:00:00Z"},
		},
	})

	if got.Version != version || got.Commit != commit || got.BuildDate != buildDate {
		t.Fatalf("resolve() did not preserve linker values: %#v", got)
	}
	if got.Dirty {
		t.Fatal("resolve() unexpectedly marked a clean linker build dirty")
	}
}

func TestResolveFallsBackToModuleAndVCSSettings(t *testing.T) {
	originalVersion, originalCommit, originalDate := version, commit, buildDate
	t.Cleanup(func() {
		version, commit, buildDate = originalVersion, originalCommit, originalDate
	})

	version, commit, buildDate = "dev", "unknown", "unknown"
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

func TestResolveRecognizesDirtyVersionSuffix(t *testing.T) {
	originalVersion, originalCommit, originalDate := version, commit, buildDate
	t.Cleanup(func() {
		version, commit, buildDate = originalVersion, originalCommit, originalDate
	})

	version, commit, buildDate = "0.1.0-dev+gabc1234.dirty", "abc1234", "unknown"
	if got := resolve(nil); !got.Dirty {
		t.Fatalf("resolve(nil).Dirty = false for version %q", version)
	}
}
