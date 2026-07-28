// Package buildinfo exposes immutable metadata about the running binary.
package buildinfo

import (
	"runtime"
	"runtime/debug"
	"strings"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// Info describes the source and toolchain used to build the application.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
	Dirty     bool   `json:"dirty"`
	GoVersion string `json:"goVersion"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Current returns metadata for the running binary. Linker-injected values take
// precedence; Go module and VCS build settings provide a fallback for local
// builds and binaries installed with "go install".
func Current() Info {
	build, ok := debug.ReadBuildInfo()
	if !ok {
		return resolve(nil)
	}

	return resolve(build)
}

// Get is an alias for Current retained for callers that prefer getter naming.
func Get() Info {
	return Current()
}

func resolve(build *debug.BuildInfo) Info {
	info := Info{
		Version:   version,
		Commit:    commit,
		BuildDate: buildDate,
		Dirty:     strings.HasSuffix(version, ".dirty"),
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}

	if build == nil {
		return info
	}

	if info.Version == "dev" && build.Main.Version != "" && build.Main.Version != "(devel)" {
		info.Version = strings.TrimPrefix(build.Main.Version, "v")
	}

	for _, setting := range build.Settings {
		switch setting.Key {
		case "vcs.revision":
			if info.Commit == "unknown" && setting.Value != "" {
				info.Commit = setting.Value
			}
		case "vcs.time":
			if info.BuildDate == "unknown" && setting.Value != "" {
				info.BuildDate = setting.Value
			}
		case "vcs.modified":
			if setting.Value == "true" {
				info.Dirty = true
			}
		}
	}

	return info
}
