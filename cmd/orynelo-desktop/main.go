// Binary orynelo-desktop provides the graphical interface to the shared
// diagnostic application service.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Naenier/orynelo/internal/bootstrap"
	"github.com/Naenier/orynelo/internal/buildinfo"
	"github.com/Naenier/orynelo/internal/gui"
	"github.com/Naenier/orynelo/internal/platform"
)

// main exits the process with the desktop runtime result.
func main() {
	os.Exit(run())
}

// run initializes the runtime, starts the GUI, and coordinates cancellation.
func run() int {
	info := buildinfo.Current()
	ctx, stop := platform.NotifyShutdownContext(
		context.Background(),
		func() { os.Exit(130) },
		terminationSignals()...,
	)
	defer stop()
	policy := bootstrap.PersistenceDefault
	var runtime *bootstrap.Runtime
	for {
		var err error
		runtime, err = bootstrap.OpenRuntimeWithOptions(
			info,
			bootstrap.RuntimeOptions{Persistence: policy},
		)
		if err == nil {
			break
		}
		_, _ = fmt.Fprintln(os.Stderr, "Could not start Orynelo Desktop:", err)
		switch gui.RunStartupRecovery(ctx, info, err) {
		case gui.StartupRecoveryRetry:
			policy = bootstrap.PersistenceDefault
		case gui.StartupRecoveryEphemeral:
			policy = bootstrap.PersistenceEphemeral
		default:
			return 1
		}
	}
	defer func() {
		if err := runtime.Close(); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "Error closing Orynelo Desktop:", err)
		}
	}()
	gui.Run(ctx, runtime.Service, info)
	return 0
}
