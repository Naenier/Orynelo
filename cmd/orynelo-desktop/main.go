// Binary orynelo-desktop provides the graphical interface to the shared
// diagnostic application service.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/Naenier/orynelo/internal/bootstrap"
	"github.com/Naenier/orynelo/internal/buildinfo"
	"github.com/Naenier/orynelo/internal/gui"
)

// main exits the process with the desktop runtime result.
func main() {
	os.Exit(run())
}

// run initializes the runtime, starts the GUI, and coordinates cancellation.
func run() int {
	info := buildinfo.Current()
	runtime, err := bootstrap.OpenRuntime(info)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Could not start Orynelo Desktop:", err)
		return 1
	}
	defer func() {
		if err := runtime.Close(); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "Error closing Orynelo Desktop:", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), terminationSignals()...)
	defer stop()
	gui.Run(ctx, runtime.Service, info)
	return 0
}
