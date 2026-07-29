package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/Naenier/opsdoctor/internal/bootstrap"
	"github.com/Naenier/opsdoctor/internal/buildinfo"
	"github.com/Naenier/opsdoctor/internal/gui"
)

func main() {
	os.Exit(run())
}

func run() int {
	info := buildinfo.Current()
	runtime, err := bootstrap.OpenRuntime(info)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Could not start OpsDoctor Desktop:", err)
		return 1
	}
	defer func() {
		if err := runtime.Close(); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "Error closing OpsDoctor Desktop:", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), terminationSignals()...)
	defer stop()
	gui.Run(ctx, runtime.Service, info)
	return 0
}
