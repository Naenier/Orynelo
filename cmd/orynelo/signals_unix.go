//go:build !windows

package main

import (
	"os"
	"syscall"
)

// terminationSignals returns the graceful-shutdown signals supported on Unix.
func terminationSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}
