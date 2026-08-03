//go:build windows

package main

import "os"

// terminationSignals returns the graceful-shutdown signals supported on Windows.
func terminationSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
