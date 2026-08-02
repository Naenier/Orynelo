// Package assets exposes application resources embedded in the executable.
package assets

import _ "embed"

// iconPNG contains the desktop application icon.
//
//go:embed Icon.png
var iconPNG []byte

// IconPNG returns the embedded PNG application icon.
func IconPNG() []byte {
	return iconPNG
}
