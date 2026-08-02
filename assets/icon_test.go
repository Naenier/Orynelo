package assets

import (
	"bytes"
	"image/png"
	"testing"
)

func TestIconPNG(t *testing.T) {
	data := IconPNG()
	if len(data) == 0 {
		t.Fatal("embedded application icon is empty")
	}

	image, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode embedded application icon: %v", err)
	}
	if image.Width != 1024 || image.Height != 1024 {
		t.Fatalf("embedded application icon is %dx%d, want 1024x1024", image.Width, image.Height)
	}
}
