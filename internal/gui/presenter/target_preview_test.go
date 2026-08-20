package presenter

import "testing"

func TestTargetPreviewExplainsExplicitAndSelectedModesWithoutSecrets(t *testing.T) {
	tests := []struct {
		raw  string
		mode string
		want string
	}{
		{raw: "example.test", mode: "auto", want: "https://example.test:443"},
		{raw: "example.test:8443", mode: "tcp", want: "tcp://example.test:8443"},
		{raw: "example.test:8443", mode: "tls", want: "tls://example.test:8443"},
		{raw: "tcp://example.test:22", mode: "auto", want: "tcp://example.test:22"},
		{raw: "tls://example.test:8443", mode: "auto", want: "tls://example.test:8443"},
		{raw: "http://example.test/path", mode: "auto", want: "http://example.test:80/path"},
		{raw: "https://example.test/path", mode: "auto", want: "https://example.test:443/path"},
		{raw: "tls://[fe80::2%25en0]:443", mode: "auto", want: "tls://[fe80::2%25en0]:443"},
		{raw: "https://user:secret@example.test/path?token=secret", mode: "auto", want: "https://example.test:443/path?token=[REDACTED]"},
	}
	for _, test := range tests {
		got, err := TargetPreview(test.raw, test.mode)
		if err != nil {
			t.Fatalf("TargetPreview(%q, %q) error = %v", test.raw, test.mode, err)
		}
		if got != test.want {
			t.Fatalf("TargetPreview(%q, %q) = %q, want %q", test.raw, test.mode, got, test.want)
		}
	}
}

func TestTargetPreviewRejectsExplicitModeConflict(t *testing.T) {
	if _, err := TargetPreview("https://example.test", "tcp"); err == nil {
		t.Fatal("TargetPreview() conflict error = nil")
	}
}

func TestTargetPreviewRejectsSchemeLessURLComponentsInTransportMode(t *testing.T) {
	if preview, err := TargetPreview(
		"example.test:443/private?token=preview-mode-secret",
		"tls",
	); err == nil || preview != "" {
		t.Fatalf("TargetPreview() = %q, %v; want safe rejection", preview, err)
	}
}

func TestTargetPreviewRejectsURLComponentsInTransportMode(t *testing.T) {
	t.Parallel()
	if _, err := TargetPreview("example.test/path?token=secret", "tls"); err == nil {
		t.Fatal("TargetPreview() accepted URL components in explicit TLS mode")
	}
}
