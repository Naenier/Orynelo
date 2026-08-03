package target

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

func TestParseValidTargets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		input      string
		host       string
		port       uint16
		kind       model.TargetKind
		scheme     string
		useTLS     bool
		normalized string
	}{
		{
			name:       "bare hostname defaults to HTTPS",
			input:      "example.com",
			host:       "example.com",
			port:       443,
			kind:       model.TargetHTTP,
			scheme:     "https",
			useTLS:     true,
			normalized: "https://example.com:443",
		},
		{
			name:       "host and port is TCP",
			input:      "example.com:443",
			host:       "example.com",
			port:       443,
			kind:       model.TargetTCP,
			normalized: "example.com:443",
		},
		{
			name:       "HTTP default port",
			input:      "http://example.com/health",
			host:       "example.com",
			port:       80,
			kind:       model.TargetHTTP,
			scheme:     "http",
			normalized: "http://example.com:80/health",
		},
		{
			name:       "HTTPS explicit port and path",
			input:      "https://example.com:8443/a",
			host:       "example.com",
			port:       8443,
			kind:       model.TargetHTTP,
			scheme:     "https",
			useTLS:     true,
			normalized: "https://example.com:8443/a",
		},
		{
			name:       "IPv4 URL",
			input:      "http://10.10.0.25:8080/api/health",
			host:       "10.10.0.25",
			port:       8080,
			kind:       model.TargetHTTP,
			scheme:     "http",
			normalized: "http://10.10.0.25:8080/api/health",
		},
		{
			name:       "bracketed IPv6 endpoint",
			input:      "[2001:db8::1]:443",
			host:       "2001:db8::1",
			port:       443,
			kind:       model.TargetTCP,
			normalized: "[2001:db8::1]:443",
		},
		{
			name:       "IPv6 URL",
			input:      "https://[2001:db8::1]/",
			host:       "2001:db8::1",
			port:       443,
			kind:       model.TargetHTTP,
			scheme:     "https",
			useTLS:     true,
			normalized: "https://[2001:db8::1]:443/",
		},
		{
			name:       "bare IPv6 defaults to HTTPS",
			input:      "2001:db8::1",
			host:       "2001:db8::1",
			port:       443,
			kind:       model.TargetHTTP,
			scheme:     "https",
			useTLS:     true,
			normalized: "https://[2001:db8::1]:443",
		},
		{
			name:       "IDN normalized with lookup profile",
			input:      "https://пример.рф/путь",
			host:       "xn--e1afmkfd.xn--p1ai",
			port:       443,
			kind:       model.TargetHTTP,
			scheme:     "https",
			useTLS:     true,
			normalized: "https://xn--e1afmkfd.xn--p1ai:443/%D0%BF%D1%83%D1%82%D1%8C",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := Parse(test.input)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if got.Host != test.host || got.Port != test.port || got.Kind != test.kind ||
				got.Scheme != test.scheme || got.UseTLS != test.useTLS || got.Normalized != test.normalized {
				t.Fatalf("Parse() = %#v", got)
			}
		})
	}
}

func TestParseRemovesSecretsFromSerializableTarget(t *testing.T) {
	t.Parallel()
	const input = "https://alice:password@example.com/path?token=top-secret&view=full#fragment"
	got, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	text := string(serialized)
	for _, secret := range []string{"alice", "password", "top-secret", "fragment"} {
		if strings.Contains(text, secret) {
			t.Fatalf("serialized target leaked %q: %s", secret, text)
		}
	}
	if !strings.Contains(got.Normalized, "[REDACTED]") {
		t.Fatalf("normalized query was not redacted: %s", got.Normalized)
	}
	if !strings.Contains(got.RequestURL, "top-secret") {
		t.Fatalf("request URL should retain query only in json-excluded field: %s", got.RequestURL)
	}
	if strings.Contains(got.RequestURL, "alice") {
		t.Fatalf("request URL must not replay userinfo: %s", got.RequestURL)
	}
	if !got.PrivacyRedacted {
		t.Fatal("target did not retain privacy-redaction provenance for profile preview")
	}
}

func TestParsePreservesSchemeLessOriginalSyntax(t *testing.T) {
	t.Parallel()

	got, err := Parse("example.com/path?token=top-secret&view=full#fragment")
	if err != nil {
		t.Fatal(err)
	}
	if got.Original != "example.com/path?token=[REDACTED]&view=full" {
		t.Fatalf("Original = %q", got.Original)
	}
	if got.Normalized != "https://example.com:443/path?token=[REDACTED]&view=full" {
		t.Fatalf("Normalized = %q", got.Normalized)
	}
}

func TestParseRedactsSchemeLessURLUserinfo(t *testing.T) {
	t.Parallel()

	got, err := Parse("alice:password@example.com/path?token=top-secret&view=full#fragment")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got.Original != "example.com/path?token=[REDACTED]&view=full" {
		t.Fatalf("Original = %q", got.Original)
	}
	if got.RequestURL != "https://example.com:443/path?token=top-secret&view=full" {
		t.Fatalf("RequestURL = %q", got.RequestURL)
	}
}

func TestParseInvalidTargets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		code  string
	}{
		{"", ErrorEmptyTarget},
		{"   ", ErrorEmptyTarget},
		{"ftp://example.com", ErrorUnsupportedScheme},
		{"https:///path", ErrorMissingHost},
		{"example.com:0", ErrorInvalidPort},
		{"example.com:65536", ErrorInvalidPort},
		{"[2001:db8::1", ErrorInvalidTarget},
		{"bad host", ErrorInvalidTarget},
		{"https://example.com/\nheader", ErrorInvalidTarget},
	}
	for _, test := range tests {
		test := test
		t.Run(test.input, func(t *testing.T) {
			t.Parallel()
			_, err := Parse(test.input)
			if err == nil {
				t.Fatal("Parse() unexpectedly succeeded")
			}
			if got := ErrorCode(err); got != test.code {
				t.Fatalf("ErrorCode() = %q, want %q (error %v)", got, test.code, err)
			}
		})
	}
}
