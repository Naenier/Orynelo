package application

import (
	"strings"
	"testing"
)

func TestParseTransientHeadersKeepsValuesRuntimeOnlyAndReturnsSafeNames(t *testing.T) {
	headers, names, err := ParseTransientHeaders([]string{
		"Authorization: Bearer one-time-secret",
		"X-Incident: INC-42",
	})
	if err != nil {
		t.Fatalf("ParseTransientHeaders() error = %v", err)
	}
	if headers["authorization"] != "Bearer one-time-secret" {
		t.Fatalf("authorization header was not parsed: %#v", headers)
	}
	if strings.Join(names, ",") != "authorization,x-incident" {
		t.Fatalf("names = %v", names)
	}
}

func TestParseTransientHeadersRejectsRequestSmugglingAndManagedHeaders(t *testing.T) {
	tests := [][]string{
		{"X-Test: safe\r\nInjected: value"},
		{"Host: attacker.example"},
		{"Content-Length: 1"},
		{"Proxy-Authorization: secret"},
	}
	for _, lines := range tests {
		if _, _, err := ParseTransientHeaders(lines); err == nil {
			t.Fatalf("ParseTransientHeaders(%q) error = nil", lines)
		}
	}
}

func TestParseTransientHeadersDoesNotEchoInvalidSecretValue(t *testing.T) {
	secret := "invalid-secret"
	_, _, err := ParseTransientHeaders([]string{"X-Test: " + secret + "\r\n"})
	if err == nil {
		t.Fatal("ParseTransientHeaders() error = nil")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error exposed header value: %v", err)
	}
}
