package redaction

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRedactURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "userinfo and sensitive query",
			in:   "https://alice:p%40ss@example.test/path?token=abc&view=full",
			want: "https://example.test/path?token=[REDACTED]&view=full",
		},
		{
			name: "all required names and case insensitive",
			in: "https://example.test/?token=1&access_token=2&api_key=3&apikey=4&key=5&secret=6" +
				"&password=7&passwd=8&signature=9&sig=10&auth=11&credential=12&safe=13",
			want: "https://example.test/?token=[REDACTED]&access_token=[REDACTED]&api_key=[REDACTED]" +
				"&apikey=[REDACTED]&key=[REDACTED]&secret=[REDACTED]&password=[REDACTED]" +
				"&passwd=[REDACTED]&signature=[REDACTED]&sig=[REDACTED]&auth=[REDACTED]" +
				"&credential=[REDACTED]&safe=13",
		},
		{
			name: "encoded key",
			in:   "https://example.test/?access%5Ftoken=secret",
			want: "https://example.test/?access%5Ftoken=[REDACTED]",
		},
		{
			name: "semicolon separator",
			in:   "https://example.test/?safe=yes;client_secret=no",
			want: "https://example.test/?safe=yes;client_secret=[REDACTED]",
		},
		{
			name: "IPv6 proxy",
			in:   "http://proxy-user:proxy-password@[2001:db8::1]:8080",
			want: "http://[2001:db8::1]:8080",
		},
		{
			name: "malformed URL is scrubbed",
			in:   "https://user:pass@example.test/%zz?token=secret&safe=yes",
			want: "https://example.test/%zz?token=[REDACTED]&safe=yes",
		},
		{
			name: "malformed URL fragment is scrubbed",
			in:   "https://user:pass@example.test/%zz#access_token=fragment-secret",
			want: "https://example.test/%zz#access_token=[REDACTED]",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := RedactURL(tt.in); got != tt.want {
				t.Fatalf("RedactURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRedactParsedURLDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	input, err := url.Parse("https://user:pass@example.test/?api_key=secret")
	if err != nil {
		t.Fatal(err)
	}
	got := RedactParsedURL(input)
	if input.User == nil || input.RawQuery != "api_key=secret" {
		t.Fatal("RedactParsedURL() mutated its input")
	}
	if strings.Contains(got.String(), "user") || strings.Contains(got.String(), "secret") {
		t.Fatalf("RedactParsedURL() leaked a value: %s", got)
	}
}

func TestRedactProxyURLWithoutScheme(t *testing.T) {
	t.Parallel()

	got := RedactProxyURL("proxy-user:proxy-password@proxy.test:8080")
	if got != "proxy.test:8080" {
		t.Fatalf("RedactProxyURL() = %q", got)
	}
}

func TestRedactHeaders(t *testing.T) {
	t.Parallel()

	input := http.Header{
		"Authorization":       {"Bearer secret"},
		"Proxy-Authorization": {"Basic secret"},
		"Cookie":              {"session=secret"},
		"Set-Cookie":          {"session=secret"},
		"Location":            {"https://user:pass@example.test/callback?access_token=secret&ok=yes"},
		"X-Trace":             {"visible"},
	}
	got := RedactHeaders(input)
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie"} {
		if value := got.Get(name); value != Replacement {
			t.Errorf("%s = %q, want replacement", name, value)
		}
	}
	if value := got.Get("Location"); value != "https://example.test/callback?access_token=[REDACTED]&ok=yes" {
		t.Errorf("Location = %q", value)
	}
	if got.Get("X-Trace") != "visible" {
		t.Errorf("X-Trace = %q", got.Get("X-Trace"))
	}
	if input.Get("Authorization") != "Bearer secret" {
		t.Fatal("RedactHeaders() mutated input")
	}
}

func TestRedactText(t *testing.T) {
	t.Parallel()

	input := "proxy=https://user:pass@proxy.test:8443?token=secret Authorization: Bearer abc\nsafe=yes"
	got := RedactText(input)
	for _, secret := range []string{"user", "pass", "secret", "Bearer abc"} {
		if strings.Contains(got, secret) {
			t.Fatalf("RedactText() = %q, contains %q", got, secret)
		}
	}
	if !strings.Contains(got, "safe=yes") {
		t.Fatalf("RedactText() removed non-sensitive data: %q", got)
	}
}

func TestSensitiveNames(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"token", "ACCESS_TOKEN", "client-secret", "my_session_token", "password[]"} {
		if !IsSensitiveQueryKey(name) {
			t.Errorf("IsSensitiveQueryKey(%q) = false", name)
		}
	}
	for _, name := range []string{"monkey", "hockey", "view", "username"} {
		if IsSensitiveQueryKey(name) {
			t.Errorf("IsSensitiveQueryKey(%q) = true", name)
		}
	}
	for _, name := range []string{"Authorization", "proxy-authorization", "Cookie", "Set-Cookie", "X-API-Key"} {
		if !IsSensitiveHeader(name) {
			t.Errorf("IsSensitiveHeader(%q) = false", name)
		}
	}
	for _, name := range []string{
		"responseHeader.Authorization", "request.headers[Cookie]", "query/access_token",
	} {
		if !IsSensitiveStructuredKey(name) {
			t.Errorf("IsSensitiveStructuredKey(%q) = false", name)
		}
	}
}

func TestSlogHandler(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	handler := NewHandler(slog.NewJSONHandler(&output, nil))
	logger := slog.New(handler).With("api_key", "with-secret")
	logger.LogAttrs(
		context.Background(),
		slog.LevelInfo,
		"request https://user:pass@example.test/?token=message-secret",
		slog.String("authorization", "Bearer attr-secret"),
		slog.Any("headers", http.Header{"Cookie": {"cookie-secret"}, "X-Trace": {"visible"}}),
		slog.Group("request", slog.String("url", "https://u:p@example.test/?key=group-secret")),
		slog.Any("nested", map[string]any{
			"client_secret": "nested-secret",
			"safe":          "kept",
		}),
	)

	logged := output.String()
	for _, secret := range []string{
		"with-secret",
		"message-secret",
		"attr-secret",
		"cookie-secret",
		"group-secret",
		"nested-secret",
		"user",
		"pass",
	} {
		if strings.Contains(logged, secret) {
			t.Fatalf("slog output contains %q: %s", secret, logged)
		}
	}
	if !strings.Contains(logged, Replacement) || !strings.Contains(logged, "visible") {
		t.Fatalf("unexpected slog output: %s", logged)
	}
}

func TestSlogHandlerHandlesNilAndRecursiveValues(t *testing.T) {
	t.Parallel()

	_ = NewHandler(nil)
	recursive := map[string]any{}
	recursive["self"] = recursive

	var output bytes.Buffer
	logger := slog.New(NewHandler(slog.NewJSONHandler(&output, nil)))
	logger.Info("recursive", "value", recursive)
	if output.Len() == 0 {
		t.Fatal("recursive value was not logged")
	}
}

func TestSlogHandlerDoesNotRecursivelySerializeUnknownAnyValues(t *testing.T) {
	t.Parallel()

	type unapprovedPayload struct {
		Visible string
		Secret  string
	}
	var output bytes.Buffer
	logger := slog.New(NewHandler(slog.NewJSONHandler(&output, nil)))
	logger.Info(
		"unknown payload",
		slog.Any("payload", unapprovedPayload{Visible: "struct-visible", Secret: "struct-secret"}),
		slog.Any("nested", map[string]any{
			"safe":                         "map-visible",
			"unknown":                      unapprovedPayload{Visible: "nested-visible", Secret: "nested-secret"},
			"responseHeader.Authorization": "Bearer namespaced-log-secret",
		}),
	)

	logged := output.String()
	for _, leaked := range []string{
		"struct-visible", "struct-secret", "nested-visible", "nested-secret", "namespaced-log-secret",
	} {
		if strings.Contains(logged, leaked) {
			t.Fatalf("slog recursively serialized unknown value %q: %s", leaked, logged)
		}
	}
	if !strings.Contains(logged, "map-visible") || !strings.Contains(logged, Replacement) {
		t.Fatalf("slog did not preserve safe map data and mark unknown values: %s", logged)
	}
}

type unsafeStringer struct{}

func (unsafeStringer) String() string { return "custom-stringer-secret" }

func TestSlogHandlerDoesNotTrustArbitraryStringers(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	logger := slog.New(NewHandler(slog.NewJSONHandler(&output, nil)))
	logger.Info("stringer", slog.Any("payload", unsafeStringer{}))
	if strings.Contains(output.String(), "custom-stringer-secret") {
		t.Fatalf("slog trusted an arbitrary Stringer: %s", output.String())
	}
	if !strings.Contains(output.String(), Replacement) {
		t.Fatalf("slog did not mark an unknown Stringer: %s", output.String())
	}
}

type unsafeLogValuer struct {
	calls *atomic.Int32
}

func (value unsafeLogValuer) LogValue() slog.Value {
	value.calls.Add(1)
	return slog.StringValue("bare-custom-logvaluer-secret")
}

func TestSlogHandlerDoesNotResolveArbitraryLogValuers(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	var calls atomic.Int32
	logger := slog.New(NewHandler(slog.NewJSONHandler(&output, nil)))
	logger.Info("logvaluer", slog.Any("payload", unsafeLogValuer{calls: &calls}))
	if strings.Contains(output.String(), "custom-logvaluer-secret") {
		t.Fatalf("slog resolved an arbitrary LogValuer: %s", output.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("slog invoked an arbitrary LogValuer %d time(s)", calls.Load())
	}
	if !strings.Contains(output.String(), Replacement) {
		t.Fatalf("slog did not mark an unknown LogValuer: %s", output.String())
	}
}
