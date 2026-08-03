package application

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/privacy"
)

func TestResolveDiagnoseOptionsAppliesConfigOverDefaults(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	config.Diagnostics.DefaultTimeout = 30 * time.Second
	config.Diagnostics.CheckTimeout = 4 * time.Second
	config.Diagnostics.MaxRedirects = 7
	config.Diagnostics.PreferredIPVersion = "6"
	config.Diagnostics.CertificateWarningThreshold = 14 * 24 * time.Hour
	config.Network.UseSystemProxy = false
	config.Network.UserAgent = "OpsDoctor/config-test"

	got, err := ResolveDiagnoseOptions(config, nil, DiagnoseOverrides{
		Target: optionPointer("https://config.example/status"),
	})
	if err != nil {
		t.Fatalf("ResolveDiagnoseOptions() error = %v", err)
	}

	if got.Target != "https://config.example/status" ||
		got.Timeout != 30*time.Second ||
		got.CheckTimeout != 4*time.Second ||
		got.IPVersion != model.IPVersion6 ||
		!got.NoProxy ||
		got.MaxRedirects != 7 ||
		got.UserAgent != "OpsDoctor/config-test" ||
		got.CertificateWarningThreshold != 14*24*time.Hour {
		t.Fatalf("config-backed options = %+v", got)
	}
	if got.Method != "GET" ||
		got.ReportVerbosity != model.ReportVerbosityNormal ||
		got.MaxRedirectLocationBytes != 8<<10 ||
		got.ActualHTTPReserve != 4*time.Second ||
		got.MaxConcurrency != 4 ||
		got.BodyLimit != 64<<10 {
		t.Fatalf("model defaults were not retained and normalized: %+v", got)
	}
}

func TestResolveDiagnoseOptionsAppliesProfileOverConfig(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	config.Diagnostics.DefaultTimeout = 40 * time.Second
	config.Diagnostics.CheckTimeout = 8 * time.Second
	config.Diagnostics.MaxRedirects = 9
	config.Diagnostics.PreferredIPVersion = "6"
	config.Network.UseSystemProxy = true

	profile := model.Profile{
		Name:         "saved",
		Target:       "example.test:9443",
		Mode:         model.DiagnosticModeTLS,
		IPVersion:    model.IPVersion4,
		Timeout:      12 * time.Second,
		CheckTimeout: 3 * time.Second,
		NoProxy:      true,
		EnableTLS:    false, // Mode is canonical when redundant fields disagree.
		MaxRedirects: 2,
		Method:       "HEAD",
	}
	original := profile

	got, err := ResolveDiagnoseOptions(config, &profile, DiagnoseOverrides{})
	if err != nil {
		t.Fatalf("ResolveDiagnoseOptions() error = %v", err)
	}
	if !reflect.DeepEqual(profile, original) {
		t.Fatalf("profile was mutated: got %+v, want %+v", profile, original)
	}
	if got.Target != "example.test:9443" ||
		got.Timeout != 12*time.Second ||
		got.CheckTimeout != 3*time.Second ||
		got.IPVersion != model.IPVersion4 ||
		!got.NoProxy ||
		!got.EnableTLS ||
		got.MaxRedirects != 2 ||
		got.Method != "HEAD" {
		t.Fatalf("profile-backed options = %+v", got)
	}
	if got.ActualHTTPReserve != 3*time.Second {
		t.Fatalf("ActualHTTPReserve = %s, want 3s", got.ActualHTTPReserve)
	}
}

func TestResolveDiagnoseOptionsAppliesExplicitOverridesLast(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	config.Network.UseSystemProxy = false
	profile := model.Profile{
		Name:         "saved",
		Target:       "profile.example:443",
		Mode:         model.DiagnosticModeTLS,
		IPVersion:    model.IPVersion4,
		Timeout:      12 * time.Second,
		CheckTimeout: 3 * time.Second,
		NoProxy:      true,
		EnableTLS:    true,
		MaxRedirects: 4,
		Method:       "HEAD",
	}

	got, err := ResolveDiagnoseOptions(config, &profile, DiagnoseOverrides{
		Target:                      optionPointer("  https://override.example/path  "),
		Mode:                        optionPointer(model.DiagnosticModeAuto),
		Timeout:                     optionPointer(18 * time.Second),
		CheckTimeout:                optionPointer(2 * time.Second),
		IPVersion:                   optionPointer(model.IPVersion6),
		NoProxy:                     optionPointer(false),
		Insecure:                    optionPointer(true),
		EnableTLS:                   optionPointer(true),
		MaxRedirects:                optionPointer(0),
		MaxRedirectLocationBytes:    optionPointer(1024),
		AllowInsecureRedirects:      optionPointer(true),
		AllowPrivateRedirects:       optionPointer(true),
		ActualHTTPReserve:           optionPointer(time.Second),
		Method:                      optionPointer(" options "),
		ReportVerbosity:             optionPointer(model.ReportVerbosityVerbose),
		UserAgent:                   optionPointer("OpsDoctor/override"),
		CertificateWarningThreshold: optionPointer(48 * time.Hour),
		MaxConcurrency:              optionPointer(8),
		BodyLimit:                   optionPointer(int64(2048)),
	})
	if err != nil {
		t.Fatalf("ResolveDiagnoseOptions() error = %v", err)
	}

	want := model.DiagnoseOptions{
		Target:                      "https://override.example/path",
		Timeout:                     18 * time.Second,
		CheckTimeout:                2 * time.Second,
		IPVersion:                   model.IPVersion6,
		NoProxy:                     false,
		Insecure:                    true,
		EnableTLS:                   true,
		MaxRedirects:                0,
		MaxRedirectLocationBytes:    1024,
		AllowInsecureRedirects:      true,
		AllowPrivateRedirects:       true,
		ActualHTTPReserve:           time.Second,
		Method:                      "OPTIONS",
		ReportVerbosity:             model.ReportVerbosityVerbose,
		UserAgent:                   "OpsDoctor/override",
		CertificateWarningThreshold: 48 * time.Hour,
		MaxConcurrency:              8,
		BodyLimit:                   2048,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveDiagnoseOptions() =\n%+v\nwant\n%+v", got, want)
	}
}

func TestResolveDiagnoseOptionsTCPModeCanonicalizesTarget(t *testing.T) {
	t.Parallel()

	got, err := ResolveDiagnoseOptions(DefaultConfig(), nil, DiagnoseOverrides{
		Target: optionPointer(" https://Example.Test:8443/private?q=1 "),
		Mode:   optionPointer(model.DiagnosticModeTCP),
	})
	if err != nil {
		t.Fatalf("ResolveDiagnoseOptions() error = %v", err)
	}
	if got.Target != "example.test:8443" {
		t.Fatalf("Target = %q, want %q", got.Target, "example.test:8443")
	}
	if got.EnableTLS {
		t.Fatal("EnableTLS = true in TCP mode")
	}
}

func TestResolveDiagnoseOptionsNormalizesInterfaceAliases(t *testing.T) {
	t.Parallel()

	got, err := ResolveDiagnoseOptions(DefaultConfig(), nil, DiagnoseOverrides{
		Target:          optionPointer("example.test"),
		Mode:            optionPointer(model.DiagnosticMode(" TLS ")),
		IPVersion:       optionPointer(model.IPVersion(" IPv6 ")),
		Method:          optionPointer(" head "),
		ReportVerbosity: optionPointer(model.ReportVerbosity(" VERBOSE ")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.IPVersion != model.IPVersion6 || got.Method != "HEAD" ||
		got.ReportVerbosity != model.ReportVerbosityVerbose || !got.EnableTLS {
		t.Fatalf("normalized options = %+v", got)
	}
}

func TestResolveDiagnoseOptionsFallsBackFromEmptyConfiguredUserAgent(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	config.Network.UserAgent = ""
	got, err := ResolveDiagnoseOptions(config, nil, DiagnoseOverrides{
		Target: optionPointer("example.test"),
	})
	if err != nil {
		t.Fatalf("ResolveDiagnoseOptions() error = %v", err)
	}
	if got.UserAgent != model.DefaultDiagnoseOptions("").UserAgent {
		t.Fatalf("UserAgent = %q, want model default", got.UserAgent)
	}
}

func TestPreviewDiagnoseOptionsProjectsRequestCapableValues(t *testing.T) {
	t.Parallel()

	rawTarget := "https://alice:password@example.test/private?access_token=target-secret&view=full"
	rawUserAgent := "client https://bob:password@agent.test/?token=agent-secret"
	overrides := DiagnoseOverrides{
		Target:    &rawTarget,
		UserAgent: &rawUserAgent,
	}
	execution, err := ResolveDiagnoseOptions(DefaultConfig(), nil, overrides)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := PreviewDiagnoseOptions(
		DefaultConfig(),
		nil,
		overrides,
		privacy.ModeStandard,
	)
	if err != nil {
		t.Fatal(err)
	}
	if execution.Target != rawTarget || execution.UserAgent != rawUserAgent {
		t.Fatalf("execution options were projected: %+v", execution)
	}
	for _, secret := range []string{"alice", "password", "target-secret", "bob", "agent-secret"} {
		if strings.Contains(preview.Target, secret) || strings.Contains(preview.UserAgent, secret) {
			t.Fatalf("preview leaked %q: %+v", secret, preview)
		}
	}
	if !strings.Contains(preview.Target, "view=full") {
		t.Fatalf("standard preview removed non-sensitive query context: %q", preview.Target)
	}
}

func TestResolveDiagnoseOptionsRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	config.Diagnostics.CheckTimeout = config.Diagnostics.DefaultTimeout + time.Second
	_, err := ResolveDiagnoseOptions(config, nil, DiagnoseOverrides{
		Target: optionPointer("example.test"),
	})
	if err == nil || !IsErrorCategory(err, ErrorCategoryConfiguration) ||
		!strings.Contains(resolutionCauseText(err), "invalid configuration") {
		t.Fatalf("ResolveDiagnoseOptions() error = %v, want invalid configuration", err)
	}
}

func TestResolveDiagnoseOptionsValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		overrides DiagnoseOverrides
		want      string
	}{
		{name: "empty target", overrides: DiagnoseOverrides{Target: optionPointer("  ")}, want: "target is required"},
		{name: "long target", overrides: DiagnoseOverrides{Target: optionPointer(strings.Repeat("a", maximumDiagnoseTargetBytes+1))}, want: "4096 bytes"},
		{name: "invalid target", overrides: DiagnoseOverrides{Target: optionPointer("https://")}, want: "invalid target"},
		{name: "invalid mode", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), Mode: optionPointer(model.DiagnosticMode("udp"))}, want: "mode must be"},
		{name: "zero timeout", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), Timeout: optionPointer(time.Duration(0))}, want: "timeout must be"},
		{name: "long timeout", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), Timeout: optionPointer(25 * time.Hour)}, want: "timeout must be"},
		{name: "zero check timeout", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), CheckTimeout: optionPointer(time.Duration(0))}, want: "check timeout must be"},
		{name: "check exceeds total", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), Timeout: optionPointer(time.Second), CheckTimeout: optionPointer(2 * time.Second)}, want: "must not exceed"},
		{name: "invalid IP version", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), IPVersion: optionPointer(model.IPVersion("5"))}, want: "IP version must be"},
		{name: "negative redirects", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), MaxRedirects: optionPointer(-1)}, want: "maximum redirects"},
		{name: "too many redirects", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), MaxRedirects: optionPointer(51)}, want: "maximum redirects"},
		{name: "zero Location limit", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), MaxRedirectLocationBytes: optionPointer(0)}, want: "Location limit"},
		{name: "large Location limit", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), MaxRedirectLocationBytes: optionPointer(65 << 10)}, want: "Location limit"},
		{name: "negative HTTP reserve", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), ActualHTTPReserve: optionPointer(-time.Second)}, want: "HTTP reserve"},
		{name: "HTTP reserve equals timeout", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), ActualHTTPReserve: optionPointer(15 * time.Second)}, want: "HTTP reserve"},
		{name: "unsafe method", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), Method: optionPointer("POST")}, want: "GET, HEAD, or OPTIONS"},
		{name: "method whitespace", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), Method: optionPointer("GE T")}, want: "contains whitespace"},
		{name: "invalid verbosity", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), ReportVerbosity: optionPointer(model.ReportVerbosity("trace"))}, want: "verbosity"},
		{name: "empty user agent", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), UserAgent: optionPointer("")}, want: "user agent"},
		{name: "control in user agent", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), UserAgent: optionPointer("bad\nagent")}, want: "user agent"},
		{name: "long user agent", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), UserAgent: optionPointer(strings.Repeat("a", 257))}, want: "user agent"},
		{name: "negative certificate threshold", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), CertificateWarningThreshold: optionPointer(-time.Second)}, want: "certificate warning"},
		{name: "large certificate threshold", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), CertificateWarningThreshold: optionPointer(366 * 24 * time.Hour)}, want: "certificate warning"},
		{name: "zero concurrency", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), MaxConcurrency: optionPointer(0)}, want: "concurrency"},
		{name: "large concurrency", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), MaxConcurrency: optionPointer(33)}, want: "concurrency"},
		{name: "zero body limit", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), BodyLimit: optionPointer(int64(0))}, want: "body limit"},
		{name: "large body limit", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), BodyLimit: optionPointer(int64(4<<20 + 1))}, want: "body limit"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ResolveDiagnoseOptions(DefaultConfig(), nil, test.overrides)
			if err == nil || !IsErrorCategory(err, ErrorCategoryValidation) ||
				!strings.Contains(resolutionCauseText(err), test.want) {
				t.Fatalf("ResolveDiagnoseOptions() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestResolveDiagnoseOptionsExposesSafeValidationField(t *testing.T) {
	t.Parallel()

	invalid := "https://"
	_, err := ResolveDiagnoseOptions(DefaultConfig(), nil, DiagnoseOverrides{Target: &invalid})
	view := ToErrorView(err)
	if view == nil || view.Category != ErrorCategoryValidation ||
		view.Code != "APP_DIAGNOSE_OPTIONS_INVALID" ||
		view.Arguments["field"] != "target" {
		t.Fatalf("validation view = %#v", view)
	}
	encoded, marshalErr := json.Marshal(view)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(string(encoded), invalid) || strings.Contains(string(encoded), "invalid target") {
		t.Fatalf("validation view exposed raw cause: %s", encoded)
	}
}

func optionPointer[T any](value T) *T {
	return &value
}

func resolutionCauseText(err error) string {
	applicationError, ok := AsError(err)
	if !ok {
		return ""
	}
	cause := errors.Unwrap(applicationError)
	if cause == nil {
		return ""
	}
	return strings.TrimSpace(cause.Error())
}
