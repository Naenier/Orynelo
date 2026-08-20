package application

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/privacy"
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
	config.Network.UserAgent = "Orynelo/config-test"

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
		got.UserAgent != "Orynelo/config-test" ||
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
	if got.Target != "tls://example.test:9443" ||
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
		UserAgent:                   optionPointer("Orynelo/override"),
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
		ProbeMode:                   model.ProbeModeClientEffective,
		AddressLimit:                4,
		AddressMatrixBudget:         5 * time.Second,
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
		UserAgent:                   "Orynelo/override",
		CertificateWarningThreshold: 48 * time.Hour,
		MaxConcurrency:              8,
		BodyLimit:                   2048,
		ExpectedStatusMin:           200,
		ExpectedStatusMax:           399,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveDiagnoseOptions() =\n%+v\nwant\n%+v", got, want)
	}
}

func TestResolveDiagnoseOptionsTCPModeCanonicalizesTarget(t *testing.T) {
	t.Parallel()

	got, err := ResolveDiagnoseOptions(DefaultConfig(), nil, DiagnoseOverrides{
		Target: optionPointer(" Example.Test:8443 "),
		Mode:   optionPointer(model.DiagnosticModeTCP),
	})
	if err != nil {
		t.Fatalf("ResolveDiagnoseOptions() error = %v", err)
	}
	if got.Target != "tcp://example.test:8443" {
		t.Fatalf("Target = %q, want %q", got.Target, "tcp://example.test:8443")
	}
	if got.EnableTLS {
		t.Fatal("EnableTLS = true in TCP mode")
	}
}

func TestResolveDiagnoseOptionsAcceptsExplicitSchemesAndLinkLocalZone(t *testing.T) {
	t.Parallel()
	for _, target := range []string{
		"tcp://example.test:443",
		"tls://example.test:443",
		"http://example.test/path",
		"https://example.test/path",
	} {
		target := target
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			got, err := ResolveDiagnoseOptions(DefaultConfig(), nil, DiagnoseOverrides{
				Target: &target,
			})
			if err != nil {
				t.Fatalf("ResolveDiagnoseOptions(%q) error = %v", target, err)
			}
			if got.Target != target {
				t.Fatalf("Target = %q, want %q", got.Target, target)
			}
		})
	}

	target := "tls://[fe80::1%25eth0]:443"
	connectIP := "fe80::2%eth0"
	ipVersion := model.IPVersion6
	got, err := ResolveDiagnoseOptions(DefaultConfig(), nil, DiagnoseOverrides{
		Target:    &target,
		IPVersion: &ipVersion,
		ConnectIP: &connectIP,
	})
	if err != nil {
		t.Fatalf("link-local ResolveDiagnoseOptions() error = %v", err)
	}
	if got.ConnectIP != connectIP {
		t.Fatalf("ConnectIP = %q, want %q", got.ConnectIP, connectIP)
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

func TestResolveDiagnoseOptionsAppliesStageThreeRuntimeOverridesWithoutSerializingSecrets(t *testing.T) {
	probeMode := model.ProbeModeAddressMatrix
	addressLimit := 7
	matrixBudget := 4 * time.Second
	expectedMin, expectedMax := 201, 204
	latency := 750 * time.Millisecond
	connectIP := "192.0.2.44"
	serverName := "node.example.test"
	httpHost := "service.example.test:8443"
	caPath := "/runtime/only/ca.pem"
	collectDNS, inspectBody := true, true
	got, err := ResolveDiagnoseOptions(DefaultConfig(), nil, DiagnoseOverrides{
		Target:              optionPointer("https://service.example.test:8443/health"),
		ProbeMode:           &probeMode,
		AddressLimit:        &addressLimit,
		AddressMatrixBudget: &matrixBudget,
		ExpectedStatusMin:   &expectedMin,
		ExpectedStatusMax:   &expectedMax,
		LatencyThreshold:    &latency,
		ConnectIP:           &connectIP,
		ServerName:          &serverName,
		HTTPHost:            &httpHost,
		CustomCABundlePath:  &caPath,
		CollectDNSDetails:   &collectDNS,
		InspectBody:         &inspectBody,
		RequestHeaders: map[string]string{
			"Authorization": "Bearer stage-three-secret",
			"X-Incident":    "INC-42",
		},
	})
	if err != nil {
		t.Fatalf("ResolveDiagnoseOptions() error = %v", err)
	}
	if got.ProbeMode != probeMode || got.AddressLimit != addressLimit ||
		got.AddressMatrixBudget != matrixBudget || !got.ExpectedStatusConfigured ||
		got.ExpectedStatusMin != expectedMin || got.ExpectedStatusMax != expectedMax ||
		got.LatencyThreshold != latency || got.ConnectIP != connectIP ||
		got.ServerName != serverName || got.HTTPHost != httpHost ||
		!got.CustomCAConfigured || !got.CollectDNSDetails || !got.InspectBody ||
		got.RequestHeaders["authorization"] == "" {
		t.Fatalf("stage-three options = %+v", got)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(encoded)
	for _, forbidden := range []string{"stage-three-secret", caPath, "INC-42"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("serialized options exposed runtime-only value %q: %s", forbidden, serialized)
		}
	}
}

func TestPreviewDiagnoseOptionsUsesNormalizedPrivacySafeTarget(t *testing.T) {
	caPath := "/runtime/private/ca.pem"
	preview, err := PreviewDiagnoseOptions(
		DefaultConfig(),
		nil,
		DiagnoseOverrides{
			Target:             optionPointer("https://user:password@Example.Test/path?token=secret"),
			CustomCABundlePath: &caPath,
			RequestHeaders: map[string]string{
				"Authorization": "Bearer preview-header-secret",
				"X-Incident":    "INC-preview-secret",
			},
		},
		privacy.ModeStandard,
	)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Target != "https://example.test:443/path?token=[REDACTED]" ||
		strings.Contains(preview.Target, "password") || strings.Contains(preview.Target, "secret") {
		t.Fatalf("preview target = %q", preview.Target)
	}
	if preview.CustomCABundlePath != "" || preview.CustomCAPEM != nil || preview.RequestHeaders != nil {
		t.Fatalf("preview retained runtime-only options: %+v", preview)
	}
	if !preview.CustomCAConfigured ||
		strings.Join(preview.RequestHeaderNames, ",") != "authorization,x-incident" {
		t.Fatalf("preview omitted safe runtime metadata: %+v", preview)
	}
	encoded, err := json.Marshal(preview)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"password", "secret", caPath, "preview-header-secret", "INC-preview-secret",
	} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("preview JSON leaked %q: %s", secret, encoded)
		}
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
		{name: "scheme-less path in explicit TLS mode", overrides: DiagnoseOverrides{Target: optionPointer("example.test:443/private?token=mode-secret"), Mode: optionPointer(model.DiagnosticModeTLS)}, want: "does not accept URL paths"},
		{name: "zero timeout", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), Timeout: optionPointer(time.Duration(0))}, want: "timeout must be"},
		{name: "long timeout", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), Timeout: optionPointer(25 * time.Hour)}, want: "timeout must be"},
		{name: "zero check timeout", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), CheckTimeout: optionPointer(time.Duration(0))}, want: "check timeout must be"},
		{name: "check exceeds total", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), Timeout: optionPointer(time.Second), CheckTimeout: optionPointer(2 * time.Second)}, want: "must not exceed"},
		{name: "invalid IP version", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), IPVersion: optionPointer(model.IPVersion("5"))}, want: "IP version must be"},
		{name: "invalid probe mode", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), ProbeMode: optionPointer(model.ProbeMode("scan"))}, want: "probe mode"},
		{name: "zero address limit", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), AddressLimit: optionPointer(0)}, want: "address limit"},
		{name: "large address limit", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), AddressLimit: optionPointer(17)}, want: "address limit"},
		{name: "negative matrix budget", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), AddressMatrixBudget: optionPointer(-time.Second)}, want: "matrix budget"},
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
		{name: "invalid expected status", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), ExpectedStatusMin: optionPointer(99), ExpectedStatusMax: optionPointer(200)}, want: "expected HTTP status"},
		{name: "reversed expected status", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), ExpectedStatusMin: optionPointer(300), ExpectedStatusMax: optionPointer(200)}, want: "expected HTTP status"},
		{name: "negative latency", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), LatencyThreshold: optionPointer(-time.Second)}, want: "latency threshold"},
		{name: "invalid connect IP", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), ConnectIP: optionPointer("not-an-ip")}, want: "connect IP"},
		{name: "connect IP family mismatch", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), IPVersion: optionPointer(model.IPVersion4), ConnectIP: optionPointer("2001:db8::1")}, want: "does not match"},
		{name: "zone on global IP", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), ConnectIP: optionPointer("2001:db8::1%eth0")}, want: "zone"},
		{name: "invalid SNI", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), ServerName: optionPointer("bad/name")}, want: "invalid characters"},
		{name: "insecure custom CA", overrides: DiagnoseOverrides{Target: optionPointer("example.test"), Insecure: optionPointer(true), CustomCABundlePath: optionPointer("ca.pem")}, want: "mutually exclusive"},
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
