package environment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

func TestCheckProxySelectionAndSanitization(t *testing.T) {
	t.Parallel()
	values := map[string]string{
		"HTTPS_PROXY": "http://user:password@proxy.example:8080",
	}
	check := &Check{LookupEnv: func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}}
	options := model.DefaultDiagnoseOptions("https://example.com")
	state := model.NewState(model.Target{
		Scheme: "https", Host: "example.com", Port: 443,
		RequestURL: "https://example.com:443/",
	}, options)
	result := check.Run(context.Background(), state)
	if result.Status != model.StatusWarning {
		t.Fatalf("result = %#v", result)
	}
	info := state.Proxy()
	if info.ProxyURL != "http://proxy.example:8080" {
		t.Fatalf("ProxyURL = %q", info.ProxyURL)
	}
	if info.Selection.SourceVariable != "HTTPS_PROXY" ||
		info.Selection.Validity != model.ProxyValidityValid ||
		info.Selection.RequestURL == "" {
		t.Fatalf("typed selection = %#v", info.Selection)
	}
	if got := info.Environment["HTTPS_PROXY"]; got != "http://proxy.example:8080" {
		t.Fatalf("sanitized environment = %q", got)
	}
}

func TestCheckMalformedProxyFailsClosed(t *testing.T) {
	t.Parallel()
	check := &Check{LookupEnv: mapLookup(map[string]string{
		"HTTPS_PROXY": "%%%",
	})}
	state := httpState("https://example.com:443/", "example.com", 443)

	result := check.Run(context.Background(), state)

	if result.Status != model.StatusFailed || result.ErrorCode != ErrorProxyConfigInvalid {
		t.Fatalf("result = %#v", result)
	}
	selection := state.Proxy().Selection
	if selection.Validity != model.ProxyValidityInvalid || selection.RequestURL != "" {
		t.Fatalf("selection = %#v", selection)
	}
	if len(result.Evidence) != 1 || result.Evidence[0].Code != ErrorProxyConfigInvalid {
		t.Fatalf("evidence = %#v", result.Evidence)
	}
}

func TestCheckRejectsHTTPProxyInCGIEnvironment(t *testing.T) {
	t.Parallel()
	check := &Check{LookupEnv: mapLookup(map[string]string{
		"HTTP_PROXY":     "http://proxy.example:8080",
		"REQUEST_METHOD": "GET",
	})}
	state := httpState("http://example.com:80/", "example.com", 80)
	state.Target.UseTLS = false
	state.Target.Scheme = "http"

	result := check.Run(context.Background(), state)

	if result.Status != model.StatusFailed || result.ErrorCode != ErrorProxyConfigInvalid {
		t.Fatalf("result = %#v", result)
	}
	selection := state.Proxy().Selection
	if selection.SourceVariable != "HTTP_PROXY" ||
		selection.Validity != model.ProxyValidityInvalid {
		t.Fatalf("selection = %#v", selection)
	}
}

func TestCheckAllowsLowercaseHTTPProxyInCGIEnvironment(t *testing.T) {
	t.Parallel()
	tests := []map[string]string{
		{"http_proxy": "http://proxy.example:8080", "REQUEST_METHOD": "GET"},
		{"HTTP_PROXY": "http://proxy.example:8080", "REQUEST_METHOD": ""},
	}
	for _, values := range tests {
		check := &Check{LookupEnv: mapLookup(values)}
		state := httpState("http://example.com:80/", "example.com", 80)
		state.Target.UseTLS = false
		state.Target.Scheme = "http"

		result := check.Run(context.Background(), state)

		if result.Status != model.StatusWarning || !state.Proxy().Selected {
			t.Fatalf("values=%#v result=%#v selection=%#v", values, result, state.Proxy().Selection)
		}
	}
}

func TestCheckRejectsMalformedProxyPortAndQueryWithoutLeaking(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"http://proxy.example:bad",
		"http://proxy.example:70000",
		"http://proxy.example:",
		"http://proxy.example:8080?token=proxy-secret",
	} {
		check := &Check{LookupEnv: mapLookup(map[string]string{"HTTPS_PROXY": raw})}
		state := httpState("https://example.com:443/", "example.com", 443)
		result := check.Run(context.Background(), state)
		if result.Status != model.StatusFailed || result.ErrorCode != ErrorProxyConfigInvalid {
			t.Fatalf("raw=%q result=%#v", raw, result)
		}
		if strings.Contains(fmt.Sprintf("%#v", result), "proxy-secret") ||
			strings.Contains(fmt.Sprintf("%#v", state.Proxy()), "proxy-secret") {
			t.Fatalf("invalid proxy leaked query secret: result=%#v proxy=%#v", result, state.Proxy())
		}
	}
}

func TestSelectProxyHonorsNoProxyHostCIDRAndPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		target  string
		noProxy string
	}{
		{name: "host", target: "https://api.example.com/", noProxy: ".example.com"},
		{name: "CIDR", target: "https://192.0.2.25/", noProxy: "192.0.2.0/24"},
		{name: "host and port", target: "https://example.com:8443/", noProxy: "example.com:8443"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			target, err := url.Parse(test.target)
			if err != nil {
				t.Fatal(err)
			}
			selection := selectProxy(target, map[string]string{
				"HTTPS_PROXY": "http://proxy.example:8080",
				"NO_PROXY":    test.noProxy,
			}, false)
			if selection.BypassReason != model.ProxyBypassNoProxy ||
				selection.Validity != model.ProxyValidityNotApplicable ||
				selection.RequestURL != "" {
				t.Fatalf("selection = %#v", selection)
			}
		})
	}
}

func TestCapturedProxySelectorIsImmutableAndNeverSerializesRawValues(t *testing.T) {
	t.Parallel()
	values := map[string]string{
		"HTTPS_PROXY": "http://proxy-user:proxy-password@proxy.example:8443",
		"NO_PROXY":    "bypass.example",
	}
	state := httpState("https://bypass.example:443/", "bypass.example", 443)
	result := (&Check{LookupEnv: mapLookup(values)}).Run(context.Background(), state)
	if result.Status != model.StatusPassed {
		t.Fatalf("result = %#v", result)
	}
	info := state.Proxy()
	if info.SelectForURL == nil {
		t.Fatal("captured proxy selector is nil")
	}
	values["HTTPS_PROXY"] = "http://changed.example:9999"
	target, err := url.Parse("https://outside.example/")
	if err != nil {
		t.Fatal(err)
	}
	selection := info.SelectForURL(target)
	if selection.Validity != model.ProxyValidityValid ||
		!strings.Contains(selection.RequestURL, "proxy-password@proxy.example:8443") {
		t.Fatalf("selection changed after source mutation: %#v", selection)
	}
	serialized, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"proxy-user", "proxy-password", "changed.example"} {
		if strings.Contains(string(serialized), secret) {
			t.Fatalf("serialized proxy policy leaked %q: %s", secret, serialized)
		}
	}
}

func TestCheckNoProxyAndDisabled(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		disabled bool
		wantCode string
	}{
		{name: "NO_PROXY match", wantCode: "NO_PROXY_MATCH"},
		{name: "flag disables selected proxy", disabled: true, wantCode: "PROXY_DISABLED"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := map[string]string{"HTTPS_PROXY": "http://proxy.example:8080"}
			if !test.disabled {
				values["NO_PROXY"] = "example.com"
			}
			check := &Check{LookupEnv: func(key string) (string, bool) {
				value, ok := values[key]
				return value, ok
			}}
			options := model.DefaultDiagnoseOptions("https://example.com")
			options.NoProxy = test.disabled
			state := model.NewState(model.Target{
				Scheme: "https", Host: "example.com", Port: 443,
				RequestURL: "https://example.com:443/",
			}, options)
			result := check.Run(context.Background(), state)
			if len(result.Evidence) == 0 || result.Evidence[0].Code != test.wantCode {
				t.Fatalf("result evidence = %#v", result.Evidence)
			}
		})
	}
}

func TestCheckExplicitDirectDoesNotClaimAProxyWasDisabled(t *testing.T) {
	t.Parallel()
	state := httpState("https://example.com:443/", "example.com", 443)
	state.Options.NoProxy = true
	result := (&Check{LookupEnv: mapLookup(nil)}).Run(context.Background(), state)

	if result.Status != model.StatusPassed || len(result.Evidence) != 1 ||
		result.Evidence[0].Code != "PROXY_EXPLICIT_DIRECT" {
		t.Fatalf("result = %#v", result)
	}
	if strings.Contains(strings.ToLower(result.Summary), "disabled") ||
		strings.Contains(strings.ToLower(result.Evidence[0].Message), "applicable proxy") &&
			strings.Contains(strings.ToLower(result.Evidence[0].Message), "disabled") {
		t.Fatalf("result falsely claims a configured proxy was disabled: %#v", result)
	}
}

func TestCheckSchemeSpecificProxyIsReportedAsNotApplicable(t *testing.T) {
	t.Parallel()
	state := httpState("https://example.com:443/", "example.com", 443)
	result := (&Check{LookupEnv: mapLookup(map[string]string{
		"HTTP_PROXY": "http://user:password@http-proxy.example:8080",
	})}).Run(context.Background(), state)

	selection := state.Proxy().Selection
	if result.Status != model.StatusPassed || len(result.Evidence) != 1 ||
		result.Evidence[0].Code != "PROXY_NOT_APPLICABLE" ||
		selection.Validity != model.ProxyValidityNotApplicable ||
		selection.BypassReason != model.ProxyBypassNotApplicable ||
		selection.SourceVariable != "HTTP_PROXY" || state.Proxy().Bypassed {
		t.Fatalf("result=%#v proxy=%#v", result, state.Proxy())
	}
	if strings.Contains(fmt.Sprintf("%#v", result), "password") ||
		strings.Contains(fmt.Sprintf("%#v", state.Proxy()), "password") {
		t.Fatalf("non-applicable proxy leaked credentials: result=%#v proxy=%#v", result, state.Proxy())
	}
}

func TestCheckExplicitDirectWithNonApplicableProxyIsTruthful(t *testing.T) {
	t.Parallel()
	state := httpState("https://example.com:443/", "example.com", 443)
	state.Options.NoProxy = true
	result := (&Check{LookupEnv: mapLookup(map[string]string{
		"HTTP_PROXY": "http://http-proxy.example:8080",
	})}).Run(context.Background(), state)

	if result.Status != model.StatusPassed || len(result.Evidence) != 1 ||
		result.Evidence[0].Code != "PROXY_EXPLICIT_DIRECT" {
		t.Fatalf("result = %#v", result)
	}
	selection := state.Proxy().Selection
	if selection.Validity != model.ProxyValidityNotApplicable ||
		selection.BypassReason != model.ProxyBypassNotApplicable {
		t.Fatalf("selection = %#v", selection)
	}
}

func TestSanitizeProxyURLMalformed(t *testing.T) {
	t.Parallel()
	if got := SanitizeProxyURL("%%%"); got != "[configured proxy]" {
		t.Fatalf("SanitizeProxyURL() = %q", got)
	}
}

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func httpState(rawURL, host string, port uint16) *model.State {
	options := model.DefaultDiagnoseOptions(rawURL)
	return model.NewState(model.Target{
		Kind:       model.TargetHTTP,
		Scheme:     "https",
		UseTLS:     true,
		Host:       host,
		Port:       port,
		RequestURL: rawURL,
	}, options)
}
