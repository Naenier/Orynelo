package environment

import (
	"context"
	"testing"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

func TestCheckProxySelectionAndSanitization(t *testing.T) {
	t.Parallel()
	values := map[string]string{
		"HTTPS_PROXY": "http://user:password@proxy.example:8080?token=secret",
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
	if got := info.Environment["HTTPS_PROXY"]; got != "http://proxy.example:8080" {
		t.Fatalf("sanitized environment = %q", got)
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

func TestSanitizeProxyURLMalformed(t *testing.T) {
	t.Parallel()
	if got := SanitizeProxyURL("%%%"); got != "[configured proxy]" {
		t.Fatalf("SanitizeProxyURL() = %q", got)
	}
}
