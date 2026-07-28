// Package environment inspects proxy-related process environment safely.
package environment

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"golang.org/x/net/http/httpproxy"
)

var proxyVariables = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "all_proxy", "no_proxy",
}

// Check inspects proxy environment and determines whether a proxy applies.
type Check struct {
	LookupEnv func(string) (string, bool)
}

// New constructs an environment check using the process environment.
func New() *Check { return &Check{LookupEnv: os.LookupEnv} }

func (*Check) ID() string   { return "environment" }
func (*Check) Name() string { return "Environment and proxy" }

func (c *Check) Run(_ context.Context, state *model.State) model.CheckResult {
	lookup := c.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	env := make(map[string]string)
	raw := make(map[string]string)
	for _, key := range proxyVariables {
		if value, ok := lookup(key); ok && value != "" {
			raw[key] = value
			env[key] = SanitizeProxyURL(value)
		}
	}

	info := model.ProxyInfo{Disabled: state.Options.NoProxy, Environment: env}
	if state.Target.Kind == model.TargetTCP {
		state.SetProxy(info)
		result := model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusPassed,
			Summary: "Proxy environment does not apply to direct TCP diagnostics.",
		}
		if len(env) > 0 {
			result.Evidence = []model.Evidence{{
				ID:      "environment.proxy_not_applicable",
				Code:    "PROXY_NOT_APPLICABLE",
				Message: "Proxy variables are configured, but this host:port target uses direct TCP checks.",
			}}
		}
		return result
	}
	targetURL := requestURL(state.Target)
	available, bypassed := selectProxy(targetURL, raw)
	if state.Options.NoProxy {
		info.Bypassed = available != ""
		state.SetProxy(info)
		result := model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusPassed,
			Summary: "Proxy use is disabled for this diagnosis.",
		}
		if available != "" {
			result.Evidence = append(result.Evidence, model.Evidence{
				ID:      "environment.proxy_disabled",
				Code:    "PROXY_DISABLED",
				Message: "A proxy would have been selected, but proxy use was explicitly disabled.",
				Details: map[string]string{"proxy": SanitizeProxyURL(available)},
			})
		}
		return result
	}

	info.Bypassed = bypassed
	if available != "" {
		info.Selected = true
		info.ProxyURL = SanitizeProxyURL(available)
	}
	state.SetProxy(info)

	switch {
	case info.Selected:
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusWarning,
			Summary: "A proxy is selected for this target.",
			Evidence: []model.Evidence{{
				ID:      "environment.proxy_selected",
				Code:    "PROXY_SELECTED",
				Message: "Proxy environment rules select a proxy for the target.",
				Details: map[string]string{"proxy": info.ProxyURL},
			}},
			Recommendations: []model.Recommendation{{
				ID:       "environment.verify_proxy",
				Priority: "medium",
				Message:  "Verify that the selected proxy is reachable and intended for this target.",
			}},
		}
	case info.Bypassed:
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusPassed,
			Summary: "Proxy rules bypass this target.",
			Evidence: []model.Evidence{{
				ID:      "environment.no_proxy",
				Code:    "NO_PROXY_MATCH",
				Message: "The target matches NO_PROXY.",
			}},
		}
	default:
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusPassed,
			Summary: "No proxy is selected for this target.",
		}
	}
}

func requestURL(target model.Target) *url.URL {
	if target.RequestURL != "" {
		if parsed, err := url.Parse(target.RequestURL); err == nil {
			return parsed
		}
	}
	scheme := "https"
	if !target.UseTLS {
		scheme = "http"
	}
	parsed, _ := url.Parse(fmt.Sprintf("%s://%s", scheme, target.Address()))
	return parsed
}

func selectProxy(target *url.URL, values map[string]string) (proxy string, bypassed bool) {
	config := &httpproxy.Config{
		HTTPProxy:  first(values, "HTTP_PROXY", "http_proxy"),
		HTTPSProxy: first(values, "HTTPS_PROXY", "https_proxy"),
		NoProxy:    first(values, "NO_PROXY", "no_proxy"),
	}
	selected, err := config.ProxyFunc()(target)
	if err == nil && selected != nil {
		return selected.String(), false
	}
	if err == nil && selected == nil && config.NoProxy != "" &&
		(config.HTTPProxy != "" || config.HTTPSProxy != "") {
		return "", true
	}

	all := first(values, "ALL_PROXY", "all_proxy")
	if all == "" {
		return "", false
	}
	// Apply NO_PROXY to ALL_PROXY by temporarily treating it as both HTTP and
	// HTTPS proxy in the same standards-compliant matcher.
	fallback := &httpproxy.Config{HTTPProxy: all, HTTPSProxy: all, NoProxy: config.NoProxy}
	selected, err = fallback.ProxyFunc()(target)
	if err != nil || selected == nil {
		return "", config.NoProxy != ""
	}
	return selected.String(), false
}

func first(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := values[key]; value != "" {
			return value
		}
	}
	return ""
}

// ProxyFunc returns a request proxy function using current environment values.
// It extends the standard behavior with ALL_PROXY and never exposes credentials.
func ProxyFunc(noProxy bool) func(*url.URL) (*url.URL, error) {
	if noProxy {
		return nil
	}
	values := make(map[string]string)
	for _, key := range proxyVariables {
		if value, ok := os.LookupEnv(key); ok {
			values[key] = value
		}
	}
	return func(target *url.URL) (*url.URL, error) {
		selected, _ := selectProxy(target, values)
		if selected == "" {
			return nil, nil
		}
		return url.Parse(selected)
	}
}

// SanitizeProxyURL removes userinfo and query data from a proxy URL.
func SanitizeProxyURL(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	withScheme := value
	if !strings.Contains(withScheme, "://") {
		withScheme = "http://" + withScheme
	}
	parsed, err := url.Parse(withScheme)
	if err != nil || parsed.Host == "" {
		return "[configured proxy]"
	}
	parsed.User = nil
	parsed.Path = ""
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}
