// Package environment inspects proxy-related process environment safely.
package environment

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"golang.org/x/net/http/httpproxy"
)

// ErrorProxyConfigInvalid identifies a malformed proxy environment setting.
const ErrorProxyConfigInvalid = "PROXY_CONFIG_INVALID"

var proxyVariables = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "all_proxy", "no_proxy",
}

// Check inspects one immutable proxy-environment snapshot and determines the
// route that the actual HTTP check must use. HTTP consumes this selection
// rather than reading process-global environment again.
type Check struct {
	LookupEnv func(string) (string, bool)
}

// New constructs an environment check using the process environment.
func New() *Check { return &Check{LookupEnv: os.LookupEnv} }

// ID returns the stable diagnostic identifier.
func (*Check) ID() string { return "environment" }

// Name returns the human-readable check name.
func (*Check) Name() string { return "Environment and proxy" }

// Run captures proxy environment and computes the immutable route selection.
func (c *Check) Run(_ context.Context, state *model.State) model.CheckResult {
	lookup := c.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	raw := make(map[string]string)
	safe := make(map[string]string)
	for _, key := range proxyVariables {
		if value, ok := lookup(key); ok && strings.TrimSpace(value) != "" {
			raw[key] = value
			safe[key] = sanitizeEnvironmentValue(key, value)
		}
	}
	requestMethod, _ := lookup("REQUEST_METHOD")
	cgi := strings.TrimSpace(requestMethod) != ""

	selection := selectProxy(requestURL(state.Target), raw, cgi)
	proxyWouldAffectRoute := selection.BypassReason == model.ProxyBypassNone &&
		(selection.Validity == model.ProxyValidityValid ||
			selection.Validity == model.ProxyValidityInvalid)
	selector := capturedProxySelector(raw, cgi)
	if state.Target.Kind == model.TargetTCP {
		selection.Validity = model.ProxyValidityNotApplicable
		selection.BypassReason = model.ProxyBypassNotApplicable
		selection.Error = ""
		selection.ErrorCode = ""
		selection.RequestURL = ""
	}
	if state.Target.Kind != model.TargetTCP && state.Options.NoProxy && proxyWouldAffectRoute {
		selection.Validity = model.ProxyValidityNotApplicable
		selection.BypassReason = model.ProxyBypassDisabled
		selection.Error = ""
		selection.ErrorCode = ""
		selection.RequestURL = ""
	}

	info := proxyInfo(selection, safe, state.Options.NoProxy)
	if state.Target.Kind == model.TargetHTTP {
		info.SelectForURL = selector
	}
	state.SetProxy(info)

	if state.Target.Kind == model.TargetTCP {
		result := model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusPassed,
			Summary: "Proxy environment does not apply to direct TCP diagnostics.",
		}
		if len(safe) > 0 {
			result.Evidence = []model.Evidence{{
				ID:      "environment.proxy_not_applicable",
				Code:    "PROXY_NOT_APPLICABLE",
				Message: "Proxy variables are configured, but this host:port target uses direct TCP checks.",
				Details: selectionDetails(selection),
			}}
		}
		return result
	}
	if state.Options.NoProxy {
		code := "PROXY_EXPLICIT_DIRECT"
		evidenceID := "environment.proxy_explicit_direct"
		summary := "Direct HTTP was explicitly selected; proxy policy did not select an applicable proxy for this target."
		message := "The diagnosis explicitly selected a direct route without bypassing an applicable proxy."
		if proxyWouldAffectRoute {
			code = "PROXY_DISABLED"
			evidenceID = "environment.proxy_disabled"
			summary = "Proxy use is explicitly disabled for this diagnosis."
			message = "Direct HTTP is allowed because an applicable proxy was explicitly disabled."
		}
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusPassed,
			Summary: summary,
			Evidence: []model.Evidence{{
				ID:      evidenceID,
				Code:    code,
				Message: message,
				Details: selectionDetails(selection),
			}},
		}
	}

	switch {
	case selection.Validity == model.ProxyValidityInvalid:
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusFailed,
			Summary:   "The configured proxy is invalid; direct fallback is blocked.",
			ErrorCode: ErrorProxyConfigInvalid,
			Evidence: []model.Evidence{{
				ID:      "environment.proxy_invalid",
				Code:    ErrorProxyConfigInvalid,
				Message: "Proxy selection failed closed before any HTTP request was sent.",
				Details: selectionDetails(selection),
			}},
			Recommendations: []model.Recommendation{{
				ID:       "environment.correct_proxy",
				Priority: "high",
				Message:  "Correct or explicitly disable the proxy configuration, then retry.",
			}},
		}
	case selection.BypassReason == model.ProxyBypassNoProxy ||
		selection.BypassReason == model.ProxyBypassLoopback:
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusPassed,
			Summary: "Proxy rules explicitly bypass this target.",
			Evidence: []model.Evidence{{
				ID:      "environment.no_proxy",
				Code:    "NO_PROXY_MATCH",
				Message: "A direct HTTP route was selected by an explicit bypass rule.",
				Details: selectionDetails(selection),
			}},
		}
	case selection.BypassReason == model.ProxyBypassNotApplicable:
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusPassed,
			Summary: "Configured proxy variables do not apply to this target scheme.",
			Evidence: []model.Evidence{{
				ID:      "environment.proxy_not_applicable",
				Code:    "PROXY_NOT_APPLICABLE",
				Message: "The configured scheme-specific proxy does not apply to this target URL.",
				Details: selectionDetails(selection),
			}},
		}
	case selection.Validity == model.ProxyValidityValid:
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusWarning,
			Summary: "A proxy is selected for the actual HTTP request.",
			Evidence: []model.Evidence{{
				ID:      "environment.proxy_selected",
				Code:    "PROXY_SELECTED",
				Message: "Proxy environment rules selected a validated proxy for the target.",
				Details: selectionDetails(selection),
			}},
			Recommendations: []model.Recommendation{{
				ID:       "environment.verify_proxy",
				Priority: "medium",
				Message:  "Verify that the selected proxy is reachable and intended for this target.",
			}},
		}
	default:
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusPassed,
			Summary: "No proxy is configured for this target.",
			Evidence: []model.Evidence{{
				ID:      "environment.proxy_not_configured",
				Code:    "PROXY_NOT_CONFIGURED",
				Message: "The actual HTTP request will use a direct route because no proxy is configured.",
			}},
		}
	}
}

func proxyInfo(
	selection model.ProxySelection,
	environment map[string]string,
	disabled bool,
) model.ProxyInfo {
	selected := selection.Validity == model.ProxyValidityValid &&
		selection.BypassReason == model.ProxyBypassNone
	bypassed := selection.BypassReason == model.ProxyBypassDisabled ||
		selection.BypassReason == model.ProxyBypassNoProxy ||
		selection.BypassReason == model.ProxyBypassLoopback
	return model.ProxyInfo{
		Disabled:    disabled,
		Selected:    selected,
		Bypassed:    bypassed,
		ProxyURL:    selection.URL,
		Environment: environment,
		Selection:   selection,
	}
}

func capturedProxySelector(
	values map[string]string,
	cgi bool,
) func(*url.URL) model.ProxySelection {
	// Capture a private copy: neither later process-environment changes nor a
	// caller mutating a test map may alter the policy within one diagnosis.
	snapshot := make(map[string]string, len(values))
	for key, value := range values {
		snapshot[key] = value
	}
	return func(target *url.URL) model.ProxySelection {
		return selectProxy(target, snapshot, cgi)
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

// selectProxy applies standards-compatible NO_PROXY matching before parsing
// the configured proxy. A malformed or CGI-unsafe proxy is represented as an
// invalid selection and is never reinterpreted as a direct route.
func selectProxy(target *url.URL, values map[string]string, cgi bool) model.ProxySelection {
	raw, source := configuredProxy(target, values)
	if raw == "" {
		if nonApplicable, nonApplicableSource := configuredNonApplicableProxy(target, values); nonApplicable != "" {
			return model.ProxySelection{
				SourceVariable: nonApplicableSource,
				URL:            SanitizeProxyURL(nonApplicable),
				Validity:       model.ProxyValidityNotApplicable,
				BypassReason:   model.ProxyBypassNotApplicable,
			}
		}
		return model.ProxySelection{Validity: model.ProxyValidityNotConfigured}
	}
	selection := model.ProxySelection{
		SourceVariable: source,
		URL:            SanitizeProxyURL(raw),
	}
	noProxy := first(values, "NO_PROXY", "no_proxy")
	if bypasses(target, noProxy) {
		selection.Validity = model.ProxyValidityNotApplicable
		selection.BypassReason = model.ProxyBypassNoProxy
		if isLoopbackTarget(target) {
			selection.BypassReason = model.ProxyBypassLoopback
		}
		return selection
	}
	if cgi && target != nil && strings.EqualFold(target.Scheme, "http") &&
		source == "HTTP_PROXY" {
		selection.Validity = model.ProxyValidityInvalid
		selection.ErrorCode = ErrorProxyConfigInvalid
		selection.Error = "HTTP proxy environment variables are unsafe in CGI mode"
		return selection
	}

	parsed, err := parseProxy(raw)
	if err != nil {
		selection.Validity = model.ProxyValidityInvalid
		selection.ErrorCode = ErrorProxyConfigInvalid
		selection.Error = "configured proxy URL is malformed or uses an unsupported scheme"
		return selection
	}
	selection.Validity = model.ProxyValidityValid
	selection.URL = SanitizeProxyURL(parsed.String())
	selection.RequestURL = parsed.String()
	return selection
}

func configuredNonApplicableProxy(target *url.URL, values map[string]string) (string, string) {
	if target != nil && strings.EqualFold(target.Scheme, "http") {
		return firstWithSource(values, "HTTPS_PROXY", "https_proxy")
	}
	return firstWithSource(values, "HTTP_PROXY", "http_proxy")
}

func configuredProxy(target *url.URL, values map[string]string) (string, string) {
	if target != nil && strings.EqualFold(target.Scheme, "http") {
		if value, source := firstWithSource(values, "HTTP_PROXY", "http_proxy"); value != "" {
			return value, source
		}
	} else {
		if value, source := firstWithSource(values, "HTTPS_PROXY", "https_proxy"); value != "" {
			return value, source
		}
	}
	return firstWithSource(values, "ALL_PROXY", "all_proxy")
}

func bypasses(target *url.URL, noProxy string) bool {
	if target == nil {
		return false
	}
	config := &httpproxy.Config{
		HTTPProxy:  "http://proxy.invalid",
		HTTPSProxy: "http://proxy.invalid",
		NoProxy:    noProxy,
	}
	selected, err := config.ProxyFunc()(target)
	return err == nil && selected == nil
}

func isLoopbackTarget(target *url.URL) bool {
	if target == nil {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(target.Hostname()), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func parseProxy(raw string) (*url.URL, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, fmt.Errorf("proxy URL is empty")
	}
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" {
		return nil, fmt.Errorf("invalid proxy URL")
	}
	port := parsed.Port()
	if strings.HasSuffix(parsed.Host, ":") {
		return nil, fmt.Errorf("proxy URL has an empty port")
	}
	if port != "" {
		value, portErr := strconv.ParseUint(port, 10, 16)
		if portErr != nil || value == 0 {
			return nil, fmt.Errorf("proxy URL port must be between 1 and 65535")
		}
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("unsupported proxy scheme")
	}
	if parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("proxy URL path, query, and fragment are not supported")
	}
	return parsed, nil
}

func first(values map[string]string, keys ...string) string {
	value, _ := firstWithSource(values, keys...)
	return value
}

func firstWithSource(values map[string]string, keys ...string) (string, string) {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value, key
		}
	}
	return "", ""
}

func selectionDetails(selection model.ProxySelection) map[string]string {
	details := map[string]string{
		"validity": string(selection.Validity),
	}
	if selection.SourceVariable != "" {
		details["sourceVariable"] = selection.SourceVariable
	}
	if selection.URL != "" {
		details["proxy"] = selection.URL
	}
	if selection.BypassReason != model.ProxyBypassNone {
		details["bypassReason"] = string(selection.BypassReason)
	}
	if selection.Error != "" {
		details["reason"] = selection.Error
	}
	return details
}

func sanitizeEnvironmentValue(key, value string) string {
	if strings.EqualFold(key, "NO_PROXY") {
		return "[configured]"
	}
	return SanitizeProxyURL(value)
}

// SanitizeProxyURL removes userinfo, path, query, and fragment data from a
// proxy URL while retaining enough origin metadata for diagnosis.
func SanitizeProxyURL(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	parsed, err := parseProxy(value)
	if err != nil {
		return "[configured proxy]"
	}
	parsed.User = nil
	parsed.Path = ""
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}
