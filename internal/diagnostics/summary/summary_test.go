package summary

import (
	"strings"
	"testing"
	"time"

	httpcheck "github.com/Naenier/orynelo/internal/diagnostics/checks/http"
	"github.com/Naenier/orynelo/internal/diagnostics/checks/tcp"
	tlscheck "github.com/Naenier/orynelo/internal/diagnostics/checks/tls"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

func TestEvidenceBasedRules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		results []model.CheckResult
		title   string
		status  model.Status
	}{
		{
			name:    "invalid target",
			results: []model.CheckResult{result("target", model.StatusFailed, "TARGET_INVALID")},
			title:   "Invalid target",
			status:  model.StatusFailed,
		},
		{
			name:    "DNS failure",
			results: []model.CheckResult{result("dns", model.StatusFailed, "DNS_LOOKUP_FAILED")},
			title:   "DNS resolution failed",
			status:  model.StatusFailed,
		},
		{
			name: "IPv4 works IPv6 fails",
			results: []model.CheckResult{tcpResult(
				model.StatusWarning,
				tcp.ErrorPartialFailure,
				attempt("ipv4", true),
				attempt("ipv6", false),
			)},
			title:  "IPv4 reachable; IPv6 connection failed",
			status: model.StatusWarning,
		},
		{
			name: "IPv6 works IPv4 fails",
			results: []model.CheckResult{tcpResult(
				model.StatusWarning,
				tcp.ErrorPartialFailure,
				attempt("ipv4", false),
				attempt("ipv6", true),
			)},
			title:  "IPv6 reachable; IPv4 connection failed",
			status: model.StatusWarning,
		},
		{
			name:    "all refused",
			results: []model.CheckResult{result("tcp", model.StatusFailed, tcp.ErrorConnectionRefused)},
			title:   "TCP connections refused",
			status:  model.StatusFailed,
		},
		{
			name:    "all timeout",
			results: []model.CheckResult{result("tcp", model.StatusFailed, tcp.ErrorTimeout)},
			title:   "TCP connections timed out",
			status:  model.StatusFailed,
		},
		{
			name:    "mixed TCP",
			results: []model.CheckResult{result("tcp", model.StatusWarning, tcp.ErrorPartialFailure)},
			title:   "Mixed TCP results",
			status:  model.StatusWarning,
		},
		{
			name:    "expired TLS",
			results: []model.CheckResult{result("tls", model.StatusFailed, tlscheck.ErrorExpired)},
			title:   "TLS certificate expired",
			status:  model.StatusFailed,
		},
		{
			name:    "hostname mismatch",
			results: []model.CheckResult{result("tls", model.StatusFailed, tlscheck.ErrorHostnameMismatch)},
			title:   "TLS hostname mismatch",
			status:  model.StatusFailed,
		},
		{
			name:    "unknown authority",
			results: []model.CheckResult{result("tls", model.StatusFailed, tlscheck.ErrorUnknownAuthority)},
			title:   "TLS chain is not trusted",
			status:  model.StatusFailed,
		},
		{
			name:    "redirect loop",
			results: []model.CheckResult{result("http", model.StatusFailed, httpcheck.ErrorRedirectLoop)},
			title:   "HTTP redirect chain failed",
			status:  model.StatusFailed,
		},
		{
			name:    "HTTP 4xx",
			results: []model.CheckResult{result("http", model.StatusWarning, httpcheck.ErrorClientResponse)},
			title:   "Target reachable with HTTP client error",
			status:  model.StatusWarning,
		},
		{
			name:    "HTTP 5xx",
			results: []model.CheckResult{result("http", model.StatusWarning, httpcheck.ErrorServerResponse)},
			title:   "Target reachable with application-level error",
			status:  model.StatusWarning,
		},
		{
			name: "proxy selected",
			results: []model.CheckResult{
				withEvidence(result("environment", model.StatusWarning, ""), "PROXY_SELECTED"),
				result("http", model.StatusPassed, ""),
			},
			title:  "Target reachable through selected proxy",
			status: model.StatusWarning,
		},
		{
			name: "proxy success supersedes direct TCP failure",
			results: []model.CheckResult{
				withEvidence(result("environment", model.StatusWarning, ""), "PROXY_SELECTED"),
				result("dns", model.StatusFailed, "DNS_LOOKUP_FAILED"),
				result("tcp", model.StatusFailed, tcp.ErrorTimeout),
				result("http", model.StatusPassed, ""),
			},
			title:  "Target reachable through selected proxy",
			status: model.StatusWarning,
		},
		{
			name: "direct works with proxy disabled",
			results: []model.CheckResult{
				withEvidence(result("environment", model.StatusPassed, ""), "PROXY_DISABLED"),
				result("tcp", model.StatusPassed, ""),
			},
			title:  "Direct connection works with proxy disabled",
			status: model.StatusWarning,
		},
		{
			name:    "operation cancelled",
			results: []model.CheckResult{result("dns", model.StatusCancelled, "DNS_CANCELLED")},
			title:   "Diagnosis cancelled",
			status:  model.StatusCancelled,
		},
		{
			name:    "global timeout",
			results: []model.CheckResult{result("dns", model.StatusFailed, "OPERATION_TIMEOUT")},
			title:   "Diagnosis timed out",
			status:  model.StatusFailed,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := Build(test.results)
			if got.Title != test.title || got.Status != test.status {
				t.Fatalf("Build() = %#v", got)
			}
			if len(got.EvidenceRefs) == 0 {
				t.Fatalf("rule did not reference concrete evidence: %#v", got)
			}
		})
	}
}

func TestBlockerOutranksEarlierDegradedPathWarning(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		upper  model.CheckResult
		title  string
		status model.Status
	}{
		{
			name:   "TLS failure outranks partial TCP",
			upper:  result("tls", model.StatusFailed, tlscheck.ErrorExpired),
			title:  "TLS certificate expired",
			status: model.StatusFailed,
		},
		{
			name:   "untrusted TLS outranks partial TCP",
			upper:  result("tls", model.StatusFailed, tlscheck.ErrorUnknownAuthority),
			title:  "TLS chain is not trusted",
			status: model.StatusFailed,
		},
		{
			name:   "HTTP failure outranks partial TCP",
			upper:  result("http", model.StatusFailed, httpcheck.ErrorTransport),
			title:  "HTTP transport failed",
			status: model.StatusFailed,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			results := []model.CheckResult{
				tcpResult(
					model.StatusWarning,
					tcp.ErrorPartialFailure,
					attempt("ipv4", true),
					attempt("ipv6", false),
				),
				test.upper,
			}
			got := Build(results)
			if got.Title != test.title || got.Status != test.status {
				t.Fatalf("Build() = %#v", got)
			}
			if !containsReference(got.EvidenceRefs, test.upper.Evidence[0].ID) {
				t.Fatalf("evidence refs = %#v, want %q", got.EvidenceRefs, test.upper.Evidence[0].ID)
			}
		})
	}
}

func TestHTTPFailureOutranksRouteWarning(t *testing.T) {
	t.Parallel()
	routeWarning := result("route", model.StatusWarning, "ROUTE_DISCOVERY_FAILED")
	httpFailure := result("http", model.StatusFailed, httpcheck.ErrorTransport)

	got := Build([]model.CheckResult{routeWarning, httpFailure})
	if got.Title != "HTTP transport failed" || got.Status != model.StatusFailed {
		t.Fatalf("Build() = %#v", got)
	}
	if !containsReference(got.EvidenceRefs, httpFailure.Evidence[0].ID) {
		t.Fatalf("evidence refs = %#v", got.EvidenceRefs)
	}
}

func TestObservedFailureOutranksLaterCancellation(t *testing.T) {
	t.Parallel()
	dns := result("dns", model.StatusFailed, "DNS_LOOKUP_FAILED")
	cancelled := result("tcp", model.StatusCancelled, tcp.ErrorCancelled)

	got := Build([]model.CheckResult{dns, cancelled})
	if got.Title != "DNS resolution failed" || got.Status != model.StatusFailed {
		t.Fatalf("Build() = %#v", got)
	}
}

func TestCheckTimeoutIdentifiesStageAndConfiguredBudget(t *testing.T) {
	t.Parallel()
	timedOut := result("tls", model.StatusFailed, "CHECK_TIMEOUT")
	timedOut.Name = "TLS handshake and certificate"
	timedOut.Duration = 5 * time.Second
	timedOut.Evidence = []model.Evidence{{
		ID:      "tls.timeout",
		CheckID: "tls",
		Code:    "CHECK_TIMEOUT",
		Message: "The diagnostic check exceeded its configured timeout.",
		Details: map[string]string{
			"stage":            "tls",
			"configuredBudget": "5s",
			"elapsed":          "5s",
		},
	}}

	got := Build([]model.CheckResult{timedOut})
	if got.Title != "Diagnostic check timed out" || got.Status != model.StatusFailed {
		t.Fatalf("Build() = %#v", got)
	}
	if !strings.Contains(got.Description, "TLS handshake and certificate") ||
		!strings.Contains(got.Description, "5s") {
		t.Fatalf("description = %q", got.Description)
	}
	if !containsReference(got.EvidenceRefs, "tls.timeout") {
		t.Fatalf("evidence refs = %#v", got.EvidenceRefs)
	}
}

func TestHigherLayerFailureOutranksLowerCheckTimeout(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		lower model.CheckResult
		upper model.CheckResult
		title string
	}{
		{
			name:  "HTTP transport failure outranks TCP check budget",
			lower: result("tcp", model.StatusFailed, "CHECK_TIMEOUT"),
			upper: result("http", model.StatusFailed, httpcheck.ErrorTransport),
			title: "HTTP transport failed",
		},
		{
			name:  "HTTP redirect failure outranks route check budget",
			lower: result("route", model.StatusFailed, "CHECK_TIMEOUT"),
			upper: result("http", model.StatusFailed, httpcheck.ErrorRedirectLoop),
			title: "HTTP redirect chain failed",
		},
		{
			name:  "TLS certificate failure outranks TCP check budget",
			lower: result("tcp", model.StatusFailed, "CHECK_TIMEOUT"),
			upper: result("tls", model.StatusFailed, tlscheck.ErrorExpired),
			title: "TLS certificate expired",
		},
		{
			name:  "actual HTTP check budget outranks TCP check budget",
			lower: result("tcp", model.StatusFailed, "CHECK_TIMEOUT"),
			upper: result("http", model.StatusFailed, "CHECK_TIMEOUT"),
			title: "Diagnostic check timed out",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := Build([]model.CheckResult{test.lower, test.upper})
			if got.Title != test.title || got.Status != model.StatusFailed {
				t.Fatalf("Build() = %#v", got)
			}
			if !containsReference(got.EvidenceRefs, test.upper.Evidence[0].ID) {
				t.Fatalf("evidence refs = %#v, want %q", got.EvidenceRefs, test.upper.Evidence[0].ID)
			}
		})
	}
}

func TestActualHTTPSuccessTurnsPreflightFailureIntoDiscrepancy(t *testing.T) {
	t.Parallel()
	tcpFailure := result("tcp", model.StatusFailed, tcp.ErrorTimeout)
	httpSuccess := result("http", model.StatusPassed, "")

	got := Build([]model.CheckResult{tcpFailure, httpSuccess})
	if got.Title != "HTTP request succeeded despite preflight failure" ||
		got.Status != model.StatusWarning {
		t.Fatalf("Build() = %#v", got)
	}
	for _, reference := range []string{tcpFailure.Evidence[0].ID, httpSuccess.Evidence[0].ID} {
		if !containsReference(got.EvidenceRefs, reference) {
			t.Fatalf("evidence refs = %#v, want %q", got.EvidenceRefs, reference)
		}
	}
	if !strings.Contains(strings.ToLower(got.Description), "preflight") {
		t.Fatalf("description = %q", got.Description)
	}
}

func TestActualMixedRouteSupersedesInitialProxySelection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		environment   model.CheckResult
		redirectRoute string
		bypass        string
	}{
		{
			name:          "initial proxy redirects to NO_PROXY direct",
			environment:   withEvidence(result("environment", model.StatusWarning, ""), "PROXY_SELECTED"),
			redirectRoute: "direct",
			bypass:        "no_proxy_match",
		},
		{
			name:          "initial NO_PROXY direct redirects to proxy",
			environment:   withEvidence(result("environment", model.StatusPassed, ""), "NO_PROXY_MATCH"),
			redirectRoute: "proxy",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			httpResult := result("http", model.StatusPassed, "")
			httpResult.Evidence = []model.Evidence{
				{
					ID:      "http.response",
					Code:    "HTTP_RESPONSE",
					Message: "response",
					Details: map[string]string{"route": "mixed"},
				},
				{
					ID:      "http.redirect.1",
					Code:    "HTTP_REDIRECT_FOLLOWED",
					Message: "redirect",
					Details: map[string]string{
						"route":             test.redirectRoute,
						"proxySource":       "HTTPS_PROXY",
						"proxyBypassReason": test.bypass,
					},
				},
			}

			got := Build([]model.CheckResult{test.environment, httpResult})

			if got.Title != "Target reachable across mixed direct/proxy routes" ||
				got.Status != model.StatusWarning ||
				!strings.Contains(got.Description, "both direct and proxy") ||
				strings.Contains(got.Title, "through selected proxy") {
				t.Fatalf("Build() = %#v", got)
			}
			if !containsReference(got.EvidenceRefs, "http.redirect.1") {
				t.Fatalf("evidence refs = %#v", got.EvidenceRefs)
			}
		})
	}
}

func TestActualHTTPResponseSupersedesAuxiliaryPreflightTimeout(t *testing.T) {
	t.Parallel()
	proxy := withEvidence(result("environment", model.StatusWarning, ""), "PROXY_SELECTED")
	preflight := result("tcp", model.StatusFailed, "CHECK_TIMEOUT")
	preflight.Role = model.CheckRoleAuxiliaryDirectComparison
	response := result("http", model.StatusWarning, httpcheck.ErrorServerResponse)

	got := Build([]model.CheckResult{proxy, preflight, response})
	if got.Title != "Target reachable through selected proxy with application-level error" ||
		got.Status != model.StatusWarning {
		t.Fatalf("Build() = %#v", got)
	}
	for _, reference := range []string{proxy.Evidence[0].ID, preflight.Evidence[0].ID, response.Evidence[0].ID} {
		if !containsReference(got.EvidenceRefs, reference) {
			t.Fatalf("evidence refs = %#v, want %q", got.EvidenceRefs, reference)
		}
	}
}

func TestActualHTTPCheckTimeoutIsNotHiddenByAuxiliaryTimeout(t *testing.T) {
	t.Parallel()
	proxy := withEvidence(result("environment", model.StatusWarning, ""), "PROXY_SELECTED")
	preflight := result("tcp", model.StatusFailed, "CHECK_TIMEOUT")
	preflight.Role = model.CheckRoleAuxiliaryDirectComparison
	httpTimeout := result("http", model.StatusFailed, "CHECK_TIMEOUT")
	httpTimeout.Name = "HTTP request"
	httpTimeout.Evidence = []model.Evidence{{
		ID:      "http.timeout",
		CheckID: "http",
		Code:    "CHECK_TIMEOUT",
		Message: "timed out",
		Details: map[string]string{"configuredBudget": "3s"},
	}}

	got := Build([]model.CheckResult{proxy, preflight, httpTimeout})
	if got.Title != "Diagnostic check timed out" || got.Status != model.StatusFailed ||
		!strings.Contains(got.Description, "HTTP request") ||
		!strings.Contains(got.Description, "3s") {
		t.Fatalf("Build() = %#v", got)
	}
	if !containsReference(got.EvidenceRefs, "http.timeout") {
		t.Fatalf("evidence refs = %#v", got.EvidenceRefs)
	}
}

func TestInvalidProxyIsBlockingAndDoesNotFallBackToHTTPFailure(t *testing.T) {
	t.Parallel()
	environment := withEvidence(
		result("environment", model.StatusFailed, "PROXY_CONFIG_INVALID"),
		"PROXY_CONFIG_INVALID",
	)
	httpFailure := result("http", model.StatusFailed, "PROXY_CONFIG_INVALID")

	got := Build([]model.CheckResult{environment, httpFailure})
	if got.Title != "Proxy configuration is invalid" || got.Status != model.StatusFailed {
		t.Fatalf("Build() = %#v", got)
	}
	if !containsReference(got.EvidenceRefs, environment.Evidence[0].ID) {
		t.Fatalf("evidence refs = %#v", got.EvidenceRefs)
	}
}

func TestSkippedAndNotApplicableRemainMachineReadableAndDistinct(t *testing.T) {
	t.Parallel()
	tls := result("tls", model.StatusNotApplicable, "")
	http := result("http", model.StatusNotApplicable, "")

	got := Build([]model.CheckResult{tls, http})
	if got.Title != "No applicable diagnostic checks" || got.Status != model.StatusNotApplicable {
		t.Fatalf("Build(not-applicable) = %#v", got)
	}

	tls.Status = model.StatusSkipped
	got = Build([]model.CheckResult{tls, http})
	if got.Title != "Applicable diagnostic checks were skipped" || got.Status != model.StatusSkipped {
		t.Fatalf("Build(skipped) = %#v", got)
	}
}

func containsReference(references []string, want string) bool {
	for _, reference := range references {
		if reference == want {
			return true
		}
	}
	return false
}

func TestGenericConclusionReferencesEvidence(t *testing.T) {
	t.Parallel()

	got := Build([]model.CheckResult{result("http", model.StatusPassed, "")})
	if got.Status != model.StatusPassed || len(got.EvidenceRefs) == 0 {
		t.Fatalf("Build() = %#v, want referenced successful conclusion", got)
	}

	warning := result("tls", model.StatusWarning, "")
	warning.Recommendations = []model.Recommendation{{ID: "renew", Message: "Renew soon."}}
	got = Build([]model.CheckResult{warning})
	if got.Status != model.StatusWarning ||
		len(got.EvidenceRefs) == 0 ||
		len(got.Recommendations) != 1 {
		t.Fatalf("Build() = %#v, want referenced warning with next action", got)
	}
}

func result(id string, status model.Status, code string) model.CheckResult {
	return model.CheckResult{
		ID: id, Name: id, Status: status, ErrorCode: code,
		Evidence: []model.Evidence{{
			ID: id + ".evidence", Code: code, Message: "observed",
		}},
	}
}

func withEvidence(value model.CheckResult, code string) model.CheckResult {
	value.Evidence = []model.Evidence{{
		ID: value.ID + "." + code, Code: code, Message: "observed",
	}}
	return value
}

func attempt(family string, success bool) model.Evidence {
	return model.Evidence{
		ID:      "tcp." + family,
		Code:    "TCP_ATTEMPT",
		Message: "attempt",
		Details: map[string]string{
			"family":  family,
			"success": map[bool]string{true: "true", false: "false"}[success],
		},
	}
}

func tcpResult(status model.Status, code string, evidence ...model.Evidence) model.CheckResult {
	value := result("tcp", status, code)
	value.Evidence = evidence
	return value
}
