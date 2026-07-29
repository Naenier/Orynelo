package summary

import (
	"testing"

	httpcheck "github.com/Naenier/opsdoctor/internal/diagnostics/checks/http"
	"github.com/Naenier/opsdoctor/internal/diagnostics/checks/tcp"
	tlscheck "github.com/Naenier/opsdoctor/internal/diagnostics/checks/tls"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
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
