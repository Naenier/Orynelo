// Package summary turns concrete check outcomes into cautious, evidence-based
// conclusions. It does not infer a single root cause from ambiguous symptoms.
package summary

import (
	"fmt"
	"strings"

	httpcheck "github.com/Naenier/opsdoctor/internal/diagnostics/checks/http"
	"github.com/Naenier/opsdoctor/internal/diagnostics/checks/tcp"
	tlscheck "github.com/Naenier/opsdoctor/internal/diagnostics/checks/tls"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

// Build evaluates stable summary rules in diagnostic-layer order.
func Build(results []model.CheckResult) model.Summary {
	if result := firstWithStatus(results, model.StatusCancelled); result != nil {
		return conclusion(
			model.StatusCancelled,
			"Diagnosis cancelled",
			"The operation was cancelled before all diagnostic stages completed.",
			result,
			"Run the diagnosis again when the full result is needed.",
		)
	}
	if result := firstWithErrorCode(results, "OPERATION_TIMEOUT"); result != nil {
		return conclusion(
			model.StatusFailed,
			"Diagnosis timed out",
			"The global diagnosis timeout elapsed before every stage completed.",
			result,
			"Increase the global timeout or investigate the stage that consumed the available time.",
		)
	}
	if result := byID(results, "target"); result != nil && result.Status == model.StatusFailed {
		return conclusion(
			model.StatusFailed,
			"Invalid target",
			"The target could not be validated, so no network conclusion can be made.",
			result,
			"Correct the target syntax and include a valid host and port.",
		)
	}
	proxy := byID(results, "environment")
	if proxy != nil && hasEvidenceCode(*proxy, "PROXY_SELECTED") {
		if httpResult := byID(results, "http"); httpResult != nil {
			if result, ok := selectedProxyHTTPConclusion(httpResult, proxy); ok {
				return result
			}
		}
	}
	if result := byID(results, "dns"); result != nil && result.Status == model.StatusFailed {
		return conclusion(
			model.StatusFailed,
			"DNS resolution failed",
			"DNS produced no usable address for the requested IP mode. TCP reachability was therefore not tested.",
			result,
			"Verify the hostname, resolver configuration, and expected A or AAAA records.",
		)
	}

	if result := byID(results, "tcp"); result != nil {
		families := tcpFamilies(*result)
		switch {
		case families.v4Success && families.v6Failure && !families.v6Success:
			return conclusion(
				model.StatusWarning,
				"IPv4 reachable; IPv6 connection failed",
				"TCP connected over IPv4, while every attempted IPv6 address failed. This supports an IPv6-specific path or listener issue.",
				result,
				"Compare IPv6 routing, packet filtering, and service listeners with the working IPv4 path.",
			)
		case families.v6Success && families.v4Failure && !families.v4Success:
			return conclusion(
				model.StatusWarning,
				"IPv6 reachable; IPv4 connection failed",
				"TCP connected over IPv6, while every attempted IPv4 address failed. This supports an IPv4-specific path or listener issue.",
				result,
				"Compare IPv4 routing, packet filtering, and service listeners with the working IPv6 path.",
			)
		case result.ErrorCode == tcp.ErrorConnectionRefused:
			return conclusion(
				model.StatusFailed,
				"TCP connections refused",
				"Every resolved address actively refused the TCP connection. This is consistent with no service listening on the target port or an explicit reject policy.",
				result,
				"Verify the service listener, target port, and any explicit reject rules.",
			)
		case result.ErrorCode == tcp.ErrorTimeout:
			return conclusion(
				model.StatusFailed,
				"TCP connections timed out",
				"Every TCP connection attempt timed out. This is consistent with packet filtering, an unavailable route, or a silent remote host.",
				result,
				"Check routing and filtering on both paths, then verify that the remote host is available.",
			)
		case result.Status == model.StatusWarning || (result.Status == model.StatusFailed && result.ErrorCode == tcp.ErrorOther):
			return conclusion(
				result.Status,
				"Mixed TCP results",
				"TCP outcomes differ across the resolved addresses. The evidence does not support a single host-wide cause.",
				result,
				"Compare the failed addresses, IP families, routes, and service listeners with successful attempts.",
			)
		case result.Status == model.StatusFailed:
			return conclusion(
				model.StatusFailed,
				"TCP connection failed",
				"TCP did not connect to any resolved address. The recorded operating-system errors narrow the next investigation.",
				result,
				"Inspect the per-address errors, routing, filtering, and service listener.",
			)
		}
	}

	if result := byID(results, "tls"); result != nil {
		switch result.ErrorCode {
		case tlscheck.ErrorExpired:
			return conclusion(
				result.Status,
				"TLS certificate expired",
				"The peer certificate is outside its validity period because its expiration time has passed.",
				result,
				"Renew and deploy the certificate, then verify the served chain.",
			)
		case tlscheck.ErrorHostnameMismatch:
			return conclusion(
				result.Status,
				"TLS hostname mismatch",
				"The peer certificate SAN does not cover the requested hostname.",
				result,
				"Use the intended hostname or deploy a certificate whose SAN covers it.",
			)
		case tlscheck.ErrorUnknownAuthority:
			return conclusion(
				result.Status,
				"TLS chain is not trusted",
				"The system trust verifier could not build the peer certificate chain to a trusted authority.",
				result,
				"Verify the intended trust root and that the server sends required intermediate certificates.",
			)
		case tlscheck.ErrorNotYetValid:
			return conclusion(
				result.Status,
				"TLS certificate not yet valid",
				"The certificate validity period has not started according to the local clock.",
				result,
				"Check system time and the certificate deployment schedule.",
			)
		}
		if result.Status == model.StatusFailed {
			return conclusion(
				model.StatusFailed,
				"TLS negotiation failed",
				"TCP connected, but TLS negotiation or verification did not complete successfully.",
				result,
				"Inspect the recorded TLS error, protocol support, and certificate configuration.",
			)
		}
	}

	if result := byID(results, "http"); result != nil {
		switch result.ErrorCode {
		case httpcheck.ErrorRedirectLoop, httpcheck.ErrorTooManyRedirects:
			return conclusion(
				model.StatusFailed,
				"HTTP redirect chain failed",
				"The HTTP endpoint repeated a URL or exceeded the configured redirect limit.",
				result,
				"Inspect each Location response and correct the redirect rules.",
			)
		case httpcheck.ErrorClientResponse:
			return conclusion(
				model.StatusWarning,
				"Target reachable with HTTP client error",
				"DNS, TCP, and any required TLS transport completed; the application returned an HTTP 4xx response.",
				result,
				"Verify the URL, method, access policy, and required authentication.",
			)
		case httpcheck.ErrorServerResponse:
			return conclusion(
				model.StatusWarning,
				"Target reachable with application-level error",
				"DNS, TCP, and any required TLS transport completed; the application returned an HTTP 5xx response.",
				result,
				"Inspect service health, dependencies, and server logs.",
			)
		}
		if result.Status == model.StatusFailed {
			return conclusion(
				model.StatusFailed,
				"HTTP transport failed",
				"The HTTP request did not complete. Earlier successful checks still establish which lower layers worked.",
				result,
				"Inspect the HTTP transport error and redirect evidence.",
			)
		}
	}

	if proxy != nil && hasEvidenceCode(*proxy, "PROXY_DISABLED") && transportPassed(results) {
		return conclusion(
			model.StatusWarning,
			"Direct connection works with proxy disabled",
			"A proxy would normally be selected, but this run disabled proxy use and the direct transport succeeded. This run alone does not prove that the proxy is faulty.",
			proxy,
			"Compare a proxy-enabled run and verify proxy reachability and policy.",
		)
	}
	if proxy != nil && hasEvidenceCode(*proxy, "PROXY_SELECTED") {
		status := overallStatus(results)
		title := "Proxy selected"
		description := "Environment rules select a proxy for HTTP requests. Interpret the HTTP remote address and failures in that context."
		if status == model.StatusPassed {
			title = "Target reachable through selected proxy"
			description = "The checks completed successfully, and environment rules selected a proxy for HTTP requests."
		}
		return conclusion(
			maxStatus(status, model.StatusWarning),
			title,
			description,
			proxy,
			"Confirm that using this proxy is intended for the target.",
		)
	}

	status := overallStatus(results)
	title := "Diagnosis completed"
	description := "All applicable diagnostic checks completed without a failed critical check."
	switch status {
	case model.StatusWarning:
		title = "Diagnosis completed with warnings"
		description = "The target is reachable, but one or more checks recorded conditions that deserve attention."
	case model.StatusFailed:
		title = "Diagnosis detected a failure"
		description = "One or more diagnostic checks failed; inspect their concrete evidence before assigning a root cause."
	}
	return genericConclusion(results, status, title, description)
}

func conclusion(status model.Status, title, description string, result *model.CheckResult, recommendation string) model.Summary {
	return conclusionFromResults(
		status,
		title,
		description,
		[]*model.CheckResult{result},
		recommendation,
	)
}

func conclusionFromResults(
	status model.Status,
	title string,
	description string,
	results []*model.CheckResult,
	recommendation string,
) model.Summary {
	references := referencesFromResults(results)
	checkID := ""
	for _, result := range results {
		if result != nil {
			checkID = result.ID
			break
		}
	}
	return model.Summary{
		Status:       status,
		Title:        title,
		Description:  description,
		EvidenceRefs: references,
		Recommendations: []model.Recommendation{{
			ID:       "summary.next_step",
			CheckID:  checkID,
			Priority: "high",
			Message:  recommendation,
		}},
	}
}

func selectedProxyHTTPConclusion(
	httpResult *model.CheckResult,
	proxy *model.CheckResult,
) (model.Summary, bool) {
	results := []*model.CheckResult{proxy, httpResult}
	switch httpResult.ErrorCode {
	case httpcheck.ErrorRedirectLoop, httpcheck.ErrorTooManyRedirects:
		return conclusionFromResults(
			model.StatusFailed,
			"HTTP redirect chain failed through selected proxy",
			"The proxied HTTP request repeated a URL or exceeded the configured redirect limit.",
			results,
			"Inspect each Location response and the proxy path, then correct the redirect rules.",
		), true
	case httpcheck.ErrorClientResponse:
		return conclusionFromResults(
			model.StatusWarning,
			"Target reachable through selected proxy with HTTP client error",
			"The request completed through the selected proxy, and the application returned an HTTP 4xx response.",
			results,
			"Verify the URL, method, access policy, and required authentication.",
		), true
	case httpcheck.ErrorServerResponse:
		return conclusionFromResults(
			model.StatusWarning,
			"Target reachable through selected proxy with application-level error",
			"The request completed through the selected proxy, and the application returned an HTTP 5xx response.",
			results,
			"Inspect service health, dependencies, and server logs.",
		), true
	}

	switch httpResult.Status {
	case model.StatusPassed:
		return conclusionFromResults(
			model.StatusWarning,
			"Target reachable through selected proxy",
			"The HTTP request completed through the selected proxy. Direct-origin preflight failures, if any, do not describe the path used by this request.",
			results,
			"Confirm that using this proxy is intended for the target.",
		), true
	case model.StatusWarning:
		return conclusionFromResults(
			model.StatusWarning,
			"Target reached through selected proxy with warnings",
			"The selected proxy delivered an HTTP response, but the HTTP check recorded a warning.",
			results,
			"Review the HTTP evidence and confirm that using this proxy is intended.",
		), true
	case model.StatusFailed:
		return conclusionFromResults(
			model.StatusFailed,
			"HTTP request through selected proxy failed",
			"The selected proxy path did not complete the HTTP request. Direct-origin preflight checks describe a different path.",
			results,
			"Inspect the HTTP transport error, proxy reachability, and proxy policy.",
		), true
	default:
		return model.Summary{}, false
	}
}

func genericConclusion(
	results []model.CheckResult,
	status model.Status,
	title string,
	description string,
) model.Summary {
	representative := representativeResult(results, status)
	if representative == nil {
		return model.Summary{Status: status, Title: title, Description: description}
	}
	recommendations := append([]model.Recommendation(nil), representative.Recommendations...)
	if len(recommendations) == 0 &&
		(status == model.StatusWarning || status == model.StatusFailed) {
		recommendations = []model.Recommendation{{
			ID:       "summary.review_evidence",
			CheckID:  representative.ID,
			Priority: "medium",
			Message:  "Review the recorded evidence for " + representative.Name + " and address the observed condition.",
		}}
	}
	return model.Summary{
		Status:          status,
		Title:           title,
		Description:     description,
		EvidenceRefs:    referencesFromResults([]*model.CheckResult{representative}),
		Recommendations: recommendations,
	}
}

func representativeResult(results []model.CheckResult, status model.Status) *model.CheckResult {
	if status == model.StatusPassed {
		for index := len(results) - 1; index >= 0; index-- {
			if results[index].Status == model.StatusPassed {
				return &results[index]
			}
		}
	}
	for index := range results {
		if results[index].Status == status {
			return &results[index]
		}
	}
	for index := len(results) - 1; index >= 0; index-- {
		if results[index].Status != model.StatusSkipped {
			return &results[index]
		}
	}
	return nil
}

func referencesFromResults(results []*model.CheckResult) []string {
	references := make([]string, 0)
	seen := make(map[string]struct{})
	for _, result := range results {
		if result == nil {
			continue
		}
		added := false
		for _, evidence := range result.Evidence {
			if evidence.ID == "" {
				continue
			}
			if _, exists := seen[evidence.ID]; exists {
				continue
			}
			seen[evidence.ID] = struct{}{}
			references = append(references, evidence.ID)
			added = true
		}
		if !added && result.ID != "" {
			if _, exists := seen[result.ID]; !exists {
				seen[result.ID] = struct{}{}
				references = append(references, result.ID)
			}
		}
	}
	return references
}

type familyOutcomes struct {
	v4Success bool
	v4Failure bool
	v6Success bool
	v6Failure bool
}

func tcpFamilies(result model.CheckResult) familyOutcomes {
	var out familyOutcomes
	for _, evidence := range result.Evidence {
		if evidence.Code != "TCP_ATTEMPT" {
			continue
		}
		success := strings.EqualFold(evidence.Details["success"], "true")
		switch evidence.Details["family"] {
		case "ipv4":
			out.v4Success = out.v4Success || success
			out.v4Failure = out.v4Failure || !success
		case "ipv6":
			out.v6Success = out.v6Success || success
			out.v6Failure = out.v6Failure || !success
		}
	}
	return out
}

func hasEvidenceCode(result model.CheckResult, code string) bool {
	for _, evidence := range result.Evidence {
		if evidence.Code == code {
			return true
		}
	}
	return false
}

func byID(results []model.CheckResult, id string) *model.CheckResult {
	for index := range results {
		if results[index].ID == id {
			return &results[index]
		}
	}
	return nil
}

func firstWithStatus(results []model.CheckResult, status model.Status) *model.CheckResult {
	for index := range results {
		if results[index].Status == status {
			return &results[index]
		}
	}
	return nil
}

func firstWithErrorCode(results []model.CheckResult, code string) *model.CheckResult {
	for index := range results {
		if results[index].ErrorCode == code {
			return &results[index]
		}
	}
	return nil
}

func transportPassed(results []model.CheckResult) bool {
	if result := byID(results, "http"); result != nil {
		return result.Status == model.StatusPassed || result.Status == model.StatusWarning
	}
	if result := byID(results, "tcp"); result != nil {
		return result.Status == model.StatusPassed || result.Status == model.StatusWarning
	}
	return false
}

func overallStatus(results []model.CheckResult) model.Status {
	status := model.StatusPassed
	for _, result := range results {
		status = maxStatus(status, result.Status)
	}
	return status
}

func maxStatus(left, right model.Status) model.Status {
	if rank(right) > rank(left) {
		return right
	}
	return left
}

func rank(status model.Status) int {
	switch status {
	case model.StatusCancelled:
		return 4
	case model.StatusFailed:
		return 3
	case model.StatusWarning:
		return 2
	case model.StatusRunning, model.StatusPending:
		return 1
	default:
		return 0
	}
}

// ExplainReference returns a readable fallback for an evidence reference.
func ExplainReference(reference string) string {
	return fmt.Sprintf("See evidence %q.", reference)
}
