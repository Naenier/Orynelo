// Package summary turns concrete check outcomes into cautious, evidence-based
// conclusions. It does not infer a single root cause from ambiguous symptoms.
package summary

import (
	"fmt"
	"strings"

	httpcheck "github.com/Naenier/orynelo/internal/diagnostics/checks/http"
	"github.com/Naenier/orynelo/internal/diagnostics/checks/tcp"
	tlscheck "github.com/Naenier/orynelo/internal/diagnostics/checks/tls"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

const (
	errorCheckTimeout       = "CHECK_TIMEOUT"
	errorOperationTimeout   = "OPERATION_TIMEOUT"
	errorProxyConfigInvalid = "PROXY_CONFIG_INVALID"
)

// conclusionSeverity is deliberately separate from model.Status. A check can
// be cancelled without having observed a blocker, and a warning can describe
// either a degraded network path or a merely informational condition.
type conclusionSeverity uint8

const (
	severityInformational conclusionSeverity = iota
	severityDegraded
	severityInterrupted
	severityBlocker
)

type conclusionCandidate struct {
	severity       conclusionSeverity
	priority       int
	status         model.Status
	title          string
	description    string
	results        []*model.CheckResult
	recommendation string
}

type diagnosticFacts struct {
	results           []model.CheckResult
	proxy             *model.CheckResult
	http              *model.CheckResult
	proxySelected     bool
	httpRoute         string
	httpReached       bool
	preflightFailures []*model.CheckResult
}

// Build gathers facts first, creates independently ranked conclusion
// candidates, and only then chooses the primary conclusion. This prevents plan
// order from allowing a degraded-path warning to hide a blocker.
// Build derives the highest-severity evidence-based conclusion from results.
func Build(results []model.CheckResult) model.Summary {
	facts := collectFacts(results)
	candidates := buildCandidates(facts)
	if len(candidates) == 0 {
		return model.Summary{
			Status:      model.StatusPassed,
			Title:       "Diagnosis completed",
			Description: "No adverse diagnostic facts were recorded.",
		}
	}

	best := candidates[0]
	for _, candidate := range candidates[1:] {
		if candidate.severity > best.severity ||
			(candidate.severity == best.severity && candidate.priority > best.priority) {
			best = candidate
		}
	}
	return conclusionFromResults(
		best.status,
		best.title,
		best.description,
		best.results,
		best.recommendation,
	)
}

func collectFacts(results []model.CheckResult) diagnosticFacts {
	facts := diagnosticFacts{results: results}
	facts.proxy = byID(results, "environment")
	facts.http = byID(results, "http")
	facts.proxySelected = facts.proxy != nil && hasEvidenceCode(*facts.proxy, "PROXY_SELECTED")
	if facts.http != nil {
		facts.httpRoute = evidenceDetailByID(*facts.http, "http.response", "route")
		switch facts.httpRoute {
		case "proxy", "mixed":
			facts.proxySelected = true
		case "direct", "blocked_by_proxy_policy":
			facts.proxySelected = false
		}
	}
	facts.httpReached = facts.http != nil &&
		(facts.http.Status == model.StatusPassed || facts.http.Status == model.StatusWarning)
	if facts.httpReached {
		for index := range results {
			if isPreflight(&results[index]) && results[index].Status == model.StatusFailed {
				facts.preflightFailures = append(facts.preflightFailures, &results[index])
			}
		}
	}
	return facts
}

func buildCandidates(facts diagnosticFacts) []conclusionCandidate {
	var candidates []conclusionCandidate
	add := func(candidate conclusionCandidate) { candidates = append(candidates, candidate) }

	if result := firstWithErrorCode(facts.results, errorOperationTimeout); result != nil {
		add(blocker(1000, "Diagnosis timed out",
			"The global diagnosis timeout elapsed before every stage completed.",
			[]*model.CheckResult{result},
			"Increase the global timeout or investigate the stage that consumed the available time."))
	}
	if result := firstRelevantCheckTimeout(facts); result != nil {
		budget := evidenceDetail(*result, errorCheckTimeout, "configuredBudget")
		if budget == "" && result.Duration > 0 {
			budget = result.Duration.String()
		}
		stage := strings.TrimSpace(result.Name)
		if stage == "" {
			stage = result.ID
		}
		description := fmt.Sprintf("The %s stage exceeded its configured per-check budget.", stage)
		if budget != "" {
			description = fmt.Sprintf("The %s stage exceeded its configured per-check budget of %s.", stage, budget)
		}
		add(blocker(950, "Diagnostic check timed out", description,
			[]*model.CheckResult{result},
			"Increase the per-check timeout or investigate why this stage exhausted its budget."))
	}
	if result := byID(facts.results, "target"); result != nil && result.Status == model.StatusFailed {
		add(blocker(900, "Invalid target",
			"The target could not be validated, so no network conclusion can be made.",
			[]*model.CheckResult{result},
			"Correct the target syntax and include a valid host and port."))
	}
	if invalid := proxyInvalidResults(facts.results); len(invalid) > 0 {
		add(blocker(875, "Proxy configuration is invalid",
			"The configured proxy was rejected, so Orynelo did not silently fall back to a direct request.",
			invalid,
			"Correct or remove the invalid proxy setting, then run the diagnosis again."))
	}

	if result := byID(facts.results, "dns"); result != nil &&
		result.Status == model.StatusFailed && !facts.isPreflightDiscrepancy(result) &&
		!facts.isAuxiliaryPreflight(result) && !facts.checkTimeoutSuperseded(result) {
		add(blocker(700, "DNS resolution failed",
			"DNS produced no usable address for the requested IP mode. TCP reachability was therefore not tested.",
			[]*model.CheckResult{result},
			"Verify the hostname, resolver configuration, and expected A or AAAA records."))
	}
	addTCPCandidates(&candidates, facts)
	addTLSCandidates(&candidates, facts)
	addHTTPCandidates(&candidates, facts)

	for index := range facts.results {
		result := &facts.results[index]
		if result.Status == model.StatusFailed && !facts.isPreflightDiscrepancy(result) &&
			!facts.isAuxiliaryPreflight(result) && !facts.checkTimeoutSuperseded(result) {
			add(blocker(100, "Diagnosis detected a failure",
				"A diagnostic check failed; inspect its concrete evidence before assigning a root cause.",
				[]*model.CheckResult{result},
				"Review the failed check evidence and address the observed condition."))
		}
	}

	if result := firstWithStatus(facts.results, model.StatusCancelled); result != nil {
		add(conclusionCandidate{
			severity:       severityInterrupted,
			priority:       500,
			status:         model.StatusCancelled,
			title:          "Diagnosis cancelled",
			description:    "The operation was cancelled before all diagnostic stages completed. Completed evidence remains available.",
			results:        []*model.CheckResult{result},
			recommendation: "Run the diagnosis again when the full result is needed.",
		})
	}

	addProxyCandidates(&candidates, facts)
	addGenericWarningCandidates(&candidates, facts)
	if allWithStatus(facts.results, model.StatusNotApplicable) {
		results := resultPointers(facts.results)
		add(conclusionCandidate{
			severity:       severityInformational,
			priority:       25,
			status:         model.StatusNotApplicable,
			title:          "No applicable diagnostic checks",
			description:    "Every supplied check is explicitly not applicable to this target or diagnostic mode.",
			results:        results,
			recommendation: "Select a different diagnostic mode if these checks were expected to apply.",
		})
	} else if onlySkippedOrNotApplicable(facts.results) {
		results := resultPointers(facts.results)
		add(conclusionCandidate{
			severity:       severityInformational,
			priority:       20,
			status:         model.StatusSkipped,
			title:          "Applicable diagnostic checks were skipped",
			description:    "At least one applicable check did not run because a prerequisite or auxiliary budget was unavailable.",
			results:        results,
			recommendation: "Review the prerequisite and budget evidence before running the diagnosis again.",
		})
	} else if result := lastWithStatus(facts.results, model.StatusPassed); result != nil {
		add(conclusionCandidate{
			severity:    severityInformational,
			priority:    10,
			status:      model.StatusPassed,
			title:       "Diagnosis completed",
			description: "All applicable diagnostic checks completed without a failed critical check.",
			results:     []*model.CheckResult{result},
		})
	}
	return candidates
}

func blocker(priority int, title, description string, results []*model.CheckResult, recommendation string) conclusionCandidate {
	return conclusionCandidate{
		severity:       severityBlocker,
		priority:       priority,
		status:         model.StatusFailed,
		title:          title,
		description:    description,
		results:        results,
		recommendation: recommendation,
	}
}

func addTCPCandidates(candidates *[]conclusionCandidate, facts diagnosticFacts) {
	result := byID(facts.results, "tcp")
	if result == nil || facts.isAuxiliaryPreflight(result) {
		return
	}
	families := tcpFamilies(*result)
	switch {
	case result.Status == model.StatusWarning && families.v4Success && families.v6Failure && !families.v6Success:
		*candidates = append(*candidates, conclusionCandidate{
			severity: severityDegraded, priority: 700, status: model.StatusWarning,
			title: "IPv4 reachable; IPv6 connection failed",
			description: "TCP connected over IPv4, while every attempted IPv6 address failed. " +
				"This supports an IPv6-specific path or listener issue.",
			results: []*model.CheckResult{result},
			recommendation: "Compare IPv6 routing, packet filtering, and service listeners " +
				"with the working IPv4 path.",
		})
	case result.Status == model.StatusWarning && families.v6Success && families.v4Failure && !families.v4Success:
		*candidates = append(*candidates, conclusionCandidate{
			severity: severityDegraded, priority: 700, status: model.StatusWarning,
			title: "IPv6 reachable; IPv4 connection failed",
			description: "TCP connected over IPv6, while every attempted IPv4 address failed. " +
				"This supports an IPv4-specific path or listener issue.",
			results: []*model.CheckResult{result},
			recommendation: "Compare IPv4 routing, packet filtering, and service listeners " +
				"with the working IPv6 path.",
		})
	case result.Status == model.StatusWarning:
		*candidates = append(*candidates, conclusionCandidate{
			severity: severityDegraded, priority: 600, status: model.StatusWarning,
			title:          "Mixed TCP results",
			description:    "TCP outcomes differ across the resolved addresses. The evidence does not support a single host-wide cause.",
			results:        []*model.CheckResult{result},
			recommendation: "Compare the failed addresses, IP families, routes, and service listeners with successful attempts.",
		})
	case result.Status == model.StatusFailed && !facts.isPreflightDiscrepancy(result) &&
		!facts.checkTimeoutSuperseded(result):
		title := "TCP connection failed"
		description := "TCP did not connect to any resolved address. The recorded operating-system errors narrow the next investigation."
		recommendation := "Inspect the per-address errors, routing, filtering, and service listener."
		switch result.ErrorCode {
		case tcp.ErrorConnectionRefused:
			title = "TCP connections refused"
			description = "Every resolved address actively refused the TCP connection. This is consistent with no service listening on the target port or an explicit reject policy."
			recommendation = "Verify the service listener, target port, and any explicit reject rules."
		case tcp.ErrorTimeout:
			title = "TCP connections timed out"
			description = "Every TCP connection attempt timed out. This is consistent with packet filtering, an unavailable route, or a silent remote host."
			recommendation = "Check routing and filtering on both paths, then verify that the remote host is available."
		case tcp.ErrorOther:
			title = "Mixed TCP results"
			description = "TCP outcomes differ across the resolved addresses. The evidence does not support a single host-wide cause."
			recommendation = "Compare the failed addresses, IP families, routes, and service listeners with successful attempts."
		}
		*candidates = append(*candidates, blocker(650, title, description,
			[]*model.CheckResult{result}, recommendation))
	}
}

func addTLSCandidates(candidates *[]conclusionCandidate, facts diagnosticFacts) {
	result := byID(facts.results, "tls")
	if result == nil || facts.isAuxiliaryPreflight(result) {
		return
	}
	severity := severityDegraded
	status := result.Status
	priority := 800
	if result.Status == model.StatusFailed {
		if facts.isPreflightDiscrepancy(result) {
			return
		}
		if facts.checkTimeoutSuperseded(result) {
			return
		}
		severity = severityBlocker
	}
	title, description, recommendation := "", "", ""
	switch result.ErrorCode {
	case tlscheck.ErrorExpired:
		title = "TLS certificate expired"
		description = "The peer certificate is outside its validity period because its expiration time has passed."
		recommendation = "Renew and deploy the certificate, then verify the served chain."
	case tlscheck.ErrorHostnameMismatch:
		title = "TLS hostname mismatch"
		description = "The peer certificate SAN does not cover the requested hostname."
		recommendation = "Use the intended hostname or deploy a certificate whose SAN covers it."
	case tlscheck.ErrorUnknownAuthority:
		title = "TLS chain is not trusted"
		description = "The system trust verifier could not build the peer certificate chain to a trusted authority."
		recommendation = "Verify the intended trust root and that the server sends required intermediate certificates."
	case tlscheck.ErrorNotYetValid:
		title = "TLS certificate not yet valid"
		description = "The certificate validity period has not started according to the local clock."
		recommendation = "Check system time and the certificate deployment schedule."
	default:
		if result.Status != model.StatusFailed {
			return
		}
		priority = 600
		title = "TLS negotiation failed"
		description = "TCP connected, but TLS negotiation or verification did not complete successfully."
		recommendation = "Inspect the recorded TLS error, protocol support, and certificate configuration."
	}
	*candidates = append(*candidates, conclusionCandidate{
		severity: severity, priority: priority, status: status,
		title: title, description: description, results: []*model.CheckResult{result},
		recommendation: recommendation,
	})
}

func addHTTPCandidates(candidates *[]conclusionCandidate, facts diagnosticFacts) {
	result := facts.http
	if result == nil {
		return
	}
	mixedRoute := facts.httpRoute == "mixed"
	proxyOnlyRoute := facts.httpRoute == "proxy" ||
		(facts.httpRoute == "" && facts.proxySelected)
	proxyInvolved := mixedRoute || proxyOnlyRoute
	related := []*model.CheckResult{result}
	if proxyInvolved && facts.proxy != nil {
		related = []*model.CheckResult{facts.proxy, result}
	}
	related = append(related, facts.preflightFailures...)
	discrepancy := ""
	if len(facts.preflightFailures) > 0 {
		discrepancy = " Direct preflight failures describe a different or inconsistent path and are recorded as a discrepancy."
	}
	switch result.ErrorCode {
	case httpcheck.ErrorRedirectLoop, httpcheck.ErrorTooManyRedirects:
		title := "HTTP redirect chain failed"
		description := "The HTTP endpoint repeated a URL or exceeded the configured redirect limit."
		if mixedRoute {
			title = "HTTP redirect chain failed across mixed direct/proxy routes"
			description = "The HTTP request used both direct and proxy routes before the redirect chain failed."
		} else if proxyOnlyRoute {
			title = "HTTP redirect chain failed through selected proxy"
			description = "The proxied HTTP request repeated a URL or exceeded the configured redirect limit."
		}
		*candidates = append(*candidates, blocker(850, title, description, related,
			"Inspect each Location response and correct the redirect rules."))
		return
	case httpcheck.ErrorClientResponse:
		title := "Target reachable with HTTP client error"
		description := "DNS, TCP, and any required TLS transport completed; the application returned an HTTP 4xx response."
		if mixedRoute {
			title = "Target reachable across mixed direct/proxy routes with HTTP client error"
			description = "The request used both direct and proxy routes, and the application returned an HTTP 4xx response."
		} else if proxyOnlyRoute {
			title = "Target reachable through selected proxy with HTTP client error"
			description = "The request completed through the selected proxy, and the application returned an HTTP 4xx response."
		}
		*candidates = append(*candidates, conclusionCandidate{
			severity: severityDegraded, priority: 900, status: model.StatusWarning,
			title: title, description: description + discrepancy, results: related,
			recommendation: "Verify the URL, method, access policy, and required authentication.",
		})
		return
	case httpcheck.ErrorServerResponse:
		title := "Target reachable with application-level error"
		description := "DNS, TCP, and any required TLS transport completed; the application returned an HTTP 5xx response."
		if mixedRoute {
			title = "Target reachable across mixed direct/proxy routes with application-level error"
			description = "The request used both direct and proxy routes, and the application returned an HTTP 5xx response."
		} else if proxyOnlyRoute {
			title = "Target reachable through selected proxy with application-level error"
			description = "The request completed through the selected proxy, and the application returned an HTTP 5xx response."
		}
		*candidates = append(*candidates, conclusionCandidate{
			severity: severityDegraded, priority: 900, status: model.StatusWarning,
			title: title, description: description + discrepancy, results: related,
			recommendation: "Inspect service health, dependencies, and server logs.",
		})
		return
	}
	if result.Status == model.StatusPassed {
		switch {
		case mixedRoute:
			*candidates = append(*candidates, conclusionCandidate{
				severity: severityDegraded, priority: 950, status: model.StatusWarning,
				title: "Target reachable across mixed direct/proxy routes",
				description: "The HTTP redirect chain completed using both direct and proxy routes. " +
					"Each redirect hop records the route selected by the captured proxy policy.",
				results:        related,
				recommendation: "Confirm that each direct/proxy transition is intended for the redirect chain.",
			})
		case proxyOnlyRoute:
			*candidates = append(*candidates, conclusionCandidate{
				severity: severityDegraded, priority: 950, status: model.StatusWarning,
				title: "Target reachable through selected proxy",
				description: "The HTTP request completed through the selected proxy. " +
					"Direct-origin preflight failures, if any, do not describe the path used by this request.",
				results:        related,
				recommendation: "Confirm that using this proxy is intended for the target.",
			})
		case len(facts.preflightFailures) > 0:
			*candidates = append(*candidates, conclusionCandidate{
				severity: severityDegraded, priority: 950, status: model.StatusWarning,
				title: "HTTP request succeeded despite preflight failure",
				description: "The actual HTTP request succeeded. One or more direct preflight checks failed, " +
					"so those failures are a path discrepancy rather than proof that the request path was blocked.",
				results:        related,
				recommendation: "Compare the actual HTTP peer and resolver path with the failed preflight evidence.",
			})
		default:
			*candidates = append(*candidates, conclusionCandidate{
				severity: severityInformational, priority: 100, status: model.StatusPassed,
				title:       "Diagnosis completed",
				description: "The actual HTTP request completed successfully and no blocking diagnostic fact was recorded.",
				results:     []*model.CheckResult{result},
			})
		}
		return
	}
	if result.Status == model.StatusWarning {
		title := "HTTP request completed with warnings"
		if mixedRoute {
			title = "Target reached across mixed direct/proxy routes with warnings"
		} else if proxyOnlyRoute {
			title = "Target reached through selected proxy with warnings"
		}
		*candidates = append(*candidates, conclusionCandidate{
			severity: severityDegraded, priority: 850, status: model.StatusWarning,
			title:          title,
			description:    "The actual HTTP request completed, but the HTTP check recorded a warning." + discrepancy,
			results:        related,
			recommendation: "Review the HTTP evidence and the actual request path.",
		})
		return
	}
	if result.Status == model.StatusFailed && result.ErrorCode != errorProxyConfigInvalid {
		title := "HTTP transport failed"
		description := "The HTTP request did not complete. Earlier successful checks still establish which lower layers worked."
		recommendation := "Inspect the HTTP transport error and redirect evidence."
		if mixedRoute {
			title = "HTTP request across mixed direct/proxy routes failed"
			description = "The request used both direct and proxy routes before the HTTP transport failed."
			recommendation = "Inspect the HTTP transport error and each redirect hop's route policy."
		} else if proxyOnlyRoute {
			title = "HTTP request through selected proxy failed"
			description = "The selected proxy path did not complete the HTTP request. Direct-origin preflight checks describe a different path."
			recommendation = "Inspect the HTTP transport error, proxy reachability, and proxy policy."
		}
		*candidates = append(*candidates, blocker(550, title, description, related, recommendation))
	}
}

func addProxyCandidates(candidates *[]conclusionCandidate, facts diagnosticFacts) {
	if facts.proxy == nil {
		return
	}
	if hasEvidenceCode(*facts.proxy, "PROXY_DISABLED") && transportPassed(facts.results) {
		*candidates = append(*candidates, conclusionCandidate{
			severity: severityDegraded, priority: 650, status: model.StatusWarning,
			title: "Direct connection works with proxy disabled",
			description: "A proxy would normally be selected, but this run disabled proxy use and the direct transport succeeded. " +
				"This run alone does not prove that the proxy is faulty.",
			results:        []*model.CheckResult{facts.proxy},
			recommendation: "Compare a proxy-enabled run and verify proxy reachability and policy.",
		})
	} else if facts.proxySelected && facts.http == nil {
		*candidates = append(*candidates, conclusionCandidate{
			severity: severityDegraded, priority: 400, status: model.StatusWarning,
			title:          "Proxy selected",
			description:    "Environment rules selected a proxy, but no actual HTTP result was recorded.",
			results:        []*model.CheckResult{facts.proxy},
			recommendation: "Confirm that using this proxy is intended and review why the HTTP check did not run.",
		})
	}
}

func addGenericWarningCandidates(candidates *[]conclusionCandidate, facts diagnosticFacts) {
	for index := range facts.results {
		result := &facts.results[index]
		if result.Status != model.StatusWarning || facts.isAuxiliaryPreflight(result) {
			continue
		}
		*candidates = append(*candidates, conclusionCandidate{
			severity: severityDegraded, priority: 50, status: model.StatusWarning,
			title:          "Diagnosis completed with warnings",
			description:    "The target may be reachable, but a check recorded a condition that deserves attention.",
			results:        []*model.CheckResult{result},
			recommendation: "Review the recorded warning evidence and address the observed condition.",
		})
	}
}

func (facts diagnosticFacts) isPreflightDiscrepancy(result *model.CheckResult) bool {
	return facts.httpReached && result.Status == model.StatusFailed && isPreflight(result)
}

func (facts diagnosticFacts) isAuxiliaryPreflight(result *model.CheckResult) bool {
	return result != nil && facts.http != nil &&
		(result.Role == model.CheckRoleAuxiliaryDirectComparison ||
			(facts.proxySelected && isPreflight(result)))
}

func isPreflight(result *model.CheckResult) bool {
	if result == nil {
		return false
	}
	if result.Role == model.CheckRoleAuxiliaryDirectComparison {
		return true
	}
	switch result.ID {
	case "dns", "route", "tcp", "tls":
		return true
	default:
		return false
	}
}

func proxyInvalidResults(results []model.CheckResult) []*model.CheckResult {
	invalid := make([]*model.CheckResult, 0, 2)
	for index := range results {
		if results[index].ErrorCode == errorProxyConfigInvalid ||
			hasEvidenceCode(results[index], errorProxyConfigInvalid) {
			invalid = append(invalid, &results[index])
		}
	}
	return invalid
}

func evidenceDetail(result model.CheckResult, code, key string) string {
	for _, evidence := range result.Evidence {
		if evidence.Code == code {
			return evidence.Details[key]
		}
	}
	return ""
}

func evidenceDetailByID(result model.CheckResult, id, key string) string {
	for _, evidence := range result.Evidence {
		if evidence.ID == id {
			return evidence.Details[key]
		}
	}
	return ""
}

func allWithStatus(results []model.CheckResult, status model.Status) bool {
	if len(results) == 0 {
		return false
	}
	for _, result := range results {
		if result.Status != status {
			return false
		}
	}
	return true
}

func onlySkippedOrNotApplicable(results []model.CheckResult) bool {
	if len(results) == 0 {
		return false
	}
	hasSkipped := false
	for _, result := range results {
		switch result.Status {
		case model.StatusSkipped:
			hasSkipped = true
		case model.StatusNotApplicable:
		default:
			return false
		}
	}
	return hasSkipped
}

func resultPointers(results []model.CheckResult) []*model.CheckResult {
	pointers := make([]*model.CheckResult, 0, len(results))
	for index := range results {
		pointers = append(pointers, &results[index])
	}
	return pointers
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
	summary := model.Summary{
		Status:       status,
		Title:        title,
		Description:  description,
		EvidenceRefs: references,
	}
	if strings.TrimSpace(recommendation) != "" {
		summary.Recommendations = []model.Recommendation{{
			ID:       "summary.next_step",
			CheckID:  checkID,
			Priority: "high",
			Message:  recommendation,
		}}
	}
	return summary
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

func lastWithStatus(results []model.CheckResult, status model.Status) *model.CheckResult {
	for index := len(results) - 1; index >= 0; index-- {
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

func firstRelevantCheckTimeout(facts diagnosticFacts) *model.CheckResult {
	for index := range facts.results {
		result := &facts.results[index]
		if result.ErrorCode == errorCheckTimeout &&
			!facts.isPreflightDiscrepancy(result) &&
			!facts.isAuxiliaryPreflight(result) &&
			!facts.checkTimeoutSuperseded(result) {
			return result
		}
	}
	return nil
}

func (facts diagnosticFacts) checkTimeoutSuperseded(result *model.CheckResult) bool {
	if result == nil || result.ErrorCode != errorCheckTimeout {
		return false
	}
	currentLayer := checkLayer(result.ID)
	if currentLayer < 0 {
		return false
	}
	for index := range facts.results {
		candidate := &facts.results[index]
		if candidate.Status != model.StatusFailed ||
			facts.isAuxiliaryPreflight(candidate) ||
			checkLayer(candidate.ID) <= currentLayer {
			continue
		}
		return true
	}
	return false
}

func checkLayer(checkID string) int {
	switch checkID {
	case "target":
		return 0
	case "environment":
		return 1
	case "dns":
		return 2
	case "route":
		return 3
	case "tcp":
		return 4
	case "tls":
		return 5
	case "http":
		return 6
	default:
		return -1
	}
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

// ExplainReference returns a readable fallback for an evidence reference.
// ExplainReference returns a stable human-readable explanation for an evidence reference.
func ExplainReference(reference string) string {
	return fmt.Sprintf("See evidence %q.", reference)
}
