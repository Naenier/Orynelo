package dns

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

func mergeDetailedFamilies(
	base []model.DNSFamilyResult,
	detailed []model.DNSFamilyResult,
) []model.DNSFamilyResult {
	result := append([]model.DNSFamilyResult(nil), base...)
	for _, detail := range detailed {
		index := familyIndex(result, detail.Family, detail.RecordType)
		if index < 0 || len(result[index].Addresses) > 0 || detail.Status == "" {
			continue
		}
		result[index].Status = detail.Status
		if detail.ErrorCode != "" {
			result[index].ErrorCode = detail.ErrorCode
		} else {
			result[index].ErrorCode = errorCodeForFamilyStatus(detail.Status)
		}
		result[index].Error = ""
		if detail.Error != "" {
			result[index].Error = boundedText(detail.Error)
		}
	}
	return result
}

func applyResolvedFamilyMismatch(results []model.DNSFamilyResult, version model.IPVersion) {
	if version == model.IPVersionAuto {
		return
	}
	required, opposite := "A", "AAAA"
	if version == model.IPVersion6 {
		required, opposite = "AAAA", "A"
	}
	requiredIndex := familyIndex(results, "", required)
	oppositeIndex := familyIndex(results, "", opposite)
	if requiredIndex < 0 || oppositeIndex < 0 ||
		len(results[requiredIndex].Addresses) > 0 ||
		len(results[oppositeIndex].Addresses) == 0 ||
		!absenceStatus(results[requiredIndex].Status) {
		return
	}
	results[requiredIndex].Status = model.DNSFamilyStatusFamilyMismatch
	results[requiredIndex].ErrorCode = ErrorFamilyMismatch
}

func populateLegacyDNSResult(result *model.DNSResult) {
	for _, family := range result.Families {
		switch family.RecordType {
		case "A":
			result.IPv4 = cloneIPs(family.Addresses)
			result.ADuration = family.Duration
			result.AError = family.Error
		case "AAAA":
			result.IPv6 = cloneIPs(family.Addresses)
			result.AAAADuration = family.Duration
			result.AAAAError = family.Error
		}
	}
}

func familyEvidence(
	results []model.DNSFamilyResult,
	duplicates map[string]int,
	responseCodes map[string]string,
	version model.IPVersion,
	addressLimit int,
) []model.Evidence {
	evidence := make([]model.Evidence, 0, len(results))
	for _, result := range results {
		familyKey := familyKey(result.RecordType)
		addresses, omitted := limitedJoinIPs(result.Addresses, addressLimit)
		details := map[string]string{
			"recordType": result.RecordType,
			"family":     result.Family,
			"status":     string(result.Status),
			"addresses":  addresses,
			"duration":   result.Duration.String(),
		}
		if omitted > 0 {
			details["addressesOmitted"] = strconv.Itoa(omitted)
		}
		if count := duplicates[familyKey]; count > 0 {
			details["duplicatesRemoved"] = strconv.Itoa(count)
		}
		responseCode := responseCodes[familyKey]
		if responseCode == "" {
			responseCode = responseCodes[result.RecordType]
		}
		if responseCode != "" {
			details["responseCode"] = responseCode
		}
		if result.ErrorCode != "" {
			details["errorCode"] = result.ErrorCode
		}
		if result.Error != "" {
			details["error"] = result.Error
		}
		message := fmt.Sprintf(
			"%s lookup returned %d unique address(es).",
			result.RecordType,
			len(result.Addresses),
		)
		if normalFamilyAbsence(result, results, version) {
			details["absence"] = "normal_for_auto_mode"
			message = result.RecordType + " records are absent; the other address family remains usable in auto mode."
		}
		evidence = append(evidence, model.Evidence{
			ID:         "dns." + strings.ToLower(result.RecordType),
			NetworkRef: cloneNetworkRef(result.NetworkRef),
			Code:       "DNS_" + result.RecordType + "_RESULT",
			Message:    message,
			Details:    details,
		})
	}
	return evidence
}

func resolverEvidence(
	result model.DNSResult,
	detailsRequested bool,
	detailErr error,
) model.Evidence {
	details := map[string]string{
		"source":        result.ResolverSource,
		"searchDomains": strings.Join(result.SearchDomains, ", "),
	}
	if len(result.CNAMEs) > 0 {
		details["cnames"] = strings.Join(result.CNAMEs, ", ")
	}
	if result.TTL > 0 {
		details["ttl"] = result.TTL.String()
	} else if detailsRequested {
		details["ttl"] = "unavailable"
	}
	code := "DNS_RESOLVER_SOURCE"
	message := "Resolver provenance available to this platform was collected."
	if detailErr != nil {
		code = ErrorDetailsFailed
		message = "Optional detailed DNS evidence could not be collected."
		details["detailsError"] = boundedErrorText(detailErr)
	}
	return model.Evidence{
		ID:         "dns.resolver",
		NetworkRef: networkRef(""),
		Code:       code,
		Message:    message,
		Details:    details,
	}
}

func skippedByLimitEvidence(
	selection AddressSelection,
	options model.DiagnoseOptions,
) model.Evidence {
	limit := options.AddressLimit
	if selection.Skipped > 0 {
		limit = len(selection.Addresses)
	}
	return model.Evidence{
		ID:         "dns.address_limit",
		NetworkRef: networkRef(""),
		Code:       "ADDRESS_SKIPPED_BY_LIMIT",
		Message:    "Resolved backend addresses were omitted by the configured probe bound.",
		Details: map[string]string{
			"probeMode": string(options.ProbeMode),
			"limit":     strconv.Itoa(limit),
			"selected":  strconv.Itoa(len(selection.Addresses)),
			"skipped":   strconv.Itoa(selection.Skipped),
			"total":     strconv.Itoa(selection.Total),
		},
	}
}

func evaluateFamilyResults(
	results []model.DNSFamilyResult,
	version model.IPVersion,
	detailErr error,
) (model.Status, string, string) {
	requested := requestedResults(results, version)
	usable := 0
	problem := false
	for _, result := range requested {
		if len(result.Addresses) > 0 {
			usable += len(result.Addresses)
			if result.Error != "" {
				problem = true
			}
			continue
		}
		if normalFamilyAbsence(result, results, version) {
			continue
		}
		problem = true
	}
	if usable > 0 {
		if problem || detailErr != nil {
			return model.StatusWarning, ErrorPartialFailure,
				fmt.Sprintf("DNS resolved %d usable address(es), but part of the resolver evidence failed.", usable)
		}
		return model.StatusPassed, "", fmt.Sprintf(
			"Resolved %d IPv4 and %d IPv6 address(es).",
			familyAddressCount(results, "A"),
			familyAddressCount(results, "AAAA"),
		)
	}

	code := aggregateFailureCode(requested)
	return model.StatusFailed, code, failureSummary(code)
}

func aggregateFailureCode(results []model.DNSFamilyResult) string {
	for _, result := range results {
		if result.Status == model.DNSFamilyStatusFamilyMismatch {
			return ErrorFamilyMismatch
		}
	}
	priorities := []struct {
		status model.DNSFamilyStatus
		code   string
	}{
		{model.DNSFamilyStatusTimeout, ErrorTimeout},
		{model.DNSFamilyStatusSERVFAIL, ErrorSERVFAIL},
		{model.DNSFamilyStatusNXDOMAIN, ErrorNXDOMAIN},
		{model.DNSFamilyStatusNotFoundUnknown, ErrorNotFoundUnknown},
		{model.DNSFamilyStatusNoData, ErrorNoData},
		{model.DNSFamilyStatusCancelled, ErrorCancelled},
		{model.DNSFamilyStatusError, ErrorLookupFailed},
	}
	for _, candidate := range priorities {
		for _, result := range results {
			if result.Status == candidate.status {
				return candidate.code
			}
		}
	}
	return ErrorNoRecords
}

func failureSummary(code string) string {
	switch code {
	case ErrorFamilyMismatch:
		return "The hostname has addresses, but not for the requested IP family."
	case ErrorNXDOMAIN:
		return "The DNS resolver reported that the hostname does not exist."
	case ErrorNoData:
		return "DNS answered successfully but returned no requested address records."
	case ErrorSERVFAIL:
		return "The DNS server could not complete the lookup."
	case ErrorTimeout:
		return "DNS resolution timed out."
	case ErrorNotFoundUnknown:
		return "The system resolver reported no result without exposing whether it was NXDOMAIN or NODATA."
	case ErrorCancelled:
		return "DNS resolution was cancelled."
	default:
		return "DNS resolution failed for the requested IP mode."
	}
}

func recommendationID(code string) string {
	if code == ErrorFamilyMismatch {
		return "dns.select_available_family"
	}
	return "dns.verify_name"
}

func recommendation(code string) string {
	switch code {
	case ErrorFamilyMismatch:
		return "Select the available IP family or publish the missing address record."
	case ErrorSERVFAIL:
		return "Check the resolver and authoritative DNS service health, then retry."
	case ErrorTimeout:
		return "Check resolver reachability and retry with an appropriate timeout."
	default:
		return "Verify the hostname, resolver configuration, and expected DNS records."
	}
}

func normalFamilyAbsence(
	result model.DNSFamilyResult,
	all []model.DNSFamilyResult,
	version model.IPVersion,
) bool {
	if version != model.IPVersionAuto || result.Status != model.DNSFamilyStatusNoData {
		return false
	}
	for _, candidate := range all {
		if candidate.RecordType != result.RecordType && len(candidate.Addresses) > 0 {
			return true
		}
	}
	return false
}

func requestedResults(
	results []model.DNSFamilyResult,
	version model.IPVersion,
) []model.DNSFamilyResult {
	if version == model.IPVersionAuto {
		return results
	}
	wanted := "A"
	if version == model.IPVersion6 {
		wanted = "AAAA"
	}
	for _, result := range results {
		if result.RecordType == wanted {
			return []model.DNSFamilyResult{result}
		}
	}
	return nil
}

func familyIndex(results []model.DNSFamilyResult, family, record string) int {
	for index, result := range results {
		if record != "" && strings.EqualFold(result.RecordType, record) {
			return index
		}
		if family != "" && strings.EqualFold(result.Family, displayFamily(family)) {
			return index
		}
	}
	return -1
}

func familyAddressCount(results []model.DNSFamilyResult, record string) int {
	if index := familyIndex(results, "", record); index >= 0 {
		return len(results[index].Addresses)
	}
	return 0
}

func errorCodeForFamilyStatus(status model.DNSFamilyStatus) string {
	switch status {
	case model.DNSFamilyStatusNXDOMAIN:
		return ErrorNXDOMAIN
	case model.DNSFamilyStatusNoData:
		return ErrorNoData
	case model.DNSFamilyStatusNotFoundUnknown:
		return ErrorNotFoundUnknown
	case model.DNSFamilyStatusSERVFAIL:
		return ErrorSERVFAIL
	case model.DNSFamilyStatusTimeout:
		return ErrorTimeout
	case model.DNSFamilyStatusCancelled:
		return ErrorCancelled
	case model.DNSFamilyStatusFamilyMismatch:
		return ErrorFamilyMismatch
	case model.DNSFamilyStatusError:
		return ErrorLookupFailed
	default:
		return ""
	}
}

func absenceStatus(status model.DNSFamilyStatus) bool {
	return status == model.DNSFamilyStatusNoData ||
		status == model.DNSFamilyStatusNXDOMAIN ||
		status == model.DNSFamilyStatusNotFoundUnknown
}

func recordType(family string) string {
	if family == "ip4" || strings.EqualFold(family, "ipv4") {
		return "A"
	}
	return "AAAA"
}

func familyKey(record string) string {
	if strings.EqualFold(record, "A") {
		return "ip4"
	}
	return "ip6"
}

func displayFamily(family string) string {
	if family == "ip4" || strings.EqualFold(family, "ipv4") {
		return "ipv4"
	}
	return "ipv6"
}

func normalizeCNAMEs(values []string, limit int) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
		if value == "" || len(value) > 253 || containsControl(value) {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
		if limit > 0 && len(result) == limit {
			break
		}
	}
	return result
}

func limitedJoinIPs(addresses []net.IP, limit int) (string, int) {
	if limit <= 0 {
		limit = model.DefaultDiagnoseOptions("").AddressLimit
	}
	shown := addresses
	omitted := 0
	if len(shown) > limit {
		omitted = len(shown) - limit
		shown = shown[:limit]
	}
	return joinIPs(shown), omitted
}

func containsControl(value string) bool {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return true
		}
	}
	return false
}

func boundedErrorText(err error) string {
	if err == nil {
		return ""
	}
	return boundedText(err.Error())
}

func boundedText(value string) string {
	const maximumRunes = 512
	runes := []rune(value)
	if len(runes) <= maximumRunes {
		return string(runes)
	}
	return string(runes[:maximumRunes]) + "…"
}

func familyNetworkRefs(results []model.DNSFamilyResult) []model.NetworkRef {
	refs := make([]model.NetworkRef, 0, len(results))
	for _, result := range results {
		if result.NetworkRef != nil {
			refs = append(refs, *cloneNetworkRef(result.NetworkRef))
		}
	}
	return refs
}

func networkRef(attemptID string) *model.NetworkRef {
	return &model.NetworkRef{
		PathID:    directPathID,
		HopID:     originHopID,
		AttemptID: attemptID,
	}
}

func cloneNetworkRef(ref *model.NetworkRef) *model.NetworkRef {
	if ref == nil {
		return nil
	}
	copy := *ref
	return &copy
}

func dnsAttemptID(record string) string {
	if strings.EqualFold(record, "A") {
		return "attempt-dns-a"
	}
	return "attempt-dns-aaaa"
}
