package dns

import (
	"net"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

func (c *Check) literalResult(state *model.State, ip net.IP) model.CheckResult {
	ip = canonicalIP(ip)
	record := "AAAA"
	family := "ipv6"
	if ip.To4() != nil {
		record = "A"
		family = "ipv4"
	}
	ref := networkRef(dnsAttemptID(record))
	familyResult := model.DNSFamilyResult{
		NetworkRef: ref,
		Family:     family,
		RecordType: record,
		Status:     model.DNSFamilyStatusSuccess,
		Addresses:  []net.IP{ip},
	}
	mismatch := (ip.To4() != nil && state.Options.IPVersion == model.IPVersion6) ||
		(ip.To4() == nil && state.Options.IPVersion == model.IPVersion4)
	if mismatch {
		familyResult.Status = model.DNSFamilyStatusFamilyMismatch
		familyResult.ErrorCode = ErrorIPFamilyMismatch
	}
	result := model.DNSResult{Families: []model.DNSFamilyResult{familyResult}}
	populateLegacyDNSResult(&result)
	state.SetDNS(result)
	c.recordDNSPath(state, result)
	if mismatch {
		return ipFamilyMismatchResult(c, ip, state.Options.IPVersion, ref)
	}
	return model.CheckResult{
		ID:          c.ID(),
		Name:        c.Name(),
		Status:      model.StatusPassed,
		Summary:     "The target is an IP literal; DNS lookup is not required.",
		NetworkRefs: []model.NetworkRef{*ref},
		Evidence: []model.Evidence{{
			ID:         "dns.literal",
			NetworkRef: cloneNetworkRef(ref),
			Code:       "DNS_IP_LITERAL",
			Message:    "The target contains a canonical IP address.",
			Details:    map[string]string{"address": ip.String()},
		}},
	}
}

func ipFamilyMismatchResult(
	c *Check,
	literal net.IP,
	requested model.IPVersion,
	ref *model.NetworkRef,
) model.CheckResult {
	return model.CheckResult{
		ID:          c.ID(),
		Name:        c.Name(),
		Status:      model.StatusFailed,
		Summary:     "The target IP family does not match the requested IP mode.",
		ErrorCode:   ErrorIPFamilyMismatch,
		NetworkRefs: []model.NetworkRef{*ref},
		Evidence: []model.Evidence{{
			ID:         "dns.literal_family_mismatch",
			NetworkRef: cloneNetworkRef(ref),
			Code:       ErrorIPFamilyMismatch,
			Message:    "The literal address family does not match the requested IP mode.",
			Details: map[string]string{
				"address":       literal.String(),
				"addressFamily": literalFamily(literal),
				"requestedMode": string(requested),
			},
		}},
		Recommendations: []model.Recommendation{{
			ID:       "dns.select_literal_family",
			Priority: "high",
			Message:  "Select an IP family that matches the literal target address.",
		}},
	}
}

func literalFamily(ip net.IP) string {
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

func (c *Check) recordDNSPath(state *model.State, result model.DNSResult) {
	role := model.NetworkPathRoleClientEffective
	if state.Options.ProbeMode == model.ProbeModeAddressMatrix {
		role = model.NetworkPathRoleAddressMatrix
	}
	paths := state.NetworkPaths()
	pathIndex := -1
	for index := range paths {
		if paths[index].ID == directPathID {
			pathIndex = index
			break
		}
	}
	if pathIndex < 0 {
		paths = append(paths, model.NetworkPath{
			ID:       directPathID,
			Role:     role,
			Kind:     model.NetworkPathDirect,
			Sequence: len(paths) + 1,
		})
		pathIndex = len(paths) - 1
	}
	hopIndex := -1
	for index := range paths[pathIndex].Hops {
		if paths[pathIndex].Hops[index].ID == originHopID {
			hopIndex = index
			break
		}
	}
	if hopIndex < 0 {
		paths[pathIndex].Hops = append(paths[pathIndex].Hops, model.NetworkHop{
			ID:       originHopID,
			PathID:   directPathID,
			Sequence: len(paths[pathIndex].Hops) + 1,
			Kind:     model.NetworkHopOrigin,
			Scheme:   state.Target.Scheme,
			Host:     state.Target.Host,
			Port:     state.Target.Port,
			Zone:     state.Target.Zone,
		})
		hopIndex = len(paths[pathIndex].Hops) - 1
	}
	dnsAttempts := make([]model.NetworkAttempt, 0, len(result.Families))
	for _, family := range result.Families {
		if family.NetworkRef == nil {
			continue
		}
		attempt := model.NetworkAttempt{
			ID:        family.NetworkRef.AttemptID,
			PathID:    directPathID,
			HopID:     originHopID,
			Kind:      model.NetworkAttemptDNS,
			State:     model.AttemptStateCompleted,
			Network:   family.Family,
			Duration:  family.Duration,
			ErrorCode: family.ErrorCode,
			Error:     family.Error,
		}
		if family.Status == model.DNSFamilyStatusCancelled {
			attempt.State = model.AttemptStateCancelled
		}
		dnsAttempts = append(dnsAttempts, attempt)
	}
	existing := make(
		[]model.NetworkAttempt,
		0,
		len(paths[pathIndex].Hops[hopIndex].Attempts),
	)
	for _, attempt := range paths[pathIndex].Hops[hopIndex].Attempts {
		if attempt.Kind != model.NetworkAttemptDNS {
			existing = append(existing, attempt)
		}
	}
	paths[pathIndex].Hops[hopIndex].Attempts = append(dnsAttempts, existing...)
	state.SetNetworkPaths(paths)
}
