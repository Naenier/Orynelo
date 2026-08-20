package diagnostics

import (
	"fmt"
	"net"
	"sort"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

const (
	directPathID = "path-direct"
	originHopID  = "hop-origin"
)

func initialDirectPath(target model.Target, options model.DiagnoseOptions) model.NetworkPath {
	role := model.NetworkPathRoleClientEffective
	if options.ProbeMode == model.ProbeModeAddressMatrix {
		role = model.NetworkPathRoleAddressMatrix
	} else if target.Kind == model.TargetHTTP {
		role = model.NetworkPathRoleAuxiliaryDirect
	}
	return model.NetworkPath{
		ID:       directPathID,
		Role:     role,
		Kind:     model.NetworkPathDirect,
		Sequence: 1,
		Hops: []model.NetworkHop{{
			ID:       originHopID,
			PathID:   directPathID,
			Sequence: 1,
			Kind:     model.NetworkHopOrigin,
			URL:      target.Normalized,
			Scheme:   target.Scheme,
			Host:     target.Host,
			Port:     target.Port,
			Zone:     target.Zone,
		}},
	}
}

// correlatedNetworkResult materializes legacy check artifacts into the path
// graph and supplies missing references without changing old result fields.
func correlatedNetworkResult(
	state *model.State,
	checks []model.CheckResult,
) ([]model.NetworkPath, []model.CheckResult) {
	paths := state.NetworkPaths()
	if len(paths) == 0 {
		paths = []model.NetworkPath{initialDirectPath(state.Target, state.Options)}
	}
	paths = mergeLegacyAttempts(paths, state)
	for index := range paths {
		if paths[index].ID == directPathID &&
			(state.Proxy().Selected ||
				(state.Target.Kind == model.TargetHTTP && state.Options.ProbeMode != model.ProbeModeAddressMatrix)) {
			paths[index].Role = model.NetworkPathRoleAuxiliaryDirect
		}
	}
	for index := range paths {
		paths[index].Sequence = index + 1
		for hopIndex := range paths[index].Hops {
			paths[index].Hops[hopIndex].Sequence = hopIndex + 1
		}
	}

	result := append([]model.CheckResult(nil), checks...)
	for index := range result {
		refs := result[index].NetworkRefs
		if len(refs) == 0 {
			refs = refsForCheck(state, result[index].ID, paths)
		}
		refs = uniqueRefs(refs)
		if len(refs) == 0 {
			refs = []model.NetworkRef{firstPathRef(paths)}
		}
		result[index].NetworkRefs = refs
		for evidenceIndex := range result[index].Evidence {
			if result[index].Evidence[evidenceIndex].NetworkRef != nil {
				continue
			}
			ref := refs[min(evidenceIndex, len(refs)-1)]
			result[index].Evidence[evidenceIndex].NetworkRef = &ref
		}
	}
	return paths, result
}

func mergeLegacyAttempts(paths []model.NetworkPath, state *model.State) []model.NetworkPath {
	pathIndex, hopIndex := ensureHop(&paths, directPathID, originHopID)
	hop := &paths[pathIndex].Hops[hopIndex]
	seen := make(map[string]struct{}, len(hop.Attempts))
	for _, attempt := range hop.Attempts {
		seen[attempt.ID] = struct{}{}
	}
	appendAttempt := func(attempt model.NetworkAttempt) {
		if attempt.ID == "" {
			return
		}
		if _, exists := seen[attempt.ID]; exists {
			return
		}
		seen[attempt.ID] = struct{}{}
		hop.Attempts = append(hop.Attempts, attempt)
		if attempt.Selected {
			hop.SelectedAttemptID = attempt.ID
		}
	}
	for index, family := range state.DNS().Families {
		ref := valueRef(family.NetworkRef, directPathID, originHopID, fmt.Sprintf("attempt-dns-%03d", index+1))
		appendAttempt(model.NetworkAttempt{
			ID: ref.AttemptID, PathID: ref.PathID, HopID: ref.HopID,
			Kind: model.NetworkAttemptDNS, State: stateForDNS(family.Status),
			Network: family.Family, Duration: family.Duration,
			ErrorCode: family.ErrorCode, Error: family.Error,
		})
		hop.Timings = appendUniqueTiming(hop.Timings, model.PhaseTiming{
			NetworkRef: ref, Phase: "dns", Duration: family.Duration,
		})
	}
	for index, route := range state.Routes() {
		ref := valueRef(route.NetworkRef, directPathID, originHopID, fmt.Sprintf("attempt-route-%03d", index+1))
		appendAttempt(model.NetworkAttempt{
			ID: ref.AttemptID, PathID: ref.PathID, HopID: ref.HopID,
			Kind: model.NetworkAttemptRoute, State: route.State,
			RemoteIP: cloneIP(route.RemoteIP), LocalAddr: route.LocalIP.String(),
			InterfaceName: route.InterfaceName, InterfaceUp: route.InterfaceUp,
			MTU: route.MTU, Error: route.Error,
		})
	}
	for index, tcp := range state.TCP() {
		ref := valueRef(tcp.NetworkRef, directPathID, originHopID, fmt.Sprintf("attempt-tcp-%03d", index+1))
		appendAttempt(model.NetworkAttempt{
			ID: ref.AttemptID, PathID: ref.PathID, HopID: ref.HopID,
			Kind: model.NetworkAttemptTCP, State: tcp.State,
			RemoteIP: cloneIP(tcp.RemoteIP), LocalAddr: tcp.LocalAddr,
			Duration: tcp.Duration, Selected: tcp.Selected,
			ErrorCode: tcp.ErrorCode, Error: tcp.Error,
		})
		hop.Timings = appendUniqueTiming(hop.Timings, model.PhaseTiming{
			NetworkRef: ref, Phase: "tcp", Duration: tcp.Duration,
		})
	}
	for index, tlsAttempt := range state.TLSAttempts() {
		ref := tlsAttempt.NetworkRef
		if ref.PathID == "" {
			ref.PathID = directPathID
		}
		if ref.HopID == "" {
			ref.HopID = originHopID
		}
		if ref.AttemptID == "" {
			ref.AttemptID = fmt.Sprintf("attempt-tls-%03d", index+1)
		}
		appendAttempt(model.NetworkAttempt{
			ID: ref.AttemptID, PathID: ref.PathID, HopID: ref.HopID,
			Kind: model.NetworkAttemptTLS, State: tlsAttempt.State,
			RemoteIP: cloneIP(tlsAttempt.RemoteIP), StartedAt: tlsAttempt.StartedAt,
			FinishedAt: tlsAttempt.FinishedAt, Duration: tlsAttempt.Duration,
			Selected: tlsAttempt.Selected, ErrorCode: tlsAttempt.ErrorCode, Error: tlsAttempt.Error,
		})
		hop.Timings = appendUniqueTiming(hop.Timings, model.PhaseTiming{
			NetworkRef: ref, Phase: "tcp", Duration: tlsAttempt.TCPDuration,
		})
		hop.Timings = appendUniqueTiming(hop.Timings, model.PhaseTiming{
			NetworkRef: ref, Phase: "tls_handshake", Duration: tlsAttempt.HandshakeDuration,
		})
	}
	sort.SliceStable(hop.Attempts, func(left, right int) bool {
		return hop.Attempts[left].ID < hop.Attempts[right].ID
	})
	return paths
}

func refsForCheck(state *model.State, checkID string, paths []model.NetworkPath) []model.NetworkRef {
	var refs []model.NetworkRef
	switch checkID {
	case "dns":
		for _, result := range state.DNS().Families {
			if result.NetworkRef != nil {
				refs = append(refs, *result.NetworkRef)
			}
		}
	case "route":
		for _, result := range state.Routes() {
			if result.NetworkRef != nil {
				refs = append(refs, *result.NetworkRef)
			}
		}
	case "tcp":
		for _, result := range state.TCP() {
			if result.NetworkRef != nil {
				refs = append(refs, *result.NetworkRef)
			}
		}
	case "tls":
		for _, result := range state.TLSAttempts() {
			refs = append(refs, result.NetworkRef)
		}
	case "http":
		for _, hop := range state.HTTP().Hops {
			refs = append(refs, hop.NetworkRef)
		}
	}
	if len(refs) == 0 {
		refs = append(refs, firstPathRef(paths))
	}
	return refs
}

func ensureHop(paths *[]model.NetworkPath, pathID, hopID string) (int, int) {
	for pathIndex := range *paths {
		if (*paths)[pathIndex].ID != pathID {
			continue
		}
		for hopIndex := range (*paths)[pathIndex].Hops {
			if (*paths)[pathIndex].Hops[hopIndex].ID == hopID {
				return pathIndex, hopIndex
			}
		}
		(*paths)[pathIndex].Hops = append((*paths)[pathIndex].Hops, model.NetworkHop{
			ID: hopID, PathID: pathID, Kind: model.NetworkHopOrigin,
		})
		return pathIndex, len((*paths)[pathIndex].Hops) - 1
	}
	*paths = append(*paths, model.NetworkPath{
		ID: pathID, Role: model.NetworkPathRoleClientEffective,
		Kind: model.NetworkPathDirect,
		Hops: []model.NetworkHop{{ID: hopID, PathID: pathID, Kind: model.NetworkHopOrigin}},
	})
	return len(*paths) - 1, 0
}

func firstPathRef(paths []model.NetworkPath) model.NetworkRef {
	if len(paths) > 0 {
		if len(paths[0].Hops) > 0 {
			return model.NetworkRef{PathID: paths[0].ID, HopID: paths[0].Hops[0].ID}
		}
		return model.NetworkRef{PathID: paths[0].ID}
	}
	return model.NetworkRef{PathID: directPathID, HopID: originHopID}
}

func valueRef(value *model.NetworkRef, pathID, hopID, attemptID string) model.NetworkRef {
	result := model.NetworkRef{PathID: pathID, HopID: hopID, AttemptID: attemptID}
	if value != nil {
		result = *value
		if result.PathID == "" {
			result.PathID = pathID
		}
		if result.HopID == "" {
			result.HopID = hopID
		}
		if result.AttemptID == "" {
			result.AttemptID = attemptID
		}
	}
	return result
}

func uniqueRefs(values []model.NetworkRef) []model.NetworkRef {
	seen := make(map[model.NetworkRef]struct{}, len(values))
	result := make([]model.NetworkRef, 0, len(values))
	for _, value := range values {
		if value.PathID == "" && value.HopID == "" && value.AttemptID == "" {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func appendUniqueTiming(values []model.PhaseTiming, candidate model.PhaseTiming) []model.PhaseTiming {
	if candidate.Duration <= 0 {
		return values
	}
	for _, value := range values {
		if value.NetworkRef == candidate.NetworkRef && value.Phase == candidate.Phase {
			return values
		}
	}
	return append(values, candidate)
}

func stateForDNS(status model.DNSFamilyStatus) model.AttemptState {
	switch status {
	case model.DNSFamilyStatusCancelled:
		return model.AttemptStateCancelled
	default:
		return model.AttemptStateCompleted
	}
}

func cloneIP(value net.IP) net.IP { return append(net.IP(nil), value...) }
