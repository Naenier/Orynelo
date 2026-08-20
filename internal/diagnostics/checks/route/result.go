package route

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Naenier/orynelo/internal/diagnostics/checks/dns"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

func (c *Check) result(
	results []model.RouteInfo,
	total int,
	cancelled bool,
	interfaces interfaceSnapshot,
	selection dns.AddressSelection,
	options model.DiagnoseOptions,
) model.CheckResult {
	sources := 0
	complete := 0
	completedAttempts := 0
	evidence := make([]model.Evidence, 0, len(results)+2)
	networkRefs := make([]model.NetworkRef, 0, len(results))
	for index, result := range results {
		if result.RemoteIP == nil ||
			result.State == model.AttemptStateQueued ||
			result.State == model.AttemptStateSkipped {
			continue
		}
		details := map[string]string{
			"remoteIp": result.RemoteIP.String(),
			"family":   result.Family,
			"state":    string(result.State),
		}
		message := "Route source discovery failed."
		if result.LocalIP != nil {
			sources++
			message = "The operating system selected a local source address."
			details["localIp"] = result.LocalIP.String()
			details["interface"] = result.InterfaceName
			details["interfaceUp"] = strconv.FormatBool(result.InterfaceUp)
			details["mtu"] = strconv.Itoa(result.MTU)
			if result.Error == "" {
				complete++
			} else {
				message = "A local source address was selected, but interface metadata is incomplete."
				details["interfaceError"] = result.Error
			}
		} else if result.Error != "" {
			details["error"] = result.Error
		}
		switch result.State {
		case model.AttemptStateCancelled:
			message = "Route source discovery was cancelled after it started."
		case model.AttemptStateCompleted:
			completedAttempts++
		}
		evidence = append(evidence, model.Evidence{
			ID:         fmt.Sprintf("route.%d", index),
			NetworkRef: cloneNetworkRef(result.NetworkRef),
			Code:       "ROUTE_SOURCE",
			Message:    message,
			Details:    details,
		})
		if result.NetworkRef != nil {
			networkRefs = append(networkRefs, *result.NetworkRef)
		}
	}
	if len(interfaces.errors) > 0 {
		totalErrors := len(interfaces.errors) + interfaces.omittedErrors
		details := map[string]string{
			"errorCount": strconv.Itoa(totalErrors),
			"errors":     strings.Join(interfaces.errors, "; "),
		}
		if interfaces.omittedErrors > 0 {
			details["errorsOmitted"] = strconv.Itoa(interfaces.omittedErrors)
		}
		evidence = append(evidence, model.Evidence{
			ID:         "route.interfaces",
			NetworkRef: &model.NetworkRef{PathID: directPathID, HopID: originHopID},
			Code:       ErrorInterfacePartial,
			Message:    "Some local interface metadata could not be enumerated.",
			Details:    details,
		})
	}
	if selection.Skipped > 0 {
		limit := len(selection.Addresses)
		evidence = append(evidence, model.Evidence{
			ID:         "route.address_limit",
			NetworkRef: &model.NetworkRef{PathID: directPathID, HopID: originHopID},
			Code:       "ADDRESS_SKIPPED_BY_LIMIT",
			Message:    "Route probes omitted resolved backends beyond the configured address bound.",
			Details: map[string]string{
				"probeMode": string(options.ProbeMode),
				"limit":     strconv.Itoa(limit),
				"selected":  strconv.Itoa(len(selection.Addresses)),
				"skipped":   strconv.Itoa(selection.Skipped),
				"total":     strconv.Itoa(selection.Total),
			},
		})
	}
	if cancelled {
		neverStarted := total - len(results)
		if neverStarted < 0 {
			neverStarted = 0
		}
		return model.CheckResult{
			ID:          c.ID(),
			Name:        c.Name(),
			Status:      model.StatusCancelled,
			Summary:     fmt.Sprintf("Route discovery was cancelled after %d of %d started attempt(s) completed; %d of %d selected address(es) were never started.", completedAttempts, len(results), neverStarted, total),
			NetworkRefs: networkRefs,
			Evidence:    evidence,
			ErrorCode:   ErrorCancelled,
		}
	}

	status := model.StatusPassed
	summary := fmt.Sprintf("Discovered a source address for %d of %d selected remote address(es).", sources, len(results))
	errorCode := ""
	if complete < len(results) || len(interfaces.errors) > 0 {
		status = model.StatusWarning
		errorCode = ErrorDiscoveryFailed
	}
	if sources == 0 {
		summary = "No local source address could be discovered for the selected addresses."
	}
	return model.CheckResult{
		ID:          c.ID(),
		Name:        c.Name(),
		Status:      status,
		Summary:     summary,
		NetworkRefs: networkRefs,
		Evidence:    evidence,
		ErrorCode:   errorCode,
	}
}

func recordRouteAttempts(state *model.State, attempts []model.NetworkAttempt) {
	paths := state.NetworkPaths()
	pathIndex := -1
	for index := range paths {
		if paths[index].ID == directPathID {
			pathIndex = index
			break
		}
	}
	if pathIndex < 0 {
		role := model.NetworkPathRoleClientEffective
		if state.Options.ProbeMode == model.ProbeModeAddressMatrix {
			role = model.NetworkPathRoleAddressMatrix
		}
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
	existing := make(
		[]model.NetworkAttempt,
		0,
		len(paths[pathIndex].Hops[hopIndex].Attempts),
	)
	for _, attempt := range paths[pathIndex].Hops[hopIndex].Attempts {
		if attempt.Kind != model.NetworkAttemptRoute {
			existing = append(existing, attempt)
		}
	}
	paths[pathIndex].Hops[hopIndex].Attempts = append(existing, attempts...)
	state.SetNetworkPaths(paths)
}

func cloneNetworkRef(ref *model.NetworkRef) *model.NetworkRef {
	if ref == nil {
		return nil
	}
	copy := *ref
	return &copy
}
