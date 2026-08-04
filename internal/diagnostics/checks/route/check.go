// Package route discovers the local source address and interface selected for
// each remote address without requiring raw sockets or elevated privileges.
package route

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

const (
	ErrorDiscoveryFailed = "ROUTE_DISCOVERY_FAILED"
	ErrorCancelled       = "ROUTE_CANCELLED"
)

// SourceDiscoverer determines the local source IP for a remote endpoint.
type SourceDiscoverer interface {
	SourceIP(ctx context.Context, remote net.IP, port uint16) (net.IP, error)
}

type udpDiscoverer struct{}

// SourceIP discovers the local source address selected for a remote endpoint.
func (udpDiscoverer) SourceIP(ctx context.Context, remote net.IP, port uint16) (net.IP, error) {
	connection, err := (&net.Dialer{}).DialContext(
		ctx,
		"udp",
		net.JoinHostPort(remote.String(), strconv.Itoa(int(port))),
	)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	address, ok := connection.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("unexpected local address type %T", connection.LocalAddr())
	}
	return append(net.IP(nil), address.IP...), nil
}

// Check performs cross-platform source and interface discovery.
type Check struct {
	Discoverer SourceDiscoverer
	Interfaces func() ([]net.Interface, error)
}

type routeSlot struct {
	result  model.RouteInfo
	started bool
}

// New constructs a route check using UDP route selection and net.Interfaces.
func New(discoverer SourceDiscoverer) *Check {
	if discoverer == nil {
		discoverer = udpDiscoverer{}
	}
	return &Check{Discoverer: discoverer, Interfaces: net.Interfaces}
}

// ID returns the stable diagnostic identifier.
func (*Check) ID() string { return "route" }

// Name returns the human-readable check name.
func (*Check) Name() string { return "Route and source address" }

// Run discovers source addresses and interface metadata for each remote address.
func (c *Check) Run(ctx context.Context, state *model.State) model.CheckResult {
	dnsResult := state.DNS()
	addresses := usableAddresses(dnsResult.IPv4, dnsResult.IPv6)
	if len(addresses) == 0 {
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusSkipped,
			Summary: "Route discovery was skipped because no remote addresses are available.",
		}
	}

	slots := make([]routeSlot, len(addresses))
	for index, remote := range addresses {
		slots[index].result = model.RouteInfo{
			RemoteIP: append(net.IP(nil), remote...),
			Family:   family(remote),
			State:    model.AttemptStateQueued,
		}
	}
	jobs := make(chan int)
	workers := state.Options.MaxConcurrency
	if workers < 1 {
		workers = 1
	}
	if workers > len(addresses) {
		workers = len(addresses)
	}
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			for index := range jobs {
				remote := addresses[index]
				result := slots[index].result
				result.State = model.AttemptStateRunning
				slots[index] = routeSlot{result: result, started: true}
				local, err := c.Discoverer.SourceIP(ctx, remote, state.Target.Port)
				if err != nil {
					result.Error = err.Error()
					result.State = model.AttemptStateCompleted
					if ctx.Err() != nil {
						result.State = model.AttemptStateCancelled
					}
					slots[index] = routeSlot{result: result, started: true}
					continue
				}
				result.LocalIP = local
				iface, err := c.interfaceFor(local)
				if err != nil {
					result.Error = err.Error()
				} else if iface != nil {
					result.InterfaceName = iface.Name
					result.InterfaceUp = iface.Flags&net.FlagUp != 0
					result.MTU = iface.MTU
				}
				result.State = model.AttemptStateCompleted
				slots[index] = routeSlot{result: result, started: true}
			}
		}()
	}
	cancelled := false
	for index := range addresses {
		if ctx.Err() != nil {
			cancelled = true
			break
		}
		select {
		case jobs <- index:
		case <-ctx.Done():
			cancelled = true
		}
		if cancelled {
			break
		}
	}
	close(jobs)
	wait.Wait()
	if ctx.Err() != nil {
		cancelled = true
	}
	results := startedRoutes(slots)
	state.SetRoutes(results)
	return c.result(results, len(addresses), cancelled)
}

func (c *Check) result(results []model.RouteInfo, total int, cancelled bool) model.CheckResult {
	sources := 0
	complete := 0
	completedAttempts := 0
	evidence := make([]model.Evidence, 0, len(results))
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
			ID:      fmt.Sprintf("route.%d", index),
			Code:    "ROUTE_SOURCE",
			Message: message,
			Details: details,
		})
	}
	if cancelled {
		neverStarted := total - len(results)
		if neverStarted < 0 {
			neverStarted = 0
		}
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusCancelled,
			Summary:   fmt.Sprintf("Route discovery was cancelled after %d of %d started attempt(s) completed; %d of %d address(es) were never started.", completedAttempts, len(results), neverStarted, total),
			Evidence:  evidence,
			ErrorCode: ErrorCancelled,
		}
	}

	status := model.StatusPassed
	summary := fmt.Sprintf("Discovered a source address for %d of %d remote address(es).", sources, len(results))
	errorCode := ""
	if complete < len(results) {
		status = model.StatusWarning
		errorCode = ErrorDiscoveryFailed
	}
	if sources == 0 {
		summary = "No local source address could be discovered for the resolved addresses."
	}
	return model.CheckResult{
		ID:        c.ID(),
		Name:      c.Name(),
		Status:    status,
		Summary:   summary,
		Evidence:  evidence,
		ErrorCode: errorCode,
	}
}

func startedRoutes(slots []routeSlot) []model.RouteInfo {
	results := make([]model.RouteInfo, 0, len(slots))
	for _, slot := range slots {
		if slot.started {
			results = append(results, slot.result)
		}
	}
	return results
}

func usableAddresses(groups ...[]net.IP) []net.IP {
	var addresses []net.IP
	for _, group := range groups {
		for _, address := range group {
			if address == nil || address.To16() == nil {
				continue
			}
			addresses = append(addresses, append(net.IP(nil), address...))
		}
	}
	return addresses
}

func (c *Check) interfaceFor(local net.IP) (*net.Interface, error) {
	interfaces := c.Interfaces
	if interfaces == nil {
		interfaces = net.Interfaces
	}
	all, err := interfaces()
	if err != nil {
		return nil, err
	}
	for index := range all {
		addresses, err := all[index].Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			var candidate net.IP
			switch value := address.(type) {
			case *net.IPNet:
				candidate = value.IP
			case *net.IPAddr:
				candidate = value.IP
			default:
				ip, _, parseErr := net.ParseCIDR(address.String())
				if parseErr == nil {
					candidate = ip
				}
			}
			if candidate != nil && candidate.Equal(local) {
				copy := all[index]
				return &copy, nil
			}
		}
	}
	return nil, fmt.Errorf("no interface owns local address %s", local)
}

func family(ip net.IP) string {
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}
