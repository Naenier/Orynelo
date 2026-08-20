// Package route discovers the local source address and interface selected for
// each bounded remote candidate without raw sockets or elevated privileges.
package route

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	dnscheck "github.com/Naenier/orynelo/internal/diagnostics/checks/dns"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

const (
	ErrorDiscoveryFailed  = "ROUTE_DISCOVERY_FAILED"
	ErrorAttemptTimeout   = "ROUTE_ATTEMPT_TIMEOUT"
	ErrorInterfacePartial = "ROUTE_INTERFACE_PARTIAL"
	ErrorCancelled        = "ROUTE_CANCELLED"

	directPathID = "path-direct"
	originHopID  = "hop-origin"
)

// SourceDiscoverer determines the local source IP for a remote endpoint.
type SourceDiscoverer interface {
	SourceIP(ctx context.Context, remote net.IP, port uint16) (net.IP, error)
}

type zonedSourceDiscoverer interface {
	SourceIPInZone(ctx context.Context, remote net.IP, zone string, port uint16) (net.IP, error)
}

type udpDiscoverer struct{}

// SourceIP discovers the local source address selected for a remote endpoint.
func (udpDiscoverer) SourceIP(ctx context.Context, remote net.IP, port uint16) (net.IP, error) {
	return udpDiscoverer{}.SourceIPInZone(ctx, remote, "", port)
}

func (udpDiscoverer) SourceIPInZone(
	ctx context.Context,
	remote net.IP,
	zone string,
	port uint16,
) (net.IP, error) {
	host := remote.String()
	if zone != "" {
		host += "%" + zone
	}
	connection, err := (&net.Dialer{}).DialContext(
		ctx,
		"udp",
		net.JoinHostPort(host, strconv.Itoa(int(port))),
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

// Check performs cross-platform source and interface discovery. Interfaces
// and their addresses are snapshotted exactly once per Run.
type Check struct {
	Discoverer     SourceDiscoverer
	Interfaces     func() ([]net.Interface, error)
	InterfaceAddrs func(net.Interface) ([]net.Addr, error)
	Now            func() time.Time
}

type routeSlot struct {
	result  model.RouteInfo
	attempt model.NetworkAttempt
	started bool
}

type interfaceEntry struct {
	interfaceInfo net.Interface
	addresses     []net.IP
}

type interfaceSnapshot struct {
	entries       []interfaceEntry
	errors        []string
	omittedErrors int
}

// New constructs a route check using UDP route selection and net.Interfaces.
func New(discoverer SourceDiscoverer) *Check {
	if discoverer == nil {
		discoverer = udpDiscoverer{}
	}
	return &Check{
		Discoverer: discoverer,
		Interfaces: net.Interfaces,
		InterfaceAddrs: func(value net.Interface) ([]net.Addr, error) {
			return value.Addrs()
		},
		Now: time.Now,
	}
}

// ID returns the stable diagnostic identifier.
func (*Check) ID() string { return "route" }

// Name returns the human-readable check name.
func (*Check) Name() string { return "Route and source address" }

// Run discovers source addresses and interface metadata for the bounded
// candidates selected by the shared DNS address policy.
func (c *Check) Run(ctx context.Context, state *model.State) model.CheckResult {
	selection := dnscheck.SelectAddresses(state.DNS(), state.Options)
	addresses := selection.Addresses
	if len(addresses) == 0 {
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusSkipped,
			Summary: "Route discovery was skipped because no selected remote addresses are available.",
		}
	}
	if ctx.Err() != nil {
		return c.result(nil, len(addresses), true, interfaceSnapshot{}, selection, state.Options)
	}

	interfaces := c.snapshotInterfaces()
	slots := make([]routeSlot, len(addresses))
	for index, remote := range addresses {
		ref := routeNetworkRef(index)
		slots[index] = routeSlot{
			result: model.RouteInfo{
				NetworkRef: ref,
				RemoteIP:   append(net.IP(nil), remote...),
				Family:     family(remote),
				State:      model.AttemptStateQueued,
			},
			attempt: model.NetworkAttempt{
				ID:       ref.AttemptID,
				PathID:   ref.PathID,
				HopID:    ref.HopID,
				Kind:     model.NetworkAttemptRoute,
				State:    model.AttemptStateQueued,
				Network:  network(remote),
				RemoteIP: append(net.IP(nil), remote...),
			},
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
	attemptBudget := routeAttemptBudget(state.Options)
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			for index := range jobs {
				c.runAttempt(ctx, state, interfaces, slots, index, attemptBudget)
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
	results, attempts := startedRoutes(slots)
	state.SetRoutes(results)
	recordRouteAttempts(state, attempts)
	return c.result(results, len(addresses), cancelled, interfaces, selection, state.Options)
}

func (c *Check) runAttempt(
	parent context.Context,
	state *model.State,
	interfaces interfaceSnapshot,
	slots []routeSlot,
	index int,
	budget time.Duration,
) {
	remote := slots[index].result.RemoteIP
	result := slots[index].result
	attempt := slots[index].attempt
	result.State = model.AttemptStateRunning
	attempt.State = model.AttemptStateRunning
	attempt.StartedAt = c.now()
	slots[index] = routeSlot{result: result, attempt: attempt, started: true}

	attemptContext := parent
	cancel := func() {}
	if budget > 0 {
		attemptContext, cancel = context.WithTimeout(parent, budget)
	}
	defer cancel()
	var local net.IP
	var err error
	zone := routeZone(state, remote)
	if discoverer, ok := c.Discoverer.(zonedSourceDiscoverer); ok && zone != "" {
		local, err = discoverer.SourceIPInZone(attemptContext, remote, zone, state.Target.Port)
	} else {
		local, err = c.Discoverer.SourceIP(attemptContext, remote, state.Target.Port)
	}
	attempt.FinishedAt = c.now()
	attempt.Duration = attempt.FinishedAt.Sub(attempt.StartedAt)
	if err != nil {
		result.Error = err.Error()
		attempt.Error = err.Error()
		attempt.ErrorCode = ErrorDiscoveryFailed
		result.State = model.AttemptStateCompleted
		attempt.State = model.AttemptStateCompleted
		if parent.Err() != nil {
			result.State = model.AttemptStateCancelled
			attempt.State = model.AttemptStateCancelled
			attempt.ErrorCode = ErrorCancelled
		} else if errors.Is(attemptContext.Err(), context.DeadlineExceeded) {
			attempt.ErrorCode = ErrorAttemptTimeout
		}
		slots[index] = routeSlot{result: result, attempt: attempt, started: true}
		return
	}

	result.LocalIP = append(net.IP(nil), local...)
	attempt.LocalAddr = local.String()
	iface, interfaceErr := interfaceFor(interfaces, local)
	if interfaceErr != nil {
		result.Error = interfaceErr.Error()
		attempt.Error = interfaceErr.Error()
		attempt.ErrorCode = ErrorDiscoveryFailed
	} else if iface != nil {
		result.InterfaceName = iface.Name
		result.InterfaceUp = iface.Flags&net.FlagUp != 0
		result.MTU = iface.MTU
		attempt.InterfaceName = result.InterfaceName
		attempt.InterfaceUp = result.InterfaceUp
		attempt.MTU = result.MTU
	}
	result.State = model.AttemptStateCompleted
	attempt.State = model.AttemptStateCompleted
	slots[index] = routeSlot{result: result, attempt: attempt, started: true}
}

func routeZone(state *model.State, remote net.IP) string {
	if state == nil || remote == nil {
		return ""
	}
	if configured, err := netip.ParseAddr(state.Options.ConnectIP); err == nil &&
		configured.Zone() != "" && remote.Equal(net.IP(configured.AsSlice())) {
		return configured.Zone()
	}
	if state.Target.Zone != "" && remote.Equal(net.ParseIP(state.Target.Host)) {
		return state.Target.Zone
	}
	return ""
}

func (c *Check) snapshotInterfaces() interfaceSnapshot {
	interfaces := c.Interfaces
	if interfaces == nil {
		interfaces = net.Interfaces
	}
	all, err := interfaces()
	if err != nil {
		return interfaceSnapshot{errors: []string{boundedError(err.Error())}}
	}
	addrs := c.InterfaceAddrs
	if addrs == nil {
		addrs = func(value net.Interface) ([]net.Addr, error) { return value.Addrs() }
	}
	snapshot := interfaceSnapshot{entries: make([]interfaceEntry, 0, len(all))}
	for _, iface := range all {
		addresses, addressErr := addrs(iface)
		if addressErr != nil {
			if len(snapshot.errors) < 16 {
				snapshot.errors = append(
					snapshot.errors,
					boundedError(fmt.Sprintf("interface %q: %v", iface.Name, addressErr)),
				)
			} else {
				snapshot.omittedErrors++
			}
			continue
		}
		entry := interfaceEntry{interfaceInfo: iface}
		for _, address := range addresses {
			if candidate := addressIP(address); candidate != nil {
				entry.addresses = append(entry.addresses, candidate)
			}
		}
		snapshot.entries = append(snapshot.entries, entry)
	}
	return snapshot
}

func boundedError(value string) string {
	const maximumRunes = 512
	runes := []rune(value)
	if len(runes) <= maximumRunes {
		return value
	}
	return string(runes[:maximumRunes]) + "…"
}

func interfaceFor(snapshot interfaceSnapshot, local net.IP) (*net.Interface, error) {
	for _, entry := range snapshot.entries {
		for _, candidate := range entry.addresses {
			if candidate.Equal(local) {
				copy := entry.interfaceInfo
				return &copy, nil
			}
		}
	}
	if len(snapshot.errors) > 0 {
		return nil, fmt.Errorf(
			"no enumerated interface owns local address %s; interface metadata was incomplete",
			local,
		)
	}
	return nil, fmt.Errorf("no interface owns local address %s", local)
}

func addressIP(address net.Addr) net.IP {
	switch value := address.(type) {
	case *net.IPNet:
		return append(net.IP(nil), value.IP...)
	case *net.IPAddr:
		return append(net.IP(nil), value.IP...)
	case nil:
		return nil
	default:
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil {
			return ip
		}
		return net.ParseIP(strings.TrimSpace(address.String()))
	}
}

func startedRoutes(slots []routeSlot) ([]model.RouteInfo, []model.NetworkAttempt) {
	results := make([]model.RouteInfo, 0, len(slots))
	attempts := make([]model.NetworkAttempt, 0, len(slots))
	for _, slot := range slots {
		if slot.started {
			results = append(results, slot.result)
			attempts = append(attempts, slot.attempt)
		}
	}
	return results, attempts
}

func routeAttemptBudget(options model.DiagnoseOptions) time.Duration {
	if options.ProbeMode != model.ProbeModeAddressMatrix || options.AddressMatrixBudget <= 0 {
		return options.CheckTimeout
	}
	limit := options.AddressLimit
	if limit <= 0 {
		limit = model.DefaultDiagnoseOptions("").AddressLimit
	}
	budget := options.AddressMatrixBudget / time.Duration(limit)
	if options.CheckTimeout > 0 && budget > options.CheckTimeout {
		budget = options.CheckTimeout
	}
	if budget <= 0 {
		return time.Nanosecond
	}
	return budget
}

func routeNetworkRef(index int) *model.NetworkRef {
	return &model.NetworkRef{
		PathID:    directPathID,
		HopID:     originHopID,
		AttemptID: fmt.Sprintf("attempt-route-%03d", index),
	}
}

func family(ip net.IP) string {
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

func network(ip net.IP) string {
	if ip.To4() != nil {
		return "udp4"
	}
	return "udp6"
}

func (c *Check) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
