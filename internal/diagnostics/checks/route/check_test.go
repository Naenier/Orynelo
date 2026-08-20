package route

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

type fakeDiscoverer struct {
	values map[string]net.IP
	errors map[string]error
}

type blockingDiscoverer struct{}

type zoneCapturingDiscoverer struct {
	zone string
}

func (*zoneCapturingDiscoverer) SourceIP(context.Context, net.IP, uint16) (net.IP, error) {
	return nil, errors.New("zone-aware discovery was not used")
}

func (discoverer *zoneCapturingDiscoverer) SourceIPInZone(
	_ context.Context,
	_ net.IP,
	zone string,
	_ uint16,
) (net.IP, error) {
	discoverer.zone = zone
	return net.ParseIP("fe80::2"), nil
}

func (blockingDiscoverer) SourceIP(
	ctx context.Context,
	_ net.IP,
	_ uint16,
) (net.IP, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestCheckSnapshotsInterfacesAndAddressesOncePerRun(t *testing.T) {
	t.Parallel()
	options := model.DefaultDiagnoseOptions("example.com:443")
	state := model.NewState(model.Target{Host: "example.com", Port: 443}, options)
	state.SetDNS(model.DNSResult{IPv4: []net.IP{
		net.ParseIP("192.0.2.1"),
		net.ParseIP("192.0.2.2"),
		net.ParseIP("192.0.2.3"),
	}})
	check := New(fakeDiscoverer{values: map[string]net.IP{
		"192.0.2.1": net.ParseIP("10.0.0.2"),
		"192.0.2.2": net.ParseIP("10.0.0.2"),
		"192.0.2.3": net.ParseIP("10.0.0.2"),
	}})
	var interfaceCalls atomic.Int32
	var addressCalls atomic.Int32
	check.Interfaces = func() ([]net.Interface, error) {
		interfaceCalls.Add(1)
		return []net.Interface{{Index: 1, Name: "eth0", Flags: net.FlagUp, MTU: 1500}}, nil
	}
	check.InterfaceAddrs = func(net.Interface) ([]net.Addr, error) {
		addressCalls.Add(1)
		return []net.Addr{&net.IPNet{
			IP:   net.ParseIP("10.0.0.2"),
			Mask: net.CIDRMask(24, 32),
		}}, nil
	}
	result := check.Run(context.Background(), state)
	if result.Status != model.StatusPassed {
		t.Fatalf("result = %#v", result)
	}
	if interfaceCalls.Load() != 1 || addressCalls.Load() != 1 {
		t.Fatalf("enumeration calls = interfaces %d, addresses %d", interfaceCalls.Load(), addressCalls.Load())
	}

	_ = check.Run(context.Background(), state)
	if interfaceCalls.Load() != 2 || addressCalls.Load() != 2 {
		t.Fatalf("a new run did not refresh the snapshot: interfaces %d, addresses %d", interfaceCalls.Load(), addressCalls.Load())
	}
}

func TestCheckPreservesLinkLocalConnectIPZoneForRouteDiscovery(t *testing.T) {
	t.Parallel()
	options := model.DefaultDiagnoseOptions("tls://[fe80::1%25eth0]:443")
	options.IPVersion = model.IPVersion6
	options.ConnectIP = "fe80::1%eth0"
	state := model.NewState(model.Target{
		Host: "fe80::1", Port: 443, Zone: "eth0",
	}, options)
	discoverer := &zoneCapturingDiscoverer{}
	check := New(discoverer)
	check.Interfaces = func() ([]net.Interface, error) { return nil, nil }
	result := check.Run(context.Background(), state)
	if discoverer.zone != "eth0" || result.Status != model.StatusWarning {
		t.Fatalf("zone=%q result=%#v", discoverer.zone, result)
	}
}

func TestCheckReportsPartialInterfaceEnumeration(t *testing.T) {
	t.Parallel()
	options := model.DefaultDiagnoseOptions("example.com:443")
	state := model.NewState(model.Target{Host: "example.com", Port: 443}, options)
	state.SetDNS(model.DNSResult{IPv4: []net.IP{net.ParseIP("192.0.2.1")}})
	check := New(fakeDiscoverer{values: map[string]net.IP{
		"192.0.2.1": net.ParseIP("10.0.0.2"),
	}})
	check.Interfaces = func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 1, Name: "broken0"},
			{Index: 2, Name: "eth0", Flags: net.FlagUp, MTU: 1400},
		}, nil
	}
	check.InterfaceAddrs = func(value net.Interface) ([]net.Addr, error) {
		if value.Name == "broken0" {
			return nil, errors.New("address enumeration failed")
		}
		return []net.Addr{&net.IPNet{
			IP:   net.ParseIP("10.0.0.2"),
			Mask: net.CIDRMask(24, 32),
		}}, nil
	}
	result := check.Run(context.Background(), state)
	if result.Status != model.StatusWarning || result.ErrorCode != ErrorDiscoveryFailed {
		t.Fatalf("result = %#v", result)
	}
	if got := state.Routes()[0].InterfaceName; got != "eth0" {
		t.Fatalf("matched interface = %q", got)
	}
	paths := state.NetworkPaths()
	if len(paths) != 1 || len(paths[0].Hops) != 1 || len(paths[0].Hops[0].Attempts) != 1 {
		t.Fatalf("network paths = %#v", paths)
	}
	attempt := paths[0].Hops[0].Attempts[0]
	if attempt.InterfaceName != "eth0" || !attempt.InterfaceUp || attempt.MTU != 1400 ||
		attempt.LocalAddr != "10.0.0.2" {
		t.Fatalf("route path attempt = %#v", attempt)
	}
	partial := evidenceWithCode(result.Evidence, ErrorInterfacePartial)
	if partial == nil || partial.Details["errorCount"] != "1" ||
		partial.Details["errors"] == "" {
		t.Fatalf("partial interface evidence = %#v", partial)
	}
}

func TestCheckAppliesAddressLimitAndCorrelatesAttempts(t *testing.T) {
	t.Parallel()
	options := model.DefaultDiagnoseOptions("example.com:443")
	options.ProbeMode = model.ProbeModeAddressMatrix
	options.AddressLimit = 2
	state := model.NewState(model.Target{Host: "example.com", Port: 443}, options)
	state.SetDNS(model.DNSResult{IPv4: []net.IP{
		net.ParseIP("192.0.2.1"),
		net.ParseIP("192.0.2.2"),
		net.ParseIP("192.0.2.3"),
	}})
	state.SetNetworkPaths([]model.NetworkPath{{
		ID:   directPathID,
		Role: model.NetworkPathRoleAddressMatrix,
		Kind: model.NetworkPathDirect,
		Hops: []model.NetworkHop{{
			ID:     originHopID,
			PathID: directPathID,
			Kind:   model.NetworkHopOrigin,
			Attempts: []model.NetworkAttempt{{
				ID:     "attempt-dns-a",
				PathID: directPathID,
				HopID:  originHopID,
				Kind:   model.NetworkAttemptDNS,
			}},
		}},
	}})
	check := New(fakeDiscoverer{values: map[string]net.IP{
		"192.0.2.1": net.ParseIP("10.0.0.2"),
		"192.0.2.2": net.ParseIP("10.0.0.2"),
	}})
	check.Interfaces = func() ([]net.Interface, error) { return nil, nil }
	result := check.Run(context.Background(), state)
	if len(state.Routes()) != 2 || evidenceWithCode(result.Evidence, "ADDRESS_SKIPPED_BY_LIMIT") == nil {
		t.Fatalf("bounded result = %#v, routes = %#v", result, state.Routes())
	}
	if len(result.NetworkRefs) != 2 || result.NetworkRefs[0].AttemptID != "attempt-route-000" ||
		result.NetworkRefs[1].AttemptID != "attempt-route-001" {
		t.Fatalf("network refs = %#v", result.NetworkRefs)
	}
	paths := state.NetworkPaths()
	if len(paths) != 1 || len(paths[0].Hops) != 1 || len(paths[0].Hops[0].Attempts) != 3 {
		t.Fatalf("network path = %#v", paths)
	}
	if paths[0].Hops[0].Attempts[0].Kind != model.NetworkAttemptDNS ||
		paths[0].Hops[0].Attempts[1].Kind != model.NetworkAttemptRoute {
		t.Fatalf("attempt correlation = %#v", paths[0].Hops[0].Attempts)
	}
}

func TestRouteAttemptBudgetIsIndependentPerMatrixSlot(t *testing.T) {
	t.Parallel()
	options := model.DefaultDiagnoseOptions("example.com:443")
	options.ProbeMode = model.ProbeModeAddressMatrix
	options.AddressLimit = 4
	options.AddressMatrixBudget = 80 * time.Millisecond
	options.CheckTimeout = time.Second
	if got := routeAttemptBudget(options); got != 20*time.Millisecond {
		t.Fatalf("routeAttemptBudget() = %s, want 20ms", got)
	}
	options.CheckTimeout = 5 * time.Millisecond
	if got := routeAttemptBudget(options); got != 5*time.Millisecond {
		t.Fatalf("routeAttemptBudget() cap = %s, want 5ms", got)
	}
}

func TestMatrixRouteAttemptTimeoutIsRecordedWithoutCancellingRun(t *testing.T) {
	t.Parallel()
	options := model.DefaultDiagnoseOptions("example.com:443")
	options.ProbeMode = model.ProbeModeAddressMatrix
	options.AddressLimit = 2
	options.AddressMatrixBudget = 10 * time.Millisecond
	options.CheckTimeout = time.Second
	state := model.NewState(model.Target{Host: "example.com", Port: 443}, options)
	state.SetDNS(model.DNSResult{IPv4: []net.IP{net.ParseIP("192.0.2.1")}})
	check := New(blockingDiscoverer{})
	check.Interfaces = func() ([]net.Interface, error) { return nil, nil }
	result := check.Run(context.Background(), state)
	if result.Status != model.StatusWarning {
		t.Fatalf("result = %#v", result)
	}
	paths := state.NetworkPaths()
	if len(paths) != 1 || len(paths[0].Hops) != 1 || len(paths[0].Hops[0].Attempts) != 1 {
		t.Fatalf("paths = %#v", paths)
	}
	attempt := paths[0].Hops[0].Attempts[0]
	if attempt.State != model.AttemptStateCompleted || attempt.ErrorCode != ErrorAttemptTimeout {
		t.Fatalf("attempt = %#v", attempt)
	}
}

func evidenceWithCode(values []model.Evidence, code string) *model.Evidence {
	for index := range values {
		if values[index].Code == code {
			return &values[index]
		}
	}
	return nil
}

func (f fakeDiscoverer) SourceIP(_ context.Context, remote net.IP, _ uint16) (net.IP, error) {
	return f.values[remote.String()], f.errors[remote.String()]
}

type stagedDiscoverer struct {
	blockRemote string
	started     chan struct{}
}

func (d stagedDiscoverer) SourceIP(ctx context.Context, remote net.IP, _ uint16) (net.IP, error) {
	if remote.String() == d.blockRemote {
		close(d.started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return net.ParseIP("10.0.0.2"), nil
}

func TestCheckPreservesSourceDiscoveryWhenInterfaceMetadataIsUnavailable(t *testing.T) {
	t.Parallel()
	options := model.DefaultDiagnoseOptions("example.com:443")
	state := model.NewState(model.Target{Host: "example.com", Port: 443}, options)
	state.SetDNS(model.DNSResult{IPv4: []net.IP{net.ParseIP("192.0.2.1")}})
	check := New(fakeDiscoverer{values: map[string]net.IP{
		"192.0.2.1": net.ParseIP("10.0.0.2"),
	}})
	check.Interfaces = func() ([]net.Interface, error) { return nil, nil }
	result := check.Run(context.Background(), state)
	if result.Status != model.StatusWarning || result.ErrorCode != ErrorDiscoveryFailed {
		t.Fatalf("result = %#v", result)
	}
	if got := state.Routes()[0].LocalIP.String(); got != "10.0.0.2" {
		t.Fatalf("local source = %s", got)
	}
	if got := state.Routes()[0].State; got != model.AttemptStateCompleted {
		t.Fatalf("route state = %q", got)
	}
	if result.Evidence[0].Details["localIp"] != "10.0.0.2" {
		t.Fatalf("evidence = %#v", result.Evidence)
	}
}

func TestCheckMixedFamiliesAndErrors(t *testing.T) {
	t.Parallel()
	options := model.DefaultDiagnoseOptions("example.com:443")
	state := model.NewState(model.Target{Host: "example.com", Port: 443}, options)
	state.SetDNS(model.DNSResult{
		IPv4: []net.IP{net.ParseIP("192.0.2.1")},
		IPv6: []net.IP{net.ParseIP("2001:db8::1")},
	})
	check := New(fakeDiscoverer{
		values: map[string]net.IP{"192.0.2.1": net.ParseIP("10.0.0.2")},
		errors: map[string]error{"2001:db8::1": errors.New("network unreachable")},
	})
	check.Interfaces = func() ([]net.Interface, error) { return nil, nil }
	result := check.Run(context.Background(), state)
	if result.Status != model.StatusWarning || len(result.Evidence) != 2 {
		t.Fatalf("result = %#v", result)
	}
	if result.Evidence[0].Details["family"] != "ipv4" ||
		result.Evidence[1].Details["family"] != "ipv6" {
		t.Fatalf("evidence order = %#v", result.Evidence)
	}
}

func TestCheckWithoutAddressesIsSkipped(t *testing.T) {
	t.Parallel()
	state := model.NewState(
		model.Target{Host: "example.com", Port: 443},
		model.DefaultDiagnoseOptions("example.com:443"),
	)
	result := New(fakeDiscoverer{}).Run(context.Background(), state)
	if result.Status != model.StatusSkipped {
		t.Fatalf("result = %#v", result)
	}
}

func TestCheckCancellationDoesNotCreateUnstartedRoute(t *testing.T) {
	t.Parallel()
	state := model.NewState(
		model.Target{Host: "example.com", Port: 443},
		model.DefaultDiagnoseOptions("example.com:443"),
	)
	state.SetDNS(model.DNSResult{IPv4: []net.IP{net.ParseIP("192.0.2.1")}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := New(fakeDiscoverer{}).Run(ctx, state)
	if result.Status != model.StatusCancelled || result.ErrorCode != ErrorCancelled {
		t.Fatalf("result = %#v", result)
	}
	if len(result.Evidence) != 0 || len(state.Routes()) != 0 {
		t.Fatalf("not-started routes leaked into result: evidence=%#v state=%#v", result.Evidence, state.Routes())
	}
}

func TestCheckCancellationPreservesOnlyStartedRoutes(t *testing.T) {
	t.Parallel()
	options := model.DefaultDiagnoseOptions("example.com:443")
	options.MaxConcurrency = 1
	state := model.NewState(model.Target{Host: "example.com", Port: 443}, options)
	state.SetDNS(model.DNSResult{IPv4: []net.IP{
		net.ParseIP("192.0.2.1"),
		net.ParseIP("192.0.2.2"),
		net.ParseIP("192.0.2.3"),
	}})
	started := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-started
		cancel()
	}()
	check := New(stagedDiscoverer{
		blockRemote: "192.0.2.2",
		started:     started,
	})
	check.Interfaces = func() ([]net.Interface, error) { return nil, nil }

	result := check.Run(ctx, state)
	if result.Status != model.StatusCancelled || result.ErrorCode != ErrorCancelled {
		t.Fatalf("result = %#v", result)
	}
	routes := state.Routes()
	if len(routes) != 2 || len(result.Evidence) != 3 ||
		evidenceWithCode(result.Evidence, "ADDRESS_SKIPPED_BY_LIMIT") == nil {
		t.Fatalf("partial route result did not retain only started attempts: state=%#v evidence=%#v", routes, result.Evidence)
	}
	if routes[0].RemoteIP.String() != "192.0.2.1" || routes[0].LocalIP.String() != "10.0.0.2" {
		t.Fatalf("completed route was not preserved: %#v", routes)
	}
	if routes[0].State != model.AttemptStateCompleted {
		t.Fatalf("completed route state = %q", routes[0].State)
	}
	if routes[1].RemoteIP.String() != "192.0.2.2" || routes[1].Error == "" {
		t.Fatalf("cancelled started route is incomplete: %#v", routes)
	}
	if routes[1].State != model.AttemptStateCancelled {
		t.Fatalf("cancelled route state = %q", routes[1].State)
	}
	for _, evidence := range result.Evidence {
		if evidence.Code == "ADDRESS_SKIPPED_BY_LIMIT" {
			continue
		}
		if evidence.Details["remoteIp"] == "<nil>" ||
			evidence.Details["family"] == "ipv6" ||
			evidence.Details["state"] == "" ||
			evidence.Message == "" {
			t.Fatalf("false cancellation evidence = %#v", evidence)
		}
	}
}
