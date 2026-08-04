package route

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

type fakeDiscoverer struct {
	values map[string]net.IP
	errors map[string]error
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
	if len(routes) != 2 || len(result.Evidence) != 2 {
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
		if evidence.Details["remoteIp"] == "<nil>" ||
			evidence.Details["family"] == "ipv6" ||
			evidence.Details["state"] == "" ||
			evidence.Message == "" {
			t.Fatalf("false cancellation evidence = %#v", evidence)
		}
	}
}
