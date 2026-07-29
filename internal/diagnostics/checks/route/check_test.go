package route

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

type fakeDiscoverer struct {
	values map[string]net.IP
	errors map[string]error
}

func (f fakeDiscoverer) SourceIP(_ context.Context, remote net.IP, _ uint16) (net.IP, error) {
	return f.values[remote.String()], f.errors[remote.String()]
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
