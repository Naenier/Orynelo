package dns

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

type fakeResolver struct {
	values map[string][]net.IP
	errors map[string]error
}

func (f fakeResolver) LookupIP(_ context.Context, network, _ string) ([]net.IP, error) {
	return append([]net.IP(nil), f.values[network]...), f.errors[network]
}

func TestCheckNormalizesFamiliesAndDuplicates(t *testing.T) {
	t.Parallel()
	check := New(fakeResolver{values: map[string][]net.IP{
		"ip4": {net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.1")},
		"ip6": {net.ParseIP("2001:db8::2"), net.ParseIP("2001:db8::1")},
	}})
	options := model.DefaultDiagnoseOptions("example.com")
	state := model.NewState(model.Target{Host: "example.com", Port: 443}, options)
	result := check.Run(context.Background(), state)
	if result.Status != model.StatusPassed {
		t.Fatalf("status = %s, summary %s", result.Status, result.Summary)
	}
	got := state.DNS()
	if joinIPs(got.IPv4) != "192.0.2.1, 192.0.2.2" {
		t.Fatalf("IPv4 = %v", got.IPv4)
	}
	if joinIPs(got.IPv6) != "2001:db8::1, 2001:db8::2" {
		t.Fatalf("IPv6 = %v", got.IPv6)
	}
	if result.Evidence[0].Details["duplicatesRemoved"] != "1" {
		t.Fatalf("duplicate evidence = %#v", result.Evidence[0].Details)
	}
}

func TestCheckFamilyRequirements(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mode   model.IPVersion
		values map[string][]net.IP
		errs   map[string]error
		status model.Status
		code   string
	}{
		{
			name:   "auto accepts IPv4 without AAAA",
			mode:   model.IPVersionAuto,
			values: map[string][]net.IP{"ip4": {net.ParseIP("192.0.2.1")}},
			errs:   map[string]error{"ip6": &net.DNSError{Err: "no such host"}},
			status: model.StatusPassed,
		},
		{
			name:   "IPv6 requires AAAA",
			mode:   model.IPVersion6,
			errs:   map[string]error{"ip6": &net.DNSError{Err: "no such host"}},
			status: model.StatusFailed,
			code:   ErrorLookupFailed,
		},
		{
			name:   "empty successful response",
			mode:   model.IPVersion4,
			values: map[string][]net.IP{"ip4": {}},
			status: model.StatusFailed,
			code:   ErrorNoRecords,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := model.DefaultDiagnoseOptions("example.com")
			options.IPVersion = test.mode
			state := model.NewState(model.Target{Host: "example.com", Port: 443}, options)
			result := New(fakeResolver{values: test.values, errors: test.errs}).Run(context.Background(), state)
			if result.Status != test.status || result.ErrorCode != test.code {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}

func TestCheckIPLiteralHonorsMode(t *testing.T) {
	t.Parallel()
	options := model.DefaultDiagnoseOptions("192.0.2.1")
	options.IPVersion = model.IPVersion6
	state := model.NewState(model.Target{Host: "192.0.2.1", Port: 443}, options)
	result := New(fakeResolver{}).Run(context.Background(), state)
	if result.Status != model.StatusFailed || result.ErrorCode != ErrorIPFamilyMismatch {
		t.Fatalf("result = %#v", result)
	}
	if len(result.Recommendations) != 1 {
		t.Fatalf("family mismatch lacks an actionable recommendation: %#v", result)
	}
	if len(result.Evidence) != 1 || result.Evidence[0].ID != "dns.literal_family_mismatch" ||
		result.Evidence[0].Details["addressFamily"] != "ipv4" ||
		result.Evidence[0].Details["requestedMode"] != "6" {
		t.Fatalf("family mismatch lacks concrete evidence: %#v", result.Evidence)
	}
}

func TestIsLookupFailure(t *testing.T) {
	t.Parallel()
	if !IsLookupFailure(errors.Join(errors.New("outer"), &net.DNSError{Err: "failure"})) {
		t.Fatal("expected wrapped DNS error")
	}
}
