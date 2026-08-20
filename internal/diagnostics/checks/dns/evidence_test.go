package dns

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

type detailedResolverFunc func(context.Context, string) (DetailedResult, error)

type panicResolver struct{}

func (panicResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	panic("resolver secret must not escape")
}

func (function detailedResolverFunc) LookupDetails(
	ctx context.Context,
	host string,
) (DetailedResult, error) {
	return function(ctx, host)
}

func TestClassifyResolverErrorDoesNotInventResponseCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		err    error
		status model.DNSFamilyStatus
		code   string
	}{
		{"cancelled", context.Canceled, model.DNSFamilyStatusCancelled, ErrorCancelled},
		{"deadline", context.DeadlineExceeded, model.DNSFamilyStatusTimeout, ErrorTimeout},
		{
			"resolver timeout",
			&net.DNSError{Err: "timeout", IsTimeout: true},
			model.DNSFamilyStatusTimeout,
			ErrorTimeout,
		},
		{
			"ambiguous not found",
			&net.DNSError{Err: "no such host", IsNotFound: true},
			model.DNSFamilyStatusNotFoundUnknown,
			ErrorNotFoundUnknown,
		},
		{"unclassified", errors.New("server failure"), model.DNSFamilyStatusError, ErrorLookupFailed},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			status, code := classifyResolverError(test.err)
			if status != test.status || code != test.code {
				t.Fatalf("classification = (%q, %q), want (%q, %q)", status, code, test.status, test.code)
			}
		})
	}
}

func TestCheckIsolatesResolverPanicFromLookupGoroutines(t *testing.T) {
	t.Parallel()

	options := model.DefaultDiagnoseOptions("example.test")
	state := model.NewState(model.Target{Host: "example.test", Port: 443}, options)
	result := New(panicResolver{}).Run(context.Background(), state)
	if result.Status != model.StatusFailed || result.ErrorCode != ErrorLookupFailed {
		t.Fatalf("result = %#v", result)
	}
	for _, evidence := range result.Evidence {
		if evidence.Details["error"] == "resolver secret must not escape" {
			t.Fatalf("panic value escaped into evidence: %#v", evidence)
		}
	}
}

func TestCheckUsesStructuredDetailedStatuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status model.DNSFamilyStatus
		code   string
	}{
		{"NXDOMAIN", model.DNSFamilyStatusNXDOMAIN, ErrorNXDOMAIN},
		{"NODATA", model.DNSFamilyStatusNoData, ErrorNoData},
		{"SERVFAIL", model.DNSFamilyStatusSERVFAIL, ErrorSERVFAIL},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ambiguous := &net.DNSError{Err: "no such host", IsNotFound: true}
			check := New(fakeResolver{errors: map[string]error{
				"ip4": ambiguous,
				"ip6": ambiguous,
			}})
			check.DetailedResolver = detailedResolverFunc(func(
				context.Context,
				string,
			) (DetailedResult, error) {
				return DetailedResult{Families: []model.DNSFamilyResult{
					{RecordType: "A", Status: test.status},
					{RecordType: "AAAA", Status: test.status},
				}}, nil
			})
			options := model.DefaultDiagnoseOptions("example.test")
			options.CollectDNSDetails = true
			state := model.NewState(model.Target{Host: "example.test", Port: 443}, options)
			result := check.Run(context.Background(), state)
			if result.Status != model.StatusFailed || result.ErrorCode != test.code {
				t.Fatalf("result = %#v", result)
			}
			for _, family := range state.DNS().Families {
				if family.Status != test.status {
					t.Fatalf("family = %#v", family)
				}
			}
		})
	}
}

func TestStructuredNoDataClearsAmbiguousSystemError(t *testing.T) {
	t.Parallel()

	ambiguous := &net.DNSError{Err: "no such host", IsNotFound: true}
	check := New(fakeResolver{
		values: map[string][]net.IP{"ip4": {net.ParseIP("192.0.2.1")}},
		errors: map[string]error{"ip6": ambiguous},
	})
	check.DetailedResolver = detailedResolverFunc(func(
		context.Context,
		string,
	) (DetailedResult, error) {
		return DetailedResult{Families: []model.DNSFamilyResult{{
			RecordType: "AAAA", Status: model.DNSFamilyStatusNoData,
		}}}, nil
	})
	options := model.DefaultDiagnoseOptions("example.test")
	options.CollectDNSDetails = true
	state := model.NewState(model.Target{Host: "example.test", Port: 443}, options)
	result := check.Run(context.Background(), state)
	if result.Status != model.StatusPassed {
		t.Fatalf("result = %#v", result)
	}
	family := state.DNS().Families[1]
	if family.Status != model.DNSFamilyStatusNoData || family.Error != "" ||
		family.ErrorCode != ErrorNoData {
		t.Fatalf("refined family = %#v", family)
	}
	if _, present := evidenceByID(result.Evidence, "dns.aaaa").Details["error"]; present {
		t.Fatalf("structured NODATA retained ambiguous system error: %#v", result.Evidence)
	}
}

func TestCheckExplainsNormalAAAAAbsenceAndRealFailure(t *testing.T) {
	t.Parallel()

	options := model.DefaultDiagnoseOptions("example.test")
	state := model.NewState(model.Target{Host: "example.test", Port: 443}, options)
	result := New(fakeResolver{values: map[string][]net.IP{
		"ip4": {net.ParseIP("192.0.2.1")},
	}}).Run(context.Background(), state)
	if result.Status != model.StatusPassed {
		t.Fatalf("NODATA result = %#v", result)
	}
	if got := evidenceByID(result.Evidence, "dns.aaaa").Details["absence"]; got != "normal_for_auto_mode" {
		t.Fatalf("AAAA absence evidence = %q", got)
	}

	state = model.NewState(model.Target{Host: "example.test", Port: 443}, options)
	result = New(fakeResolver{
		values: map[string][]net.IP{"ip4": {net.ParseIP("192.0.2.1")}},
		errors: map[string]error{"ip6": &net.DNSError{Err: "timeout", IsTimeout: true}},
	}).Run(context.Background(), state)
	if result.Status != model.StatusWarning || result.ErrorCode != ErrorPartialFailure {
		t.Fatalf("partial failure result = %#v", result)
	}
	if got := state.DNS().Families[1].Status; got != model.DNSFamilyStatusTimeout {
		t.Fatalf("AAAA status = %q", got)
	}
}

func TestCheckDetectsResolvedFamilyMismatch(t *testing.T) {
	t.Parallel()

	options := model.DefaultDiagnoseOptions("example.test")
	options.IPVersion = model.IPVersion6
	state := model.NewState(model.Target{Host: "example.test", Port: 443}, options)
	result := New(fakeResolver{values: map[string][]net.IP{
		"ip4": {net.ParseIP("192.0.2.1")},
	}}).Run(context.Background(), state)
	if result.Status != model.StatusFailed || result.ErrorCode != ErrorFamilyMismatch {
		t.Fatalf("result = %#v", result)
	}
	if got := state.DNS().Families[1].Status; got != model.DNSFamilyStatusFamilyMismatch {
		t.Fatalf("AAAA status = %q", got)
	}
}

func TestCheckCollectsBoundedDetailedEvidenceAndNetworkRefs(t *testing.T) {
	t.Parallel()

	check := New(fakeResolver{values: map[string][]net.IP{
		"ip4": {
			net.ParseIP("192.0.2.1"),
			net.ParseIP("192.0.2.2"),
			net.ParseIP("192.0.2.3"),
		},
	}})
	check.ResolverInfo = func() resolverInfo {
		return resolverInfo{source: "fixture system resolver", searchDomains: []string{"base.example"}}
	}
	check.DetailedResolver = detailedResolverFunc(func(
		context.Context,
		string,
	) (DetailedResult, error) {
		cnames := make([]string, 20)
		for index := range cnames {
			cnames[index] = "alias" + string(rune('a'+index)) + ".example."
		}
		return DetailedResult{
			CNAMEs:         cnames,
			TTL:            90 * time.Second,
			ResolverSource: "fixture wire resolver",
			SearchDomains:  []string{"svc.example.", "svc.example"},
			ResponseCodes:  map[string]string{"ip4": "NOERROR", "ip6": "NOERROR"},
		}, nil
	})
	options := model.DefaultDiagnoseOptions("example.test")
	options.CollectDNSDetails = true
	options.AddressLimit = 2
	state := model.NewState(model.Target{Host: "example.test", Port: 443}, options)
	result := check.Run(context.Background(), state)
	if result.Status != model.StatusPassed {
		t.Fatalf("result = %#v", result)
	}
	dnsResult := state.DNS()
	if len(dnsResult.CNAMEs) != 16 || dnsResult.TTL != 90*time.Second ||
		dnsResult.ResolverSource != "fixture wire resolver" ||
		len(dnsResult.SearchDomains) != 1 {
		t.Fatalf("detailed result = %#v", dnsResult)
	}
	if evidenceByCode(result.Evidence, "ADDRESS_SKIPPED_BY_LIMIT") == nil {
		t.Fatalf("limit evidence missing: %#v", result.Evidence)
	}
	if len(result.NetworkRefs) != 2 || result.NetworkRefs[0].AttemptID != "attempt-dns-a" {
		t.Fatalf("network refs = %#v", result.NetworkRefs)
	}
	paths := state.NetworkPaths()
	if len(paths) != 1 || len(paths[0].Hops) != 1 || len(paths[0].Hops[0].Attempts) != 2 {
		t.Fatalf("network paths = %#v", paths)
	}
}

func TestCheckDetailedFailureDoesNotDiscardUsableAddresses(t *testing.T) {
	t.Parallel()

	check := New(fakeResolver{values: map[string][]net.IP{
		"ip4": {net.ParseIP("192.0.2.1")},
	}})
	check.DetailedResolver = detailedResolverFunc(func(
		context.Context,
		string,
	) (DetailedResult, error) {
		return DetailedResult{}, errors.New("detail resolver unavailable")
	})
	options := model.DefaultDiagnoseOptions("example.test")
	options.CollectDNSDetails = true
	state := model.NewState(model.Target{Host: "example.test", Port: 443}, options)
	result := check.Run(context.Background(), state)
	if result.Status != model.StatusWarning || len(state.DNS().IPv4) != 1 {
		t.Fatalf("result = %#v, DNS = %#v", result, state.DNS())
	}
	if evidenceByCode(result.Evidence, ErrorDetailsFailed) == nil {
		t.Fatalf("details failure evidence missing: %#v", result.Evidence)
	}
}

func TestCheckPreservesPreviouslyRecordedProxyPath(t *testing.T) {
	t.Parallel()

	options := model.DefaultDiagnoseOptions("example.test")
	state := model.NewState(model.Target{Host: "example.test", Port: 443}, options)
	state.SetNetworkPaths([]model.NetworkPath{{
		ID:   "path-proxy",
		Role: model.NetworkPathRoleClientEffective,
		Kind: model.NetworkPathHTTPProxy,
	}})
	result := New(fakeResolver{values: map[string][]net.IP{
		"ip4": {net.ParseIP("192.0.2.1")},
	}}).Run(context.Background(), state)
	if result.Status != model.StatusPassed {
		t.Fatalf("result = %#v", result)
	}
	paths := state.NetworkPaths()
	if len(paths) != 2 || paths[0].ID != "path-proxy" || paths[1].ID != directPathID {
		t.Fatalf("paths = %#v", paths)
	}
}

func TestCheckAlwaysLooksUpBothFamiliesForMismatchEvidence(t *testing.T) {
	t.Parallel()

	resolver := &countingResolver{}
	options := model.DefaultDiagnoseOptions("example.test")
	options.IPVersion = model.IPVersion4
	state := model.NewState(model.Target{Host: "example.test", Port: 443}, options)
	_ = New(resolver).Run(context.Background(), state)
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.calls["ip4"] != 1 || resolver.calls["ip6"] != 1 {
		t.Fatalf("lookup calls = %#v", resolver.calls)
	}
}

type countingResolver struct {
	mu    sync.Mutex
	calls map[string]int
}

func (resolver *countingResolver) LookupIP(
	_ context.Context,
	network string,
	_ string,
) ([]net.IP, error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.calls == nil {
		resolver.calls = make(map[string]int)
	}
	resolver.calls[network]++
	return nil, nil
}

func evidenceByID(values []model.Evidence, id string) model.Evidence {
	for _, value := range values {
		if value.ID == id {
			return value
		}
	}
	return model.Evidence{}
}

func evidenceByCode(values []model.Evidence, code string) *model.Evidence {
	for index := range values {
		if values[index].Code == code {
			return &values[index]
		}
	}
	return nil
}
