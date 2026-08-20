package diagnostics

import (
	"context"
	"net"
	"net/url"
	"testing"

	dnscheck "github.com/Naenier/orynelo/internal/diagnostics/checks/dns"
	"github.com/Naenier/orynelo/internal/diagnostics/engine"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

type stage3SelectedProxyCheck struct{}

func (stage3SelectedProxyCheck) ID() string   { return "environment" }
func (stage3SelectedProxyCheck) Name() string { return "environment" }
func (stage3SelectedProxyCheck) Run(_ context.Context, state *model.State) model.CheckResult {
	selection := model.ProxySelection{
		SourceVariable: "HTTPS_PROXY",
		URL:            "http://proxy.example:8080",
		RequestURL:     "http://proxy.example:8080",
		Validity:       model.ProxyValidityValid,
	}
	state.SetProxy(model.ProxyInfo{
		Selected:  true,
		Selection: selection,
		SelectForURL: func(*url.URL) model.ProxySelection {
			return selection
		},
	})
	return model.CheckResult{Status: model.StatusWarning, Summary: "proxy selected"}
}

type stage3DirectEnvironmentCheck struct{}

func (stage3DirectEnvironmentCheck) ID() string   { return "environment" }
func (stage3DirectEnvironmentCheck) Name() string { return "environment" }
func (stage3DirectEnvironmentCheck) Run(_ context.Context, state *model.State) model.CheckResult {
	state.SetProxy(model.ProxyInfo{Selection: model.ProxySelection{
		Validity: model.ProxyValidityNotConfigured,
	}})
	return model.CheckResult{Status: model.StatusPassed, Summary: "direct route selected"}
}

type stage3NeverCalledCheck struct {
	id    string
	calls *int
}

func (check stage3NeverCalledCheck) ID() string   { return check.id }
func (check stage3NeverCalledCheck) Name() string { return check.id }
func (check stage3NeverCalledCheck) Run(context.Context, *model.State) model.CheckResult {
	*check.calls++
	return model.CheckResult{Status: model.StatusFailed, Summary: "unexpected direct probe"}
}

type stage3ProxyHTTPCheck struct{}

func (stage3ProxyHTTPCheck) ID() string   { return "http" }
func (stage3ProxyHTTPCheck) Name() string { return "http" }
func (stage3ProxyHTTPCheck) Run(_ context.Context, state *model.State) model.CheckResult {
	const pathID = "http-client-path-1"
	const peerID = "http-client-path-1-hop-1"
	const originID = "http-client-path-1-hop-2"
	ref := model.NetworkRef{PathID: pathID, HopID: originID, AttemptID: originID + "-http"}
	paths := state.NetworkPaths()
	paths = append(paths, model.NetworkPath{
		ID: pathID, Role: model.NetworkPathRoleClientEffective,
		Kind: model.NetworkPathHTTPSConnect,
		Hops: []model.NetworkHop{
			{
				ID: peerID, PathID: pathID, Kind: model.NetworkHopProxyPeer,
				Host: "proxy.example", Port: 8080,
				Attempts: []model.NetworkAttempt{{
					ID: peerID + "-connect-1", PathID: pathID, HopID: peerID,
					Kind: model.NetworkAttemptTCP, State: model.AttemptStateCompleted,
					RemoteIP: net.ParseIP("192.0.2.20"), Selected: true,
				}},
			},
			{
				ID: originID, PathID: pathID, Kind: model.NetworkHopOrigin,
				Host: "origin.example", Port: 443,
				Attempts: []model.NetworkAttempt{{
					ID: ref.AttemptID, PathID: pathID, HopID: originID,
					Kind: model.NetworkAttemptHTTP, State: model.AttemptStateCompleted,
					Selected: true,
				}},
			},
		},
	})
	state.SetNetworkPaths(paths)
	return model.CheckResult{
		Status:      model.StatusPassed,
		Summary:     "request completed through CONNECT proxy",
		NetworkRefs: []model.NetworkRef{ref},
		Evidence: []model.Evidence{{
			ID: "http.response", NetworkRef: &ref,
			Code: "HTTP_RESPONSE", Message: "response received",
		}},
	}
}

type stage3DirectHTTPCheck struct{}

func (stage3DirectHTTPCheck) ID() string   { return "http" }
func (stage3DirectHTTPCheck) Name() string { return "http" }
func (stage3DirectHTTPCheck) Run(_ context.Context, state *model.State) model.CheckResult {
	const pathID = "http-client-path-1"
	const hopID = "http-client-path-1-hop-1"
	ref := model.NetworkRef{PathID: pathID, HopID: hopID, AttemptID: hopID + "-http"}
	paths := state.NetworkPaths()
	paths = append(paths, model.NetworkPath{
		ID: pathID, Role: model.NetworkPathRoleClientEffective,
		Kind: model.NetworkPathDirect,
		Hops: []model.NetworkHop{{
			ID: hopID, PathID: pathID, Kind: model.NetworkHopOrigin,
			Host: "origin.example", Port: 443,
			Attempts: []model.NetworkAttempt{{
				ID: ref.AttemptID, PathID: pathID, HopID: hopID,
				Kind: model.NetworkAttemptHTTP, State: model.AttemptStateCompleted,
				Selected: true,
			}},
		}},
	})
	state.SetNetworkPaths(paths)
	return model.CheckResult{
		Status: model.StatusPassed, Summary: "direct request completed",
		NetworkRefs: []model.NetworkRef{ref},
		Evidence: []model.Evidence{{
			ID: "http.response", NetworkRef: &ref,
			Code: "HTTP_RESPONSE", Message: "response received",
		}},
	}
}

type stage3Resolver struct {
	values map[string][]net.IP
	errors map[string]error
}

func (resolver stage3Resolver) LookupIP(
	_ context.Context,
	network string,
	_ string,
) ([]net.IP, error) {
	values := resolver.values[network]
	result := make([]net.IP, len(values))
	for index, value := range values {
		result[index] = append(net.IP(nil), value...)
	}
	return result, resolver.errors[network]
}

func TestRunnerProxyPathIsTheOnlyClientEffectivePath(t *testing.T) {
	t.Parallel()

	directCalls := 0
	plan := engine.Plan{
		{stage3SelectedProxyCheck{}},
		{stage3NeverCalledCheck{id: "dns", calls: &directCalls}},
		{stage3NeverCalledCheck{id: "route", calls: &directCalls}},
		{stage3NeverCalledCheck{id: "tcp", calls: &directCalls}},
		{stage3NeverCalledCheck{id: "tls", calls: &directCalls}},
		{stage3ProxyHTTPCheck{}},
	}
	diagnosis, err := NewRunner(WithPlan(plan)).Diagnose(
		context.Background(),
		model.DefaultDiagnoseOptions("https://origin.example/"),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if directCalls != 0 {
		t.Fatalf("client-effective proxy run executed %d direct probe(s)", directCalls)
	}

	effective := make([]model.NetworkPath, 0, 1)
	for _, path := range diagnosis.NetworkPaths {
		if path.Role == model.NetworkPathRoleClientEffective {
			effective = append(effective, path)
		}
		if path.ID == directPathID && path.Role != model.NetworkPathRoleAuxiliaryDirect {
			t.Fatalf("direct path role = %q, want auxiliary_direct", path.Role)
		}
	}
	if len(effective) != 1 || effective[0].Kind != model.NetworkPathHTTPSConnect {
		t.Fatalf("client-effective paths = %#v", effective)
	}
	if len(effective[0].Hops) != 2 ||
		effective[0].Hops[0].Kind != model.NetworkHopProxyPeer ||
		effective[0].Hops[1].Kind != model.NetworkHopOrigin {
		t.Fatalf("CONNECT path conflated proxy and origin: %#v", effective[0])
	}
	assertNetworkReferencesResolve(t, diagnosis)
}

func TestRunnerHTTPPreflightIsNotTheClientEffectiveTransportPath(t *testing.T) {
	t.Parallel()
	diagnosis, err := NewRunner(WithPlan(engine.Plan{
		{stage3DirectEnvironmentCheck{}},
		{stage3DirectHTTPCheck{}},
	})).Diagnose(
		context.Background(),
		model.DefaultDiagnoseOptions("https://origin.example/"),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	clientPaths := 0
	for _, path := range diagnosis.NetworkPaths {
		switch path.ID {
		case directPathID:
			if path.Role != model.NetworkPathRoleAuxiliaryDirect {
				t.Fatalf("preflight role = %q", path.Role)
			}
		case "http-client-path-1":
			if path.Role != model.NetworkPathRoleClientEffective {
				t.Fatalf("HTTP path role = %q", path.Role)
			}
		}
		if path.Role == model.NetworkPathRoleClientEffective {
			clientPaths++
		}
	}
	if clientPaths != 1 {
		t.Fatalf("client-effective path count = %d; paths=%#v", clientPaths, diagnosis.NetworkPaths)
	}
	assertNetworkReferencesResolve(t, diagnosis)
}

func TestRunnerCorrelatesDualStackMatrixPartialFailure(t *testing.T) {
	t.Parallel()

	resolver := stage3Resolver{
		values: map[string][]net.IP{
			"ip4": {
				net.ParseIP("192.0.2.1"),
				net.ParseIP("192.0.2.2"),
				net.ParseIP("192.0.2.3"),
			},
		},
		errors: map[string]error{
			"ip6": &net.DNSError{Err: "resolver timeout", IsTimeout: true},
		},
	}
	options := model.DefaultDiagnoseOptions("dual-stack.example:443")
	options.ProbeMode = model.ProbeModeAddressMatrix
	options.AddressLimit = 2
	diagnosis, err := NewRunner(WithPlan(engine.Plan{
		{stage3DirectEnvironmentCheck{}},
		{dnscheck.New(resolver)},
	})).Diagnose(
		context.Background(), options, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	var dnsResult *model.CheckResult
	for index := range diagnosis.Checks {
		if diagnosis.Checks[index].ID == "dns" {
			dnsResult = &diagnosis.Checks[index]
			break
		}
	}
	if dnsResult == nil || dnsResult.Status != model.StatusWarning ||
		dnsResult.ErrorCode != dnscheck.ErrorPartialFailure {
		t.Fatalf("dual-stack result = %#v", diagnosis.Checks)
	}
	if evidenceByCode(dnsResult.Evidence, "ADDRESS_SKIPPED_BY_LIMIT") == nil {
		t.Fatalf("matrix limit evidence missing: %#v", dnsResult.Evidence)
	}
	if evidenceByCode(dnsResult.Evidence, dnscheck.ErrorTimeout) == nil {
		// The timeout is represented by the family evidence's details rather
		// than by replacing its stable DNS_AAAA_RESULT evidence code.
		var timeoutRecorded bool
		for _, evidence := range dnsResult.Evidence {
			if evidence.Details["errorCode"] == dnscheck.ErrorTimeout {
				timeoutRecorded = true
			}
		}
		if !timeoutRecorded {
			t.Fatalf("AAAA timeout evidence missing: %#v", dnsResult.Evidence)
		}
	}
	assertNetworkReferencesResolve(t, diagnosis)
}

func assertNetworkReferencesResolve(t *testing.T, diagnosis model.Diagnosis) {
	t.Helper()

	type hopKey struct{ pathID, hopID string }
	type attemptKey struct{ pathID, hopID, attemptID string }
	paths := make(map[string]struct{}, len(diagnosis.NetworkPaths))
	hops := make(map[hopKey]struct{})
	attempts := make(map[attemptKey]struct{})
	for _, path := range diagnosis.NetworkPaths {
		if path.ID == "" {
			t.Fatal("network path has an empty ID")
		}
		paths[path.ID] = struct{}{}
		for _, hop := range path.Hops {
			if hop.PathID != path.ID || hop.ID == "" {
				t.Fatalf("invalid hop identity: path=%#v hop=%#v", path, hop)
			}
			hops[hopKey{path.ID, hop.ID}] = struct{}{}
			for _, attempt := range hop.Attempts {
				if attempt.PathID != path.ID || attempt.HopID != hop.ID || attempt.ID == "" {
					t.Fatalf("invalid attempt identity: hop=%#v attempt=%#v", hop, attempt)
				}
				attempts[attemptKey{path.ID, hop.ID, attempt.ID}] = struct{}{}
			}
		}
	}
	assertRef := func(owner string, ref model.NetworkRef) {
		t.Helper()
		if _, ok := paths[ref.PathID]; !ok {
			t.Fatalf("%s references missing path %#v", owner, ref)
		}
		if ref.HopID != "" {
			if _, ok := hops[hopKey{ref.PathID, ref.HopID}]; !ok {
				t.Fatalf("%s references missing hop %#v", owner, ref)
			}
		}
		if ref.AttemptID != "" {
			if _, ok := attempts[attemptKey{ref.PathID, ref.HopID, ref.AttemptID}]; !ok {
				t.Fatalf("%s references missing attempt %#v", owner, ref)
			}
		}
	}
	for _, check := range diagnosis.Checks {
		if len(check.NetworkRefs) == 0 {
			t.Fatalf("check %q has no network reference", check.ID)
		}
		for _, ref := range check.NetworkRefs {
			assertRef("check "+check.ID, ref)
		}
		for _, evidence := range check.Evidence {
			if evidence.NetworkRef == nil {
				t.Fatalf("evidence %q in check %q has no network reference", evidence.ID, check.ID)
			}
			assertRef("evidence "+evidence.ID, *evidence.NetworkRef)
		}
	}
}

func evidenceByCode(values []model.Evidence, code string) *model.Evidence {
	for index := range values {
		if values[index].Code == code {
			return &values[index]
		}
	}
	return nil
}
