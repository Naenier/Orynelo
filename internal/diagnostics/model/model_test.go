package model

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestAttemptStateJSONIsBackwardCompatible(t *testing.T) {
	t.Parallel()

	var oldRoute RouteInfo
	if err := json.Unmarshal([]byte(`{"remoteIp":"192.0.2.1","family":"ipv4"}`), &oldRoute); err != nil {
		t.Fatal(err)
	}
	if oldRoute.State != "" {
		t.Fatalf("old route state = %q, want empty compatibility value", oldRoute.State)
	}
	encodedOld, err := json.Marshal(oldRoute)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encodedOld, []byte(`"state"`)) {
		t.Fatalf("old route gained a state field: %s", encodedOld)
	}

	attempt := TCPAttempt{
		RemoteIP: net.ParseIP("192.0.2.2"),
		Success:  true,
		State:    AttemptStateCompleted,
	}
	encodedAttempt, err := json.Marshal(attempt)
	if err != nil {
		t.Fatal(err)
	}
	var decodedAttempt TCPAttempt
	if err := json.Unmarshal(encodedAttempt, &decodedAttempt); err != nil {
		t.Fatal(err)
	}
	if decodedAttempt.State != AttemptStateCompleted {
		t.Fatalf("round-trip state = %q", decodedAttempt.State)
	}

	state := NewState(Target{}, DiagnoseOptions{})
	state.SetTCP([]TCPAttempt{attempt})
	if got := state.TCP()[0].State; got != AttemptStateCompleted {
		t.Fatalf("cloned attempt state = %q", got)
	}
}

func TestAttemptStateVocabulary(t *testing.T) {
	t.Parallel()
	for _, state := range []AttemptState{
		AttemptStateQueued,
		AttemptStateRunning,
		AttemptStateCompleted,
		AttemptStateCancelled,
		AttemptStateSkipped,
	} {
		if !state.Valid() {
			t.Fatalf("state %q is not valid", state)
		}
	}
	if AttemptState("").Valid() {
		t.Fatal("empty attempt state unexpectedly valid")
	}
}

func TestCheckStatusVocabularyDistinguishesNotApplicable(t *testing.T) {
	t.Parallel()
	for _, status := range []Status{
		StatusPending,
		StatusRunning,
		StatusPassed,
		StatusWarning,
		StatusFailed,
		StatusSkipped,
		StatusNotApplicable,
		StatusCancelled,
	} {
		if !status.Valid() {
			t.Fatalf("status %q is not valid", status)
		}
	}
	if StatusNotApplicable == StatusSkipped {
		t.Fatal("not-applicable is conflated with skipped")
	}
}

func TestStageThreeDefaultsAreClientEffectiveAndBounded(t *testing.T) {
	t.Parallel()

	options := DefaultDiagnoseOptions("example.test")
	if options.ProbeMode != ProbeModeClientEffective || options.AddressLimit != 4 ||
		options.AddressMatrixBudget != 5*time.Second {
		t.Fatalf("path defaults = %#v", options)
	}
	if options.ExpectedStatusMin != 200 || options.ExpectedStatusMax != 399 ||
		options.ExpectedStatusConfigured || options.InspectBody {
		t.Fatalf("HTTP defaults = %#v", options)
	}
	if !options.ProbeMode.Valid() || ProbeMode("unknown").Valid() {
		t.Fatal("probe mode validation is inconsistent")
	}
}

func TestStageThreeFieldsAreAdditiveAndRuntimeSecretsAreExcluded(t *testing.T) {
	t.Parallel()

	var legacy Diagnosis
	if err := json.Unmarshal([]byte(`{
		"id":"legacy", "target":{"host":"example.test","port":443,"kind":"http","useTLS":true},
		"options":{}, "checks":[], "summary":{"status":"passed","title":"ok","description":"ok"},
		"build":{}, "startedAt":"2026-01-01T00:00:00Z", "finishedAt":"2026-01-01T00:00:01Z", "duration":1
	}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.NetworkPaths != nil || legacy.Target.Mode != "" || legacy.Target.Zone != "" {
		t.Fatalf("legacy snapshot gained values: %#v", legacy)
	}

	legacy.Options.CustomCABundlePath = "/private/ca.pem"
	legacy.Options.CustomCAPEM = []byte("private-ca")
	legacy.Options.RequestHeaders = map[string]string{"Authorization": "secret"}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"/private/ca.pem", "private-ca", "Authorization", "secret"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("runtime-only value %q leaked: %s", secret, encoded)
		}
	}
}

func TestStateDeepClonesCorrelatedArtifacts(t *testing.T) {
	t.Parallel()

	options := DefaultDiagnoseOptions("example.test")
	options.CustomCAPEM = []byte("ca")
	options.RequestHeaders = map[string]string{"X-Test": "value"}
	state := NewState(Target{}, options)
	options.CustomCAPEM[0] = 'x'
	options.RequestHeaders["X-Test"] = "changed"
	if string(state.Options.CustomCAPEM) != "ca" || state.Options.RequestHeaders["X-Test"] != "value" {
		t.Fatal("NewState retained request-option aliases")
	}

	paths := []NetworkPath{{
		ID: "path-001", Role: NetworkPathRoleClientEffective, Kind: NetworkPathDirect,
		Hops: []NetworkHop{{
			ID: "hop-001", PathID: "path-001", Kind: NetworkHopOrigin,
			Attempts: []NetworkAttempt{{
				ID: "attempt-001", PathID: "path-001", HopID: "hop-001",
				Kind: NetworkAttemptTCP, RemoteIP: net.ParseIP("192.0.2.1"),
			}},
		}},
	}}
	state.SetNetworkPaths(paths)
	paths[0].Hops[0].Attempts[0].RemoteIP[len(paths[0].Hops[0].Attempts[0].RemoteIP)-1] = 99
	first := state.NetworkPaths()
	first[0].Hops[0].Attempts[0].RemoteIP[len(first[0].Hops[0].Attempts[0].RemoteIP)-1] = 98
	if got := state.NetworkPaths()[0].Hops[0].Attempts[0].RemoteIP.String(); got != "192.0.2.1" {
		t.Fatalf("cloned path IP = %q", got)
	}

	ref := &NetworkRef{PathID: "path-001", HopID: "hop-001", AttemptID: "tls-001"}
	attempts := []TLSAttempt{{
		NetworkRef: *ref,
		RemoteIP:   net.ParseIP("192.0.2.2"),
		Certificate: CertificateInfo{
			DNSNames: []string{"example.test"},
		},
		Chain: []CertificateInfo{{DNSNames: []string{"issuer.test"}}},
	}}
	state.SetTLSAttempts(attempts)
	attempts[0].Certificate.DNSNames[0] = "changed"
	attempts[0].Chain[0].DNSNames[0] = "changed"
	copy := state.TLSAttempts()
	copy[0].RemoteIP[len(copy[0].RemoteIP)-1] = 99
	copy[0].Chain[0].DNSNames[0] = "changed-again"
	got := state.TLSAttempts()[0]
	if got.RemoteIP.String() != "192.0.2.2" || got.Certificate.DNSNames[0] != "example.test" ||
		got.Chain[0].DNSNames[0] != "issuer.test" {
		t.Fatalf("TLS attempt was not deeply cloned: %#v", got)
	}
}
