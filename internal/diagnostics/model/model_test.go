package model

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
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
