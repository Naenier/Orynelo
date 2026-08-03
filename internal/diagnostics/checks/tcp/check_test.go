package tcp

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "operation timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestClassifyError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		code string
	}{
		{"nil", nil, ""},
		{"cancelled", context.Canceled, ErrorCancelled},
		{"deadline", context.DeadlineExceeded, ErrorTimeout},
		{"refused", &net.OpError{Err: syscall.ECONNREFUSED}, ErrorConnectionRefused},
		{"network unreachable", &net.OpError{Err: syscall.ENETUNREACH}, ErrorNetworkUnreachable},
		{"host unreachable", &net.OpError{Err: syscall.EHOSTUNREACH}, ErrorHostUnreachable},
		{"net timeout", timeoutError{}, ErrorTimeout},
		{"wrapped text", errors.New("dial: no route to host"), ErrorHostUnreachable},
		{"other", errors.New("broken"), ErrorOther},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := ClassifyError(test.err); got != test.code {
				t.Fatalf("ClassifyError() = %q, want %q", got, test.code)
			}
		})
	}
}

type fakeDialer struct {
	errors map[string]error
}

func (d fakeDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	if err := d.errors[address]; err != nil {
		return nil, err
	}
	client, server := net.Pipe()
	go func() {
		_ = server.Close()
	}()
	return client, nil
}

type stagedDialer struct {
	blockAddress string
	started      chan struct{}
}

func (d stagedDialer) DialContext(ctx context.Context, _, address string) (net.Conn, error) {
	if address == d.blockAddress {
		close(d.started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	client, server := net.Pipe()
	go func() {
		_ = server.Close()
	}()
	return client, nil
}

func TestCheckPreservesPerAddressOutcomes(t *testing.T) {
	t.Parallel()
	options := model.DefaultDiagnoseOptions("example.com:443")
	options.MaxConcurrency = 2
	state := model.NewState(model.Target{Host: "example.com", Port: 443}, options)
	state.SetDNS(model.DNSResult{
		IPv4: []net.IP{net.ParseIP("192.0.2.1")},
		IPv6: []net.IP{net.ParseIP("2001:db8::1")},
	})
	check := New(fakeDialer{errors: map[string]error{
		"[2001:db8::1]:443": syscall.ECONNREFUSED,
	}})
	result := check.Run(context.Background(), state)
	if result.Status != model.StatusWarning || result.ErrorCode != ErrorPartialFailure {
		t.Fatalf("result = %#v", result)
	}
	attempts := state.TCP()
	if len(attempts) != 2 || !attempts[0].Success ||
		attempts[1].ErrorCode != ErrorConnectionRefused {
		t.Fatalf("attempts = %#v", attempts)
	}
	if attempts[0].State != model.AttemptStateCompleted ||
		attempts[1].State != model.AttemptStateCompleted {
		t.Fatalf("attempt states = %#v", attempts)
	}
	if result.Evidence[0].Details["family"] != "ipv4" ||
		result.Evidence[1].Details["family"] != "ipv6" {
		t.Fatalf("family evidence = %#v", result.Evidence)
	}
}

func TestCheckAllTimeouts(t *testing.T) {
	t.Parallel()
	options := model.DefaultDiagnoseOptions("example.com:443")
	state := model.NewState(model.Target{Host: "example.com", Port: 443}, options)
	state.SetDNS(model.DNSResult{IPv4: []net.IP{
		net.ParseIP("192.0.2.1"),
		net.ParseIP("192.0.2.2"),
	}})
	check := New(fakeDialer{errors: map[string]error{
		"192.0.2.1:443": timeoutError{},
		"192.0.2.2:443": timeoutError{},
	}})
	result := check.Run(context.Background(), state)
	if result.Status != model.StatusFailed || result.ErrorCode != ErrorTimeout {
		t.Fatalf("result = %#v", result)
	}
}

func TestCheckCancellation(t *testing.T) {
	t.Parallel()
	options := model.DefaultDiagnoseOptions("example.com:443")
	state := model.NewState(model.Target{Host: "example.com", Port: 443}, options)
	state.SetDNS(model.DNSResult{IPv4: []net.IP{net.ParseIP("192.0.2.1")}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := New(fakeDialer{}).Run(ctx, state)
	if result.Status != model.StatusCancelled || result.ErrorCode != ErrorCancelled {
		t.Fatalf("result = %#v", result)
	}
	if len(result.Evidence) != 0 || len(state.TCP()) != 0 {
		t.Fatalf("not-started attempts leaked into result: evidence=%#v state=%#v", result.Evidence, state.TCP())
	}
}

func TestCheckCancellationPreservesOnlyStartedAttempts(t *testing.T) {
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

	result := New(stagedDialer{
		blockAddress: "192.0.2.2:443",
		started:      started,
	}).Run(ctx, state)
	if result.Status != model.StatusCancelled || result.ErrorCode != ErrorCancelled {
		t.Fatalf("result = %#v", result)
	}
	attempts := state.TCP()
	if len(attempts) != 2 || len(result.Evidence) != 2 {
		t.Fatalf("partial result did not retain only started attempts: state=%#v evidence=%#v", attempts, result.Evidence)
	}
	if !attempts[0].Success || attempts[0].RemoteIP.String() != "192.0.2.1" {
		t.Fatalf("completed attempt was not preserved: %#v", attempts)
	}
	if attempts[0].State != model.AttemptStateCompleted {
		t.Fatalf("completed attempt state = %q", attempts[0].State)
	}
	if attempts[1].RemoteIP.String() != "192.0.2.2" || attempts[1].Error == "" {
		t.Fatalf("cancelled started attempt is incomplete: %#v", attempts)
	}
	if attempts[1].State != model.AttemptStateCancelled {
		t.Fatalf("cancelled attempt state = %q", attempts[1].State)
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
