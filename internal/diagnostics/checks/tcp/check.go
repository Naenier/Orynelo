// Package tcp performs bounded direct connection attempts and preserves
// meaningful operating-system error categories.
package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

const (
	ErrorConnectionRefused  = "TCP_CONNECTION_REFUSED"
	ErrorTimeout            = "TCP_TIMEOUT"
	ErrorNetworkUnreachable = "TCP_NETWORK_UNREACHABLE"
	ErrorHostUnreachable    = "TCP_HOST_UNREACHABLE"
	ErrorCancelled          = "TCP_CANCELLED"
	ErrorOther              = "TCP_OTHER"
	ErrorPartialFailure     = "TCP_PARTIAL_FAILURE"
)

// Dialer is implemented by net.Dialer and deterministic test doubles.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Check connects to every selected address with bounded concurrency.
type Check struct {
	Dialer Dialer
	Now    func() time.Time
}

type attemptSlot struct {
	attempt model.TCPAttempt
	started bool
}

// New constructs a direct TCP check.
func New(dialer Dialer) *Check {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	return &Check{Dialer: dialer, Now: time.Now}
}

// ID returns the stable diagnostic identifier.
func (*Check) ID() string { return "tcp" }

// Name returns the human-readable check name.
func (*Check) Name() string { return "TCP connection" }

// Run attempts bounded connections to all selected addresses.
func (c *Check) Run(ctx context.Context, state *model.State) model.CheckResult {
	resolved := state.DNS()
	addresses := usableAddresses(resolved.IPv4, resolved.IPv6)
	if len(addresses) == 0 {
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusSkipped,
			Summary: "TCP checks were skipped because no remote addresses are available.",
		}
	}

	slots := make([]attemptSlot, len(addresses))
	for index, remote := range addresses {
		slots[index].attempt = model.TCPAttempt{
			RemoteIP: append(net.IP(nil), remote...),
			State:    model.AttemptStateQueued,
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
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			for index := range jobs {
				remote := addresses[index]
				address := net.JoinHostPort(remote.String(), strconv.Itoa(int(state.Target.Port)))
				started := c.now()
				attempt := slots[index].attempt
				attempt.State = model.AttemptStateRunning
				slots[index] = attemptSlot{attempt: attempt, started: true}
				connection, err := c.Dialer.DialContext(ctx, "tcp", address)
				attempt.Duration = c.now().Sub(started)
				attempt.Success = err == nil
				if err == nil {
					if connection.LocalAddr() != nil {
						attempt.LocalAddr = connection.LocalAddr().String()
					}
					_ = connection.Close()
					attempt.State = model.AttemptStateCompleted
				} else {
					attempt.ErrorCode = ClassifyError(err)
					attempt.Error = err.Error()
					attempt.State = model.AttemptStateCompleted
					if ctx.Err() != nil {
						attempt.State = model.AttemptStateCancelled
					}
				}
				slots[index] = attemptSlot{attempt: attempt, started: true}
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
	attempts := startedAttempts(slots)
	state.SetTCP(attempts)
	return c.result(attempts, len(addresses), cancelled)
}

func startedAttempts(slots []attemptSlot) []model.TCPAttempt {
	attempts := make([]model.TCPAttempt, 0, len(slots))
	for _, slot := range slots {
		if slot.started {
			attempts = append(attempts, slot.attempt)
		}
	}
	return attempts
}

func (c *Check) result(attempts []model.TCPAttempt, total int, cancelled bool) model.CheckResult {
	evidence := make([]model.Evidence, 0, len(attempts))
	successes := 0
	completed := 0
	codes := make(map[string]int)
	for index, attempt := range attempts {
		if attempt.RemoteIP == nil ||
			attempt.State == model.AttemptStateQueued ||
			attempt.State == model.AttemptStateSkipped {
			continue
		}
		details := map[string]string{
			"remoteIp": attempt.RemoteIP.String(),
			"family":   family(attempt.RemoteIP),
			"duration": attempt.Duration.String(),
			"success":  strconv.FormatBool(attempt.Success),
			"state":    string(attempt.State),
		}
		message := "TCP connection succeeded."
		if attempt.Success {
			successes++
			if attempt.LocalAddr != "" {
				details["localAddress"] = attempt.LocalAddr
			}
		} else {
			message = "TCP connection failed."
			if attempt.State == model.AttemptStateCancelled {
				message = "TCP connection attempt was cancelled."
			}
			if attempt.ErrorCode != "" {
				details["errorCode"] = attempt.ErrorCode
				codes[attempt.ErrorCode]++
			}
			if attempt.Error != "" {
				details["error"] = attempt.Error
			}
		}
		if attempt.State == model.AttemptStateCompleted {
			completed++
		}
		evidence = append(evidence, model.Evidence{
			ID:      fmt.Sprintf("tcp.%d", index),
			Code:    "TCP_ATTEMPT",
			Message: message,
			Details: details,
		})
	}

	if cancelled {
		neverStarted := total - len(attempts)
		if neverStarted < 0 {
			neverStarted = 0
		}
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusCancelled,
			Summary:   fmt.Sprintf("TCP connection attempts were cancelled after %d of %d started attempt(s) completed; %d of %d address(es) were never started.", completed, len(attempts), neverStarted, total),
			Evidence:  evidence,
			ErrorCode: ErrorCancelled,
		}
	}
	if successes == len(attempts) {
		return model.CheckResult{
			ID:       c.ID(),
			Name:     c.Name(),
			Status:   model.StatusPassed,
			Summary:  fmt.Sprintf("TCP connections succeeded for all %d address(es).", successes),
			Evidence: evidence,
		}
	}
	if successes > 0 {
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusWarning,
			Summary:   fmt.Sprintf("TCP connected to %d of %d address(es).", successes, len(attempts)),
			Evidence:  evidence,
			ErrorCode: ErrorPartialFailure,
			Recommendations: []model.Recommendation{{
				ID:       "tcp.investigate_partial",
				Priority: "medium",
				Message:  "Compare address-family routing and service listeners for the failed addresses.",
			}},
		}
	}

	code := ErrorOther
	summary := "TCP connections failed for all resolved addresses."
	if len(codes) == 1 {
		for value := range codes {
			code = value
		}
	}
	switch code {
	case ErrorConnectionRefused:
		summary = "Every remote address refused the TCP connection."
	case ErrorTimeout:
		summary = "Every TCP connection attempt timed out."
	case ErrorNetworkUnreachable:
		summary = "The network was unreachable for every TCP connection attempt."
	case ErrorHostUnreachable:
		summary = "The remote host was unreachable for every TCP connection attempt."
	}
	return model.CheckResult{
		ID:        c.ID(),
		Name:      c.Name(),
		Status:    model.StatusFailed,
		Summary:   summary,
		Evidence:  evidence,
		ErrorCode: code,
		Recommendations: []model.Recommendation{{
			ID:       "tcp.verify_service",
			Priority: "high",
			Message:  "Verify routing, packet filtering, and that the service is listening on the target port.",
		}},
	}
}

func usableAddresses(groups ...[]net.IP) []net.IP {
	var addresses []net.IP
	for _, group := range groups {
		for _, address := range group {
			if address == nil || address.To16() == nil {
				continue
			}
			addresses = append(addresses, append(net.IP(nil), address...))
		}
	}
	return addresses
}

// ClassifyError maps wrapped cross-platform network errors to stable codes.
func ClassifyError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled):
		return ErrorCancelled
	case errors.Is(err, context.DeadlineExceeded):
		return ErrorTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return ErrorConnectionRefused
	case errors.Is(err, syscall.ENETUNREACH):
		return ErrorNetworkUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH):
		return ErrorHostUnreachable
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ErrorTimeout
	}
	// Go wraps platform-specific Windows socket errors without portable errno
	// constants on non-Windows builds. These phrases retain useful categories.
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "connection refused"):
		return ErrorConnectionRefused
	case strings.Contains(message, "network is unreachable"),
		strings.Contains(message, "network unreachable"):
		return ErrorNetworkUnreachable
	case strings.Contains(message, "host is unreachable"),
		strings.Contains(message, "no route to host"):
		return ErrorHostUnreachable
	case strings.Contains(message, "timed out"),
		strings.Contains(message, "timeout"):
		return ErrorTimeout
	default:
		return ErrorOther
	}
}

func family(ip net.IP) string {
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

func (c *Check) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
