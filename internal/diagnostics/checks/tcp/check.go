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

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
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

// New constructs a direct TCP check.
func New(dialer Dialer) *Check {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	return &Check{Dialer: dialer, Now: time.Now}
}

func (*Check) ID() string   { return "tcp" }
func (*Check) Name() string { return "TCP connection" }

func (c *Check) Run(ctx context.Context, state *model.State) model.CheckResult {
	resolved := state.DNS()
	addresses := append(append([]net.IP(nil), resolved.IPv4...), resolved.IPv6...)
	if len(addresses) == 0 {
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusSkipped,
			Summary: "TCP checks were skipped because no remote addresses are available.",
		}
	}

	attempts := make([]model.TCPAttempt, len(addresses))
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
				connection, err := c.Dialer.DialContext(ctx, "tcp", address)
				attempt := model.TCPAttempt{
					RemoteIP: remote,
					Duration: c.now().Sub(started),
					Success:  err == nil,
				}
				if err == nil {
					attempt.LocalAddr = connection.LocalAddr().String()
					_ = connection.Close()
				} else {
					attempt.ErrorCode = ClassifyError(err)
					attempt.Error = err.Error()
				}
				attempts[index] = attempt
			}
		}()
	}
	for index := range addresses {
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			wait.Wait()
			state.SetTCP(attempts)
			return c.result(attempts, true)
		}
	}
	close(jobs)
	wait.Wait()
	state.SetTCP(attempts)
	return c.result(attempts, ctx.Err() != nil)
}

func (c *Check) result(attempts []model.TCPAttempt, cancelled bool) model.CheckResult {
	evidence := make([]model.Evidence, 0, len(attempts))
	successes := 0
	codes := make(map[string]int)
	for index, attempt := range attempts {
		details := map[string]string{
			"remoteIp": attempt.RemoteIP.String(),
			"family":   family(attempt.RemoteIP),
			"duration": attempt.Duration.String(),
			"success":  strconv.FormatBool(attempt.Success),
		}
		message := "TCP connection succeeded."
		if attempt.Success {
			successes++
			details["localAddress"] = attempt.LocalAddr
		} else if attempt.RemoteIP != nil {
			message = "TCP connection failed."
			details["errorCode"] = attempt.ErrorCode
			details["error"] = attempt.Error
			codes[attempt.ErrorCode]++
		}
		evidence = append(evidence, model.Evidence{
			ID:      fmt.Sprintf("tcp.%d", index),
			Code:    "TCP_ATTEMPT",
			Message: message,
			Details: details,
		})
	}

	if cancelled {
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusCancelled,
			Summary:   "TCP connection attempts were cancelled.",
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
