// Package tcp performs bounded direct connection attempts and preserves
// meaningful operating-system error categories.
package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	Dialer             Dialer
	Now                func() time.Time
	HappyEyeballsDelay time.Duration
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
	return &Check{Dialer: dialer, Now: time.Now, HappyEyeballsDelay: 250 * time.Millisecond}
}

// ID returns the stable diagnostic identifier.
func (*Check) ID() string { return "tcp" }

// Name returns the human-readable check name.
func (*Check) Name() string { return "TCP connection" }

// Run attempts bounded connections to all selected addresses.
func (c *Check) Run(ctx context.Context, state *model.State) model.CheckResult {
	resolved := state.DNS()
	addresses := usableAddresses(resolved.IPv4, resolved.IPv6)
	if state.Options.ConnectIP != "" {
		if parsed, err := netip.ParseAddr(state.Options.ConnectIP); err == nil {
			addresses = []net.IP{net.IP(parsed.Unmap().AsSlice())}
		}
	}
	if len(addresses) == 0 {
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusSkipped,
			Summary: "TCP checks were skipped because no remote addresses are available.",
		}
	}

	selected, skippedByLimit := selectAddresses(addresses, state.Options)
	var attempts []model.TCPAttempt
	var cancelled bool
	if state.Options.ProbeMode == model.ProbeModeAddressMatrix {
		attempts, cancelled = c.runMatrix(ctx, state, selected)
	} else {
		attempts, cancelled = c.runClientEffective(ctx, state, selected)
	}
	state.SetTCP(attempts)
	result := c.result(attempts, len(selected), cancelled, state.Options.ProbeMode)
	if skippedByLimit > 0 {
		result.Evidence = append(result.Evidence, model.Evidence{
			ID:         "tcp.skipped_by_limit",
			Code:       "ADDRESS_SKIPPED_BY_LIMIT",
			Message:    "Additional resolved addresses were not probed because the configured address limit was reached.",
			NetworkRef: &model.NetworkRef{PathID: "path-direct", HopID: "hop-origin"},
			Details: map[string]string{
				"skipped": strconv.Itoa(skippedByLimit),
				"limit":   strconv.Itoa(state.Options.AddressLimit),
			},
		})
	}
	if !cancelled && state.Options.ProbeMode == model.ProbeModeClientEffective && len(attempts) < len(addresses) {
		result.Evidence = append(result.Evidence, model.Evidence{
			ID:         "tcp.client_effective_bound",
			Code:       "ADDRESS_SKIPPED_CLIENT_EFFECTIVE",
			Message:    "The client-effective probe stopped after selecting a usable connection path.",
			NetworkRef: &model.NetworkRef{PathID: "path-direct", HopID: "hop-origin"},
			Details:    map[string]string{"notStarted": strconv.Itoa(len(addresses) - len(attempts))},
		})
	}
	return result
}

func (c *Check) runMatrix(
	ctx context.Context,
	state *model.State,
	addresses []net.IP,
) ([]model.TCPAttempt, bool) {
	slots := c.initialSlots(addresses)
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
				attemptContext, cancel := c.addressContext(ctx, state.Options, len(addresses))
				attempt := c.dial(attemptContext, state, slots[index].attempt)
				cancel()
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
	for index := range attempts {
		if attempts[index].Success && !hasSelected(attempts) {
			attempts[index].Selected = true
		}
	}
	return attempts, cancelled
}

func (c *Check) runClientEffective(
	ctx context.Context,
	state *model.State,
	addresses []net.IP,
) ([]model.TCPAttempt, bool) {
	if ctx.Err() != nil {
		return nil, true
	}
	if len(addresses) > 2 {
		addresses = addresses[:2]
	}
	if len(addresses) == 0 {
		return nil, ctx.Err() != nil
	}
	type outcome struct {
		index   int
		attempt model.TCPAttempt
	}
	runContext, cancelAll := context.WithCancel(ctx)
	defer cancelAll()
	outcomes := make(chan outcome, len(addresses))
	start := func(index int) {
		go func() {
			attemptContext, cancel := c.addressContext(runContext, state.Options, len(addresses))
			defer cancel()
			attempt := c.dial(attemptContext, state, c.initialAttempt(index, addresses[index]))
			outcomes <- outcome{index: index, attempt: attempt}
		}()
	}
	started := 1
	start(0)
	delay := c.HappyEyeballsDelay
	if delay <= 0 {
		delay = 250 * time.Millisecond
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	completed := make(map[int]model.TCPAttempt, len(addresses))
	for len(completed) < started {
		select {
		case outcome := <-outcomes:
			completed[outcome.index] = outcome.attempt
			if outcome.attempt.Success {
				winner := outcome.attempt
				winner.Selected = true
				completed[outcome.index] = winner
				cancelAll()
				for len(completed) < started {
					other := <-outcomes
					completed[other.index] = other.attempt
				}
				return orderedAttempts(completed), false
			}
			if started < len(addresses) {
				started++
				start(started - 1)
			}
		case <-timer.C:
			if started < len(addresses) {
				started++
				start(started - 1)
			}
		case <-ctx.Done():
			cancelAll()
			for len(completed) < started {
				outcome := <-outcomes
				completed[outcome.index] = outcome.attempt
			}
			return orderedAttempts(completed), true
		}
	}
	return orderedAttempts(completed), ctx.Err() != nil
}

func (c *Check) initialSlots(addresses []net.IP) []attemptSlot {
	slots := make([]attemptSlot, len(addresses))
	for index, remote := range addresses {
		slots[index].attempt = c.initialAttempt(index, remote)
	}
	return slots
}

func (c *Check) initialAttempt(index int, remote net.IP) model.TCPAttempt {
	return model.TCPAttempt{
		NetworkRef: &model.NetworkRef{
			PathID: "path-direct", HopID: "hop-origin",
			AttemptID: fmt.Sprintf("attempt-tcp-%03d", index+1),
		},
		RemoteIP: append(net.IP(nil), remote...),
		State:    model.AttemptStateQueued,
	}
}

func (c *Check) dial(ctx context.Context, state *model.State, attempt model.TCPAttempt) model.TCPAttempt {
	attempt.State = model.AttemptStateRunning
	address := dialAddress(state, attempt.RemoteIP)
	started := c.now()
	connection, err := c.Dialer.DialContext(ctx, "tcp", address)
	attempt.Duration = c.now().Sub(started)
	attempt.Success = err == nil
	if err == nil {
		if connection.LocalAddr() != nil {
			attempt.LocalAddr = connection.LocalAddr().String()
		}
		_ = connection.Close()
		attempt.State = model.AttemptStateCompleted
		return attempt
	}
	attempt.ErrorCode = ClassifyError(err)
	attempt.Error = err.Error()
	attempt.State = model.AttemptStateCompleted
	if ctx.Err() != nil && errors.Is(context.Cause(ctx), context.Canceled) {
		attempt.State = model.AttemptStateCancelled
	}
	return attempt
}

func (c *Check) addressContext(
	parent context.Context,
	options model.DiagnoseOptions,
	count int,
) (context.Context, context.CancelFunc) {
	budget := options.CheckTimeout
	if options.ProbeMode == model.ProbeModeAddressMatrix && options.AddressMatrixBudget > 0 {
		budget = options.AddressMatrixBudget / time.Duration(max(count, 1))
		if budget <= 0 {
			budget = time.Nanosecond
		}
		if options.CheckTimeout > 0 && budget > options.CheckTimeout {
			budget = options.CheckTimeout
		}
	}
	if budget <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, budget)
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

func selectAddresses(addresses []net.IP, options model.DiagnoseOptions) ([]net.IP, int) {
	limit := options.AddressLimit
	if limit <= 0 {
		limit = 4
	}
	if options.ProbeMode == model.ProbeModeClientEffective && limit > 2 {
		limit = 2
	}
	if limit > len(addresses) {
		limit = len(addresses)
	}
	selected := cloneAddresses(addresses[:limit])
	if options.ProbeMode == model.ProbeModeClientEffective {
		return selected, 0
	}
	return selected, len(addresses) - limit
}

func cloneAddresses(addresses []net.IP) []net.IP {
	result := make([]net.IP, len(addresses))
	for index := range addresses {
		result[index] = append(net.IP(nil), addresses[index]...)
	}
	return result
}

func hasSelected(attempts []model.TCPAttempt) bool {
	for _, attempt := range attempts {
		if attempt.Selected {
			return true
		}
	}
	return false
}

func orderedAttempts(values map[int]model.TCPAttempt) []model.TCPAttempt {
	result := make([]model.TCPAttempt, 0, len(values))
	for index := 0; index < len(values); index++ {
		if attempt, ok := values[index]; ok {
			result = append(result, attempt)
		}
	}
	return result
}

func dialAddress(state *model.State, remote net.IP) string {
	host := remote.String()
	if state.Options.ConnectIP != "" {
		host = state.Options.ConnectIP
	} else if state.Target.Zone != "" && remote.Equal(net.ParseIP(state.Target.Host)) {
		host += "%" + state.Target.Zone
	}
	return net.JoinHostPort(host, strconv.Itoa(int(state.Target.Port)))
}

func (c *Check) result(
	attempts []model.TCPAttempt,
	total int,
	cancelled bool,
	mode model.ProbeMode,
) model.CheckResult {
	evidence := make([]model.Evidence, 0, len(attempts))
	refs := make([]model.NetworkRef, 0, len(attempts))
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
			ID:         fmt.Sprintf("tcp.%d", index),
			Code:       "TCP_ATTEMPT",
			Message:    message,
			NetworkRef: attempt.NetworkRef,
			Details:    details,
		})
		if attempt.NetworkRef != nil {
			refs = append(refs, *attempt.NetworkRef)
		}
	}

	if cancelled {
		neverStarted := total - len(attempts)
		if neverStarted < 0 {
			neverStarted = 0
		}
		return model.CheckResult{
			ID:          c.ID(),
			Name:        c.Name(),
			Status:      model.StatusCancelled,
			Summary:     fmt.Sprintf("TCP connection attempts were cancelled after %d of %d started attempt(s) completed; %d of %d address(es) were never started.", completed, len(attempts), neverStarted, total),
			Evidence:    evidence,
			NetworkRefs: refs,
			ErrorCode:   ErrorCancelled,
		}
	}
	if mode == model.ProbeModeClientEffective && selectedSuccess(attempts) {
		return model.CheckResult{
			ID: c.ID(), Name: c.Name(), Status: model.StatusPassed,
			Summary:  "The client-effective TCP probe selected a reachable backend address.",
			Evidence: evidence, NetworkRefs: refs,
		}
	}
	if successes == len(attempts) {
		return model.CheckResult{
			ID:          c.ID(),
			Name:        c.Name(),
			Status:      model.StatusPassed,
			Summary:     fmt.Sprintf("TCP connections succeeded for all %d address(es).", successes),
			Evidence:    evidence,
			NetworkRefs: refs,
		}
	}
	if successes > 0 {
		return model.CheckResult{
			ID:          c.ID(),
			Name:        c.Name(),
			Status:      model.StatusWarning,
			Summary:     fmt.Sprintf("TCP connected to %d of %d address(es).", successes, len(attempts)),
			Evidence:    evidence,
			NetworkRefs: refs,
			ErrorCode:   ErrorPartialFailure,
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
		ID:          c.ID(),
		Name:        c.Name(),
		Status:      model.StatusFailed,
		Summary:     summary,
		Evidence:    evidence,
		NetworkRefs: refs,
		ErrorCode:   code,
		Recommendations: []model.Recommendation{{
			ID:       "tcp.verify_service",
			Priority: "high",
			Message:  "Verify routing, packet filtering, and that the service is listening on the target port.",
		}},
	}
}

func selectedSuccess(attempts []model.TCPAttempt) bool {
	for _, attempt := range attempts {
		if attempt.Selected && attempt.Success {
			return true
		}
	}
	return false
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
