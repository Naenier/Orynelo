// Package tls diagnoses TLS negotiation and certificate verification while
// retaining peer metadata for actionable failures.
package tls

import (
	"context"
	"crypto/dsa" //nolint:staticcheck // x509 still decodes legacy DSA certificates; retain report-only key-size metadata.
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/trust"
)

const (
	ErrorExpired          = "TLS_CERTIFICATE_EXPIRED"
	ErrorNotYetValid      = "TLS_CERTIFICATE_NOT_YET_VALID"
	ErrorUnknownAuthority = "TLS_UNKNOWN_AUTHORITY"
	ErrorHostnameMismatch = "TLS_HOSTNAME_MISMATCH"
	ErrorHandshakeTimeout = "TLS_HANDSHAKE_TIMEOUT"
	ErrorProtocolMismatch = "TLS_PROTOCOL_MISMATCH"
	ErrorConnectionClosed = "TLS_CONNECTION_CLOSED"
	ErrorCancelled        = "TLS_CANCELLED"
	ErrorHandshake        = "TLS_HANDSHAKE_FAILED"
	ErrorPartialFailure   = "TLS_PARTIAL_FAILURE"
	ErrorCustomCA         = "TLS_CUSTOM_CA_INVALID"
)

const (
	directPathID = "path-direct"
	originHopID  = "hop-origin"
)

// Dialer establishes the raw transport used by the handshake.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// HandshakeFunc makes TLS negotiation replaceable in offline tests.
type HandshakeFunc func(context.Context, net.Conn, *tls.Config) (tls.ConnectionState, error)

// Check performs TLS handshake and explicit hostname/system-trust validation.
type Check struct {
	Dialer        Dialer
	Handshake     HandshakeFunc
	Now           func() time.Time
	WarningBefore time.Duration
	RootCAs       *x509.CertPool
}

// New constructs a TLS check.
func New(dialer Dialer) *Check {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	return &Check{
		Dialer:    dialer,
		Handshake: handshake,
		Now:       time.Now,
	}
}

// ID returns the stable diagnostic identifier.
func (*Check) ID() string { return "tls" }

// Name returns the human-readable check name.
func (*Check) Name() string { return "TLS handshake and certificate" }

// Run performs address-specific TLS handshakes and retains a selected legacy
// projection for readers written before matrix attempts were introduced.
func (c *Check) Run(ctx context.Context, state *model.State) model.CheckResult {
	if !state.Target.UseTLS && !state.Options.EnableTLS {
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusNotApplicable,
			Summary: "TLS is not enabled for this target.",
		}
	}

	candidates := selectCandidates(state.TCP(), state.Options)
	if len(candidates) == 0 {
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusSkipped,
			Summary: "TLS was skipped because no TCP connection succeeded.",
		}
	}

	roots, err := c.trustPool(state.Options)
	if err != nil {
		state.SetTLS(model.TLSResult{Insecure: state.Options.Insecure, ErrorCode: ErrorCustomCA})
		state.SetTLSAttempts(nil)
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusFailed,
			Summary:   "The configured custom CA bundle could not be used.",
			ErrorCode: ErrorCustomCA,
			Evidence: []model.Evidence{{
				ID:      "tls.custom_ca",
				Code:    ErrorCustomCA,
				Message: "Custom trust roots were rejected before a TLS connection was started.",
			}},
		}
	}

	outcomes := c.runAttempts(ctx, state, candidates, roots)
	attempts := make([]model.TLSAttempt, len(outcomes))
	for index := range outcomes {
		attempts[index] = outcomes[index].attempt
	}
	state.SetTLSAttempts(attempts)
	if len(attempts) > 0 {
		state.SetTLS(legacyTLSResult(selectedAttempt(attempts)))
	}
	recordTLSPath(state, attempts)
	return c.aggregateResult(ctx, state.Options, outcomes)
}

type tlsCandidate struct {
	tcp      model.TCPAttempt
	selected bool
}

type tlsOutcome struct {
	attempt           model.TLSAttempt
	expirationWarning bool
}

func selectCandidates(attempts []model.TCPAttempt, options model.DiagnoseOptions) []tlsCandidate {
	started := make([]model.TCPAttempt, 0, len(attempts))
	for _, attempt := range attempts {
		if attempt.RemoteIP != nil && attempt.State != model.AttemptStateQueued &&
			attempt.State != model.AttemptStateSkipped {
			started = append(started, attempt)
		}
	}
	if len(started) == 0 {
		return nil
	}
	if options.ProbeMode == model.ProbeModeAddressMatrix {
		limit := options.AddressLimit
		if limit <= 0 {
			limit = model.DefaultDiagnoseOptions("").AddressLimit
		}
		if len(started) > limit {
			started = started[:limit]
		}
		result := make([]tlsCandidate, len(started))
		for index, attempt := range started {
			result[index] = tlsCandidate{tcp: attempt, selected: attempt.Selected}
		}
		return result
	}
	successful := make([]model.TCPAttempt, 0, len(started))
	for _, attempt := range started {
		if attempt.Success {
			successful = append(successful, attempt)
		}
	}
	if len(successful) > 0 {
		for _, attempt := range successful {
			if attempt.Selected {
				return []tlsCandidate{{tcp: attempt, selected: true}}
			}
		}
		return []tlsCandidate{{tcp: successful[0], selected: true}}
	}
	return nil
}

func (c *Check) runAttempts(
	ctx context.Context,
	state *model.State,
	candidates []tlsCandidate,
	roots *x509.CertPool,
) []tlsOutcome {
	type slot struct {
		outcome tlsOutcome
		started bool
	}
	slots := make([]slot, len(candidates))
	jobs := make(chan int)
	workers := state.Options.MaxConcurrency
	if workers < 1 {
		workers = 1
	}
	if workers > len(candidates) {
		workers = len(candidates)
	}
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			for index := range jobs {
				slots[index] = slot{
					outcome: c.runAttempt(ctx, state, candidates[index], index, roots),
					started: true,
				}
			}
		}()
	}

sendLoop:
	for index := range candidates {
		select {
		case jobs <- index:
		case <-ctx.Done():
			break sendLoop
		}
	}
	close(jobs)
	wait.Wait()
	outcomes := make([]tlsOutcome, 0, len(candidates))
	for _, item := range slots {
		if item.started {
			outcomes = append(outcomes, item.outcome)
		}
	}
	return outcomes
}

func (c *Check) runAttempt(
	parent context.Context,
	state *model.State,
	candidate tlsCandidate,
	index int,
	roots *x509.CertPool,
) tlsOutcome {
	ref := model.NetworkRef{
		PathID:    directPathID,
		HopID:     originHopID,
		AttemptID: fmt.Sprintf("attempt-tls-%03d", index+1),
	}
	serverName := effectiveServerName(state.Target, state.Options)
	identity := effectiveLogicalIdentity(state.Target, state.Options)
	attempt := model.TLSAttempt{
		NetworkRef: ref,
		State:      model.AttemptStateRunning,
		RemoteIP:   append(net.IP(nil), candidate.tcp.RemoteIP...),
		ServerName: serverName,
		Selected:   candidate.selected,
		Insecure:   state.Options.Insecure,
		StartedAt:  c.now(),
	}

	attemptCtx := parent
	cancel := func() {}
	if budget := attemptBudget(state.Options); budget > 0 {
		attemptCtx, cancel = context.WithTimeout(parent, budget)
	}
	defer cancel()

	address := tlsDialAddress(candidate.tcp.RemoteIP, state.Target, state.Options)
	connection, err := c.Dialer.DialContext(attemptCtx, networkFor(candidate.tcp.RemoteIP), address)
	dialFinished := c.now()
	attempt.TCPDuration = nonNegative(dialFinished.Sub(attempt.StartedAt))
	if err != nil {
		finishFailedAttempt(&attempt, attemptCtx, c.now(), classifyHandshakeError(err), err)
		return tlsOutcome{attempt: attempt}
	}
	defer connection.Close()

	config := &tls.Config{
		// The peer chain is collected before explicit hostname and trust checks.
		// No application bytes are sent by this diagnostic connection.
		InsecureSkipVerify: true, //nolint:gosec // diagnostic metadata collection
		ServerName:         serverName,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	handshaker := c.Handshake
	if handshaker == nil {
		handshaker = handshake
	}
	handshakeStarted := c.now()
	connectionState, err := handshaker(attemptCtx, connection, config)
	handshakeFinished := c.now()
	attempt.HandshakeDuration = nonNegative(handshakeFinished.Sub(handshakeStarted))
	attempt.FinishedAt = handshakeFinished
	attempt.Duration = nonNegative(attempt.FinishedAt.Sub(attempt.StartedAt))
	attempt.State = model.AttemptStateCompleted
	if err != nil {
		finishFailedAttempt(&attempt, attemptCtx, handshakeFinished, classifyHandshakeError(err), err)
		return tlsOutcome{attempt: attempt}
	}
	if len(connectionState.PeerCertificates) == 0 {
		finishFailedAttempt(
			&attempt,
			attemptCtx,
			handshakeFinished,
			ErrorHandshake,
			errors.New("peer sent no certificates"),
		)
		return tlsOutcome{attempt: attempt}
	}

	now := c.now()
	leaf := connectionState.PeerCertificates[0]
	trustErr := verifyTrust(connectionState.PeerCertificates, roots, now)
	hostnameErr := leaf.VerifyHostname(identity)
	verificationErr := chooseVerificationError(leaf, now, trustErr, hostnameErr)
	chain := certificateChain(connectionState.PeerCertificates, now, identity, trustErr == nil)
	attempt.Version = VersionName(connectionState.Version)
	attempt.CipherSuite = tls.CipherSuiteName(connectionState.CipherSuite)
	attempt.ALPN = connectionState.NegotiatedProtocol
	attempt.Chain = chain
	attempt.Certificate = chain[0]
	attempt.Success = verificationErr == nil || state.Options.Insecure
	if verificationErr != nil {
		attempt.ErrorCode = ClassifyVerificationError(verificationErr, leaf, now)
		attempt.Error = verificationErr.Error()
	}
	warningBefore := state.Options.CertificateWarningThreshold
	if c.WarningBefore > 0 {
		warningBefore = c.WarningBefore
	}
	return tlsOutcome{
		attempt: attempt,
		expirationWarning: warningBefore > 0 &&
			attempt.Certificate.Remaining >= 0 &&
			attempt.Certificate.Remaining < warningBefore,
	}
}

func (c *Check) trustPool(options model.DiagnoseOptions) (*x509.CertPool, error) {
	if options.CustomCAConfigured && len(options.CustomCAPEM) == 0 {
		return nil, trust.ErrInvalidBundle
	}
	if c.RootCAs == nil {
		return trust.Pool(options.CustomCAPEM)
	}
	roots := c.RootCAs.Clone()
	if len(options.CustomCAPEM) == 0 {
		return roots, nil
	}
	if _, err := trust.Pool(options.CustomCAPEM); err != nil {
		return nil, err
	}
	if !roots.AppendCertsFromPEM(options.CustomCAPEM) {
		return nil, trust.ErrInvalidBundle
	}
	return roots, nil
}

func attemptBudget(options model.DiagnoseOptions) time.Duration {
	budget := options.CheckTimeout
	if options.ProbeMode == model.ProbeModeAddressMatrix && options.AddressMatrixBudget > 0 {
		limit := options.AddressLimit
		if limit < 1 {
			limit = 1
		}
		perAttempt := options.AddressMatrixBudget / time.Duration(limit)
		if perAttempt <= 0 {
			perAttempt = time.Nanosecond
		}
		if budget <= 0 || perAttempt < budget {
			budget = perAttempt
		}
	}
	return budget
}

func effectiveServerName(target model.Target, options model.DiagnoseOptions) string {
	if override := strings.TrimSpace(options.ServerName); override != "" {
		return strings.TrimSuffix(override, ".")
	}
	return target.ServerName()
}

func effectiveLogicalIdentity(target model.Target, options model.DiagnoseOptions) string {
	if override := strings.TrimSpace(options.ServerName); override != "" {
		return strings.TrimSuffix(override, ".")
	}
	return strings.TrimSuffix(target.Host, ".")
}

func tlsDialAddress(
	remote net.IP,
	target model.Target,
	options model.DiagnoseOptions,
) string {
	host := remote.String()
	if options.ConnectIP != "" {
		host = options.ConnectIP
	} else if target.Zone != "" && remote.Equal(net.ParseIP(target.Host)) {
		host += "%" + target.Zone
	}
	return net.JoinHostPort(host, strconv.Itoa(int(target.Port)))
}

func networkFor(remote net.IP) string {
	if remote.To4() != nil {
		return "tcp4"
	}
	return "tcp6"
}

func finishFailedAttempt(
	attempt *model.TLSAttempt,
	ctx context.Context,
	finished time.Time,
	code string,
	err error,
) {
	attempt.FinishedAt = finished
	attempt.Duration = nonNegative(finished.Sub(attempt.StartedAt))
	attempt.State = model.AttemptStateCompleted
	if errors.Is(ctx.Err(), context.Canceled) {
		attempt.State = model.AttemptStateCancelled
	}
	attempt.ErrorCode = code
	if err != nil {
		attempt.Error = err.Error()
	}
}

func nonNegative(value time.Duration) time.Duration {
	if value < 0 {
		return 0
	}
	return value
}

func handshake(ctx context.Context, raw net.Conn, config *tls.Config) (tls.ConnectionState, error) {
	connection := tls.Client(raw, config)
	if err := connection.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, err
	}
	return connection.ConnectionState(), nil
}

func verifyTrust(chain []*x509.Certificate, roots *x509.CertPool, now time.Time) error {
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		intermediates.AddCert(certificate)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
	})
	return err
}

func certificateChain(
	certificates []*x509.Certificate,
	now time.Time,
	identity string,
	trusted bool,
) []model.CertificateInfo {
	result := make([]model.CertificateInfo, 0, len(certificates))
	for index, certificate := range certificates {
		if certificate == nil {
			continue
		}
		info := model.CertificateInfo{
			Subject:            certificate.Subject.String(),
			Issuer:             certificate.Issuer.String(),
			SerialNumber:       certificate.SerialNumber.String(),
			DNSNames:           append([]string(nil), certificate.DNSNames...),
			NotBefore:          certificate.NotBefore,
			NotAfter:           certificate.NotAfter,
			Remaining:          certificate.NotAfter.Sub(now),
			ChainLength:        len(certificates),
			SystemTrusted:      trusted,
			PublicKeyAlgorithm: certificate.PublicKeyAlgorithm.String(),
			SignatureAlgorithm: certificate.SignatureAlgorithm.String(),
			IsCA:               certificate.IsCA,
		}
		if index == 0 {
			info.HostnameValid = certificate.VerifyHostname(identity) == nil
		}
		for _, address := range certificate.IPAddresses {
			info.IPAddresses = append(info.IPAddresses, address.String())
		}
		info.PublicKeyBits, info.PublicKeyCurve = publicKeyMetadata(certificate.PublicKey)
		result = append(result, info)
	}
	return result
}

func publicKeyMetadata(key any) (bits int, curve string) {
	switch key := key.(type) {
	case *rsa.PublicKey:
		if key != nil && key.N != nil {
			return key.N.BitLen(), ""
		}
	case *ecdsa.PublicKey:
		if key != nil && key.Curve != nil {
			if parameters := key.Params(); parameters != nil {
				return parameters.BitSize, parameters.Name
			}
		}
	case ed25519.PublicKey:
		return len(key) * 8, ""
	case *dsa.PublicKey:
		if key != nil && key.P != nil {
			return key.P.BitLen(), ""
		}
	case *ecdh.PublicKey:
		if key != nil {
			return len(key.Bytes()) * 8, fmt.Sprint(key.Curve())
		}
	}
	return 0, ""
}

func chooseVerificationError(leaf *x509.Certificate, now time.Time, trustErr, hostnameErr error) error {
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return trustErr
	}
	if hostnameErr != nil {
		return hostnameErr
	}
	return trustErr
}

// ClassifyVerificationError maps x509 failures to stable diagnostic codes.
func ClassifyVerificationError(err error, leaf *x509.Certificate, now time.Time) string {
	if leaf != nil {
		if now.Before(leaf.NotBefore) {
			return ErrorNotYetValid
		}
		if now.After(leaf.NotAfter) {
			return ErrorExpired
		}
	}
	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return ErrorHostnameMismatch
	}
	var authorityError x509.UnknownAuthorityError
	if errors.As(err, &authorityError) {
		return ErrorUnknownAuthority
	}
	var invalidError x509.CertificateInvalidError
	if errors.As(err, &invalidError) && invalidError.Reason == x509.Expired {
		if leaf != nil && now.Before(leaf.NotBefore) {
			return ErrorNotYetValid
		}
		return ErrorExpired
	}
	return ErrorHandshake
}

func classifyHandshakeError(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return ErrorCancelled
	case errors.Is(err, context.DeadlineExceeded):
		return ErrorHandshakeTimeout
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF),
		errors.Is(err, net.ErrClosed):
		return ErrorConnectionClosed
	}
	var netError net.Error
	if errors.As(err, &netError) && netError.Timeout() {
		return ErrorHandshakeTimeout
	}
	var recordError tls.RecordHeaderError
	if errors.As(err, &recordError) {
		return ErrorProtocolMismatch
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "first record does not look like a tls handshake") ||
		strings.Contains(message, "unsupported protocol") ||
		strings.Contains(message, "protocol version") {
		return ErrorProtocolMismatch
	}
	if strings.Contains(message, "closed") || strings.Contains(message, "reset by peer") {
		return ErrorConnectionClosed
	}
	return ErrorHandshake
}

func (c *Check) aggregateResult(
	ctx context.Context,
	options model.DiagnoseOptions,
	outcomes []tlsOutcome,
) model.CheckResult {
	result := model.CheckResult{ID: c.ID(), Name: c.Name()}
	if len(outcomes) == 0 {
		result.Status = model.StatusCancelled
		result.Summary = "TLS was cancelled before an address-specific attempt started."
		result.ErrorCode = ErrorCancelled
		return result
	}

	succeeded := 0
	expiring := 0
	cancelled := 0
	for index, outcome := range outcomes {
		attempt := outcome.attempt
		result.NetworkRefs = append(result.NetworkRefs, attempt.NetworkRef)
		result.Evidence = append(result.Evidence, tlsAttemptEvidence(attempt, index))
		if attempt.Success {
			succeeded++
		}
		if outcome.expirationWarning && attempt.Success {
			expiring++
		}
		if attempt.State == model.AttemptStateCancelled || attempt.ErrorCode == ErrorCancelled {
			cancelled++
		}
	}

	switch {
	case succeeded == 0:
		result.ErrorCode = commonAttemptError(outcomes)
		result.Status = model.StatusFailed
		if cancelled == len(outcomes) && errors.Is(ctx.Err(), context.Canceled) {
			result.Status = model.StatusCancelled
			result.ErrorCode = ErrorCancelled
			result.Summary = "All TLS attempts were cancelled."
		} else if len(outcomes) == 1 {
			result.Summary = attemptFailureSummary(result.ErrorCode)
		} else {
			result.Summary = fmt.Sprintf(
				"TLS failed for all %d selected backend address(es).",
				len(outcomes),
			)
		}
		result.Recommendations = []model.Recommendation{{
			ID:       "tls.inspect_failures",
			Priority: "high",
			Message:  certificateRecommendation(result.ErrorCode),
		}}
	case succeeded < len(outcomes):
		result.Status = model.StatusWarning
		result.ErrorCode = ErrorPartialFailure
		result.Summary = fmt.Sprintf(
			"TLS succeeded for %d of %d selected backend address(es).",
			succeeded,
			len(outcomes),
		)
		result.Recommendations = []model.Recommendation{{
			ID:       "tls.investigate_partial",
			Priority: "high",
			Message:  "Compare certificate and TLS configuration across the failing backend addresses.",
		}}
	case options.Insecure:
		result.Status = model.StatusWarning
		result.Summary = "TLS negotiation succeeded, but certificate verification is disabled."
		result.Recommendations = []model.Recommendation{{
			ID:       "tls.enable_verification",
			Priority: "high",
			Message:  "Enable TLS verification before relying on this connection.",
		}}
	case expiring > 0:
		result.Status = model.StatusWarning
		result.Summary = fmt.Sprintf(
			"TLS verification succeeded, but %d selected certificate(s) approach expiration.",
			expiring,
		)
		result.Recommendations = []model.Recommendation{{
			ID:       "tls.renew_soon",
			Priority: "medium",
			Message:  "Renew and deploy the affected certificate before it expires.",
		}}
	default:
		result.Status = model.StatusPassed
		result.Summary = fmt.Sprintf(
			"TLS negotiation, hostname validation, and trust validation succeeded for %d selected backend address(es).",
			succeeded,
		)
	}
	return result
}

func tlsAttemptEvidence(attempt model.TLSAttempt, index int) model.Evidence {
	details := map[string]string{
		"remoteIp":          attempt.RemoteIP.String(),
		"sni":               attempt.ServerName,
		"version":           attempt.Version,
		"cipherSuite":       attempt.CipherSuite,
		"alpn":              attempt.ALPN,
		"subject":           attempt.Certificate.Subject,
		"issuer":            attempt.Certificate.Issuer,
		"serialNumber":      attempt.Certificate.SerialNumber,
		"notBefore":         formatCertificateTime(attempt.Certificate.NotBefore),
		"notAfter":          formatCertificateTime(attempt.Certificate.NotAfter),
		"remaining":         attempt.Certificate.Remaining.String(),
		"chainLength":       strconv.Itoa(len(attempt.Chain)),
		"hostnameValid":     strconv.FormatBool(attempt.Certificate.HostnameValid),
		"systemTrusted":     strconv.FormatBool(attempt.Certificate.SystemTrusted),
		"insecure":          strconv.FormatBool(attempt.Insecure),
		"dnsSANs":           strings.Join(attempt.Certificate.DNSNames, ", "),
		"ipSANs":            strings.Join(attempt.Certificate.IPAddresses, ", "),
		"publicKey":         attempt.Certificate.PublicKeyAlgorithm,
		"publicKeyBits":     strconv.Itoa(attempt.Certificate.PublicKeyBits),
		"publicKeyCurve":    attempt.Certificate.PublicKeyCurve,
		"signature":         attempt.Certificate.SignatureAlgorithm,
		"tcpDuration":       attempt.TCPDuration.String(),
		"handshakeDuration": attempt.HandshakeDuration.String(),
		"totalDuration":     attempt.Duration.String(),
		"selected":          strconv.FormatBool(attempt.Selected),
	}
	for chainIndex, certificate := range attempt.Chain {
		prefix := fmt.Sprintf("chain.%d.", chainIndex)
		details[prefix+"subject"] = certificate.Subject
		details[prefix+"issuer"] = certificate.Issuer
		details[prefix+"dnsSANs"] = strings.Join(certificate.DNSNames, ", ")
		details[prefix+"ipSANs"] = strings.Join(certificate.IPAddresses, ", ")
		details[prefix+"publicKey"] = certificate.PublicKeyAlgorithm
		details[prefix+"publicKeyBits"] = strconv.Itoa(certificate.PublicKeyBits)
		details[prefix+"publicKeyCurve"] = certificate.PublicKeyCurve
		details[prefix+"signature"] = certificate.SignatureAlgorithm
		details[prefix+"isCA"] = strconv.FormatBool(certificate.IsCA)
		details[prefix+"notBefore"] = formatCertificateTime(certificate.NotBefore)
		details[prefix+"notAfter"] = formatCertificateTime(certificate.NotAfter)
	}
	if attempt.Error != "" {
		details["verificationError"] = attempt.Error
	}
	ref := attempt.NetworkRef
	code := "TLS_CONNECTION"
	message := "TLS peer and certificate metadata were collected."
	if attempt.ErrorCode != "" {
		code = attempt.ErrorCode
		message = "The address-specific TLS attempt recorded a failure."
	}
	id := "tls.connection"
	if index > 0 {
		id = fmt.Sprintf("tls.connection.%03d", index+1)
	}
	return model.Evidence{
		ID:         id,
		NetworkRef: &ref,
		Code:       code,
		Message:    message,
		Details:    details,
	}
}

func formatCertificateTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func commonAttemptError(outcomes []tlsOutcome) string {
	code := ""
	for _, outcome := range outcomes {
		candidate := outcome.attempt.ErrorCode
		if candidate == "" {
			candidate = ErrorHandshake
		}
		if code == "" {
			code = candidate
			continue
		}
		if code != candidate {
			return ErrorHandshake
		}
	}
	if code == "" {
		return ErrorHandshake
	}
	return code
}

func attemptFailureSummary(code string) string {
	switch code {
	case ErrorExpired, ErrorNotYetValid, ErrorUnknownAuthority, ErrorHostnameMismatch:
		return verificationSummary(code)
	default:
		return handshakeSummary(code)
	}
}

func selectedAttempt(attempts []model.TLSAttempt) model.TLSAttempt {
	for _, attempt := range attempts {
		if attempt.Selected {
			return attempt
		}
	}
	for _, attempt := range attempts {
		if attempt.Success {
			return attempt
		}
	}
	return attempts[0]
}

func legacyTLSResult(attempt model.TLSAttempt) model.TLSResult {
	ref := attempt.NetworkRef
	return model.TLSResult{
		NetworkRef:        &ref,
		RemoteIP:          append(net.IP(nil), attempt.RemoteIP...),
		ServerName:        attempt.ServerName,
		Version:           attempt.Version,
		CipherSuite:       attempt.CipherSuite,
		ALPN:              attempt.ALPN,
		Certificate:       attempt.Certificate,
		Chain:             append([]model.CertificateInfo(nil), attempt.Chain...),
		Insecure:          attempt.Insecure,
		Duration:          attempt.Duration,
		TCPDuration:       attempt.TCPDuration,
		HandshakeDuration: attempt.HandshakeDuration,
		ErrorCode:         attempt.ErrorCode,
		Error:             attempt.Error,
	}
}

func recordTLSPath(state *model.State, attempts []model.TLSAttempt) {
	if len(attempts) == 0 {
		return
	}
	paths := state.NetworkPaths()
	pathIndex := -1
	for index := range paths {
		if paths[index].ID == directPathID {
			pathIndex = index
			break
		}
	}
	if pathIndex < 0 {
		role := model.NetworkPathRoleClientEffective
		if state.Options.ProbeMode == model.ProbeModeAddressMatrix {
			role = model.NetworkPathRoleAddressMatrix
		}
		paths = append(paths, model.NetworkPath{
			ID: directPathID, Role: role, Kind: model.NetworkPathDirect,
			Sequence: len(paths),
		})
		pathIndex = len(paths) - 1
	}
	path := &paths[pathIndex]
	hopIndex := -1
	for index := range path.Hops {
		if path.Hops[index].ID == originHopID {
			hopIndex = index
			break
		}
	}
	if hopIndex < 0 {
		path.Hops = append(path.Hops, model.NetworkHop{
			ID:       originHopID,
			PathID:   directPathID,
			Sequence: len(path.Hops),
			Kind:     model.NetworkHopOrigin,
			URL:      state.Target.Normalized,
			Scheme:   state.Target.Scheme,
			Host:     state.Target.Host,
			Port:     state.Target.Port,
			Zone:     state.Target.Zone,
		})
		hopIndex = len(path.Hops) - 1
	}
	hop := &path.Hops[hopIndex]
	keptAttempts := hop.Attempts[:0]
	for _, attempt := range hop.Attempts {
		if attempt.Kind != model.NetworkAttemptTLS {
			keptAttempts = append(keptAttempts, attempt)
		}
	}
	hop.Attempts = keptAttempts
	keptTimings := hop.Timings[:0]
	for _, timing := range hop.Timings {
		if !strings.HasPrefix(timing.AttemptID, "attempt-tls-") {
			keptTimings = append(keptTimings, timing)
		}
	}
	hop.Timings = keptTimings
	selected := selectedAttempt(attempts)
	hop.SelectedAttemptID = selected.AttemptID
	for _, attempt := range attempts {
		hop.Attempts = append(hop.Attempts, model.NetworkAttempt{
			ID:         attempt.AttemptID,
			PathID:     attempt.PathID,
			HopID:      attempt.HopID,
			Kind:       model.NetworkAttemptTLS,
			State:      attempt.State,
			Network:    networkFor(attempt.RemoteIP),
			RemoteIP:   append(net.IP(nil), attempt.RemoteIP...),
			RemoteAddr: tlsDialAddress(attempt.RemoteIP, state.Target, state.Options),
			StartedAt:  attempt.StartedAt,
			FinishedAt: attempt.FinishedAt,
			Duration:   attempt.Duration,
			Selected:   attempt.AttemptID == selected.AttemptID,
			ErrorCode:  attempt.ErrorCode,
			Error:      attempt.Error,
		})
		tcpFinished := attempt.StartedAt.Add(attempt.TCPDuration)
		hop.Timings = append(hop.Timings,
			model.PhaseTiming{
				NetworkRef: attempt.NetworkRef,
				Phase:      "tcp",
				StartedAt:  attempt.StartedAt,
				FinishedAt: tcpFinished,
				Duration:   attempt.TCPDuration,
			},
			model.PhaseTiming{
				NetworkRef: attempt.NetworkRef,
				Phase:      "tls_handshake",
				StartedAt:  tcpFinished,
				FinishedAt: tcpFinished.Add(attempt.HandshakeDuration),
				Duration:   attempt.HandshakeDuration,
			},
			model.PhaseTiming{
				NetworkRef: attempt.NetworkRef,
				Phase:      "total",
				StartedAt:  attempt.StartedAt,
				FinishedAt: attempt.FinishedAt,
				Duration:   attempt.Duration,
			},
		)
	}
	state.SetNetworkPaths(paths)
}

// VersionName returns a stable readable TLS version.
func VersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}

func handshakeSummary(code string) string {
	switch code {
	case ErrorHandshakeTimeout:
		return "The TLS handshake timed out."
	case ErrorProtocolMismatch:
		return "The peer did not negotiate a compatible TLS protocol."
	case ErrorConnectionClosed:
		return "The peer closed the connection during the TLS handshake."
	case ErrorCancelled:
		return "The TLS handshake was cancelled."
	default:
		return "The TLS handshake failed."
	}
}

func verificationSummary(code string) string {
	switch code {
	case ErrorExpired:
		return "The TLS certificate has expired."
	case ErrorNotYetValid:
		return "The TLS certificate is not yet valid."
	case ErrorUnknownAuthority:
		return "The TLS certificate chain is not trusted by the system."
	case ErrorHostnameMismatch:
		return "The TLS certificate is not valid for the target hostname."
	default:
		return "TLS certificate verification failed."
	}
}

func certificateRecommendation(code string) string {
	switch code {
	case ErrorExpired, ErrorNotYetValid:
		return "Check system time and deploy a certificate with a valid time window."
	case ErrorUnknownAuthority:
		return "Deploy a chain anchored in an intended trust root, including required intermediate certificates."
	case ErrorHostnameMismatch:
		return "Use the intended hostname or deploy a certificate whose SAN covers this target."
	default:
		return "Inspect the peer certificate chain and TLS endpoint configuration."
	}
}

func (c *Check) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
