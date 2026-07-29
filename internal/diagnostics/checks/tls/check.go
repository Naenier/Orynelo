// Package tls diagnoses TLS negotiation and certificate verification while
// retaining peer metadata for actionable failures.
package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
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

func (*Check) ID() string   { return "tls" }
func (*Check) Name() string { return "TLS handshake and certificate" }

func (c *Check) Run(ctx context.Context, state *model.State) model.CheckResult {
	if !state.Target.UseTLS && !state.Options.EnableTLS {
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusSkipped,
			Summary: "TLS is not enabled for this target.",
		}
	}
	remote := firstReachable(state.TCP())
	if remote == nil {
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusSkipped,
			Summary: "TLS was skipped because no TCP connection succeeded.",
		}
	}

	address := net.JoinHostPort(remote.String(), strconv.Itoa(int(state.Target.Port)))
	started := c.now()
	connection, err := c.Dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		code := classifyHandshakeError(err)
		result := model.TLSResult{
			RemoteIP:   remote,
			ServerName: state.Target.ServerName(),
			Insecure:   state.Options.Insecure,
			Duration:   c.now().Sub(started),
			ErrorCode:  code,
			Error:      err.Error(),
		}
		state.SetTLS(result)
		return failure(c, result, "A TCP connection for TLS could not be established.")
	}
	defer connection.Close()

	config := &tls.Config{
		// Peer data is collected first and verified explicitly below. No
		// application bytes are sent before verification is evaluated.
		InsecureSkipVerify: true, //nolint:gosec // diagnostic metadata collection
		ServerName:         state.Target.ServerName(),
		NextProtos:         []string{"h2", "http/1.1"},
	}
	handshaker := c.Handshake
	if handshaker == nil {
		handshaker = handshake
	}
	connectionState, err := handshaker(ctx, connection, config)
	duration := c.now().Sub(started)
	if err != nil {
		code := classifyHandshakeError(err)
		result := model.TLSResult{
			RemoteIP:   remote,
			ServerName: config.ServerName,
			Insecure:   state.Options.Insecure,
			Duration:   duration,
			ErrorCode:  code,
			Error:      err.Error(),
		}
		state.SetTLS(result)
		return failure(c, result, handshakeSummary(code))
	}
	if len(connectionState.PeerCertificates) == 0 {
		result := model.TLSResult{
			RemoteIP:   remote,
			ServerName: config.ServerName,
			Insecure:   state.Options.Insecure,
			Duration:   duration,
			ErrorCode:  ErrorHandshake,
			Error:      "peer sent no certificates",
		}
		state.SetTLS(result)
		return failure(c, result, "The TLS peer did not provide a certificate.")
	}

	leaf := connectionState.PeerCertificates[0]
	now := c.now()
	certificate := model.CertificateInfo{
		Subject:       leaf.Subject.String(),
		Issuer:        leaf.Issuer.String(),
		SerialNumber:  leaf.SerialNumber.String(),
		DNSNames:      append([]string(nil), leaf.DNSNames...),
		NotBefore:     leaf.NotBefore,
		NotAfter:      leaf.NotAfter,
		Remaining:     leaf.NotAfter.Sub(now),
		ChainLength:   len(connectionState.PeerCertificates),
		HostnameValid: leaf.VerifyHostname(state.Target.Host) == nil,
	}
	for _, address := range leaf.IPAddresses {
		certificate.IPAddresses = append(certificate.IPAddresses, address.String())
	}

	trustErr := verifyTrust(connectionState.PeerCertificates, c.RootCAs, now)
	certificate.SystemTrusted = trustErr == nil
	hostnameErr := leaf.VerifyHostname(state.Target.Host)
	result := model.TLSResult{
		RemoteIP:    remote,
		ServerName:  config.ServerName,
		Version:     VersionName(connectionState.Version),
		CipherSuite: tls.CipherSuiteName(connectionState.CipherSuite),
		ALPN:        connectionState.NegotiatedProtocol,
		Certificate: certificate,
		Insecure:    state.Options.Insecure,
		Duration:    duration,
	}

	verificationErr := chooseVerificationError(leaf, now, trustErr, hostnameErr)
	if verificationErr != nil {
		result.ErrorCode = ClassifyVerificationError(verificationErr, leaf, now)
		result.Error = verificationErr.Error()
	}
	state.SetTLS(result)
	evidence := tlsEvidence(result)

	if state.Options.Insecure {
		summary := "TLS negotiation succeeded, but certificate verification is disabled."
		if result.ErrorCode != "" {
			summary += " The peer certificate would fail verification."
		}
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusWarning,
			Summary:   summary,
			Evidence:  evidence,
			ErrorCode: result.ErrorCode,
			Recommendations: []model.Recommendation{{
				ID:       "tls.enable_verification",
				Priority: "high",
				Message:  "Enable TLS verification before relying on this connection.",
			}},
		}
	}
	if verificationErr != nil {
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusFailed,
			Summary:   verificationSummary(result.ErrorCode),
			Evidence:  evidence,
			ErrorCode: result.ErrorCode,
			Recommendations: []model.Recommendation{{
				ID:       "tls.correct_certificate",
				Priority: "high",
				Message:  certificateRecommendation(result.ErrorCode),
			}},
		}
	}

	warningBefore := state.Options.CertificateWarningThreshold
	if c.WarningBefore > 0 {
		warningBefore = c.WarningBefore
	}
	if warningBefore > 0 && certificate.Remaining < warningBefore {
		return model.CheckResult{
			ID:       c.ID(),
			Name:     c.Name(),
			Status:   model.StatusWarning,
			Summary:  fmt.Sprintf("TLS verification succeeded, but the certificate expires in %s.", certificate.Remaining.Round(time.Hour)),
			Evidence: evidence,
			Recommendations: []model.Recommendation{{
				ID:       "tls.renew_soon",
				Priority: "medium",
				Message:  "Renew and deploy the certificate before it expires.",
			}},
		}
	}
	return model.CheckResult{
		ID:       c.ID(),
		Name:     c.Name(),
		Status:   model.StatusPassed,
		Summary:  "TLS negotiation, hostname validation, and system trust validation succeeded.",
		Evidence: evidence,
	}
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

func failure(c *Check, result model.TLSResult, summary string) model.CheckResult {
	status := model.StatusFailed
	if result.ErrorCode == ErrorCancelled {
		status = model.StatusCancelled
	}
	return model.CheckResult{
		ID:        c.ID(),
		Name:      c.Name(),
		Status:    status,
		Summary:   summary,
		ErrorCode: result.ErrorCode,
		Evidence: []model.Evidence{{
			ID:      "tls.failure",
			Code:    result.ErrorCode,
			Message: "TLS negotiation did not complete successfully.",
			Details: map[string]string{
				"remoteIp": result.RemoteIP.String(),
				"error":    result.Error,
				"duration": result.Duration.String(),
			},
		}},
	}
}

func tlsEvidence(result model.TLSResult) []model.Evidence {
	details := map[string]string{
		"remoteIp":      result.RemoteIP.String(),
		"sni":           result.ServerName,
		"version":       result.Version,
		"cipherSuite":   result.CipherSuite,
		"alpn":          result.ALPN,
		"subject":       result.Certificate.Subject,
		"issuer":        result.Certificate.Issuer,
		"serialNumber":  result.Certificate.SerialNumber,
		"notBefore":     result.Certificate.NotBefore.Format(time.RFC3339),
		"notAfter":      result.Certificate.NotAfter.Format(time.RFC3339),
		"remaining":     result.Certificate.Remaining.String(),
		"chainLength":   strconv.Itoa(result.Certificate.ChainLength),
		"hostnameValid": strconv.FormatBool(result.Certificate.HostnameValid),
		"systemTrusted": strconv.FormatBool(result.Certificate.SystemTrusted),
		"insecure":      strconv.FormatBool(result.Insecure),
		"dnsSANs":       strings.Join(result.Certificate.DNSNames, ", "),
		"ipSANs":        strings.Join(result.Certificate.IPAddresses, ", "),
	}
	if result.Error != "" {
		details["verificationError"] = result.Error
	}
	return []model.Evidence{{
		ID:      "tls.connection",
		Code:    "TLS_CONNECTION",
		Message: "TLS peer and certificate metadata were collected.",
		Details: details,
	}}
}

func firstReachable(attempts []model.TCPAttempt) net.IP {
	for _, attempt := range attempts {
		if attempt.Success {
			return append(net.IP(nil), attempt.RemoteIP...)
		}
	}
	return nil
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
