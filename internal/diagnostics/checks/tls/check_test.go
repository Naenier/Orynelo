package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

func TestClassifyVerificationError(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	valid := &x509.Certificate{
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
	}
	tests := []struct {
		name string
		err  error
		leaf *x509.Certificate
		code string
	}{
		{
			name: "expired",
			err:  errors.New("expired"),
			leaf: &x509.Certificate{NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)},
			code: ErrorExpired,
		},
		{
			name: "not yet valid",
			err:  errors.New("not yet valid"),
			leaf: &x509.Certificate{NotBefore: now.Add(time.Hour), NotAfter: now.Add(2 * time.Hour)},
			code: ErrorNotYetValid,
		},
		{
			name: "hostname",
			err:  x509.HostnameError{Certificate: valid, Host: "other.example"},
			leaf: valid,
			code: ErrorHostnameMismatch,
		},
		{
			name: "authority",
			err:  x509.UnknownAuthorityError{Cert: valid},
			leaf: valid,
			code: ErrorUnknownAuthority,
		},
		{
			name: "other",
			err:  errors.New("other"),
			leaf: valid,
			code: ErrorHandshake,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := ClassifyVerificationError(test.err, test.leaf, now); got != test.code {
				t.Fatalf("ClassifyVerificationError() = %q, want %q", got, test.code)
			}
		})
	}
}

func TestClassifyHandshakeError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err  error
		code string
	}{
		{context.Canceled, ErrorCancelled},
		{context.DeadlineExceeded, ErrorHandshakeTimeout},
		{io.EOF, ErrorConnectionClosed},
		{cryptotls.RecordHeaderError{}, ErrorProtocolMismatch},
		{errors.New("remote error: unsupported protocol"), ErrorProtocolMismatch},
		{errors.New("other"), ErrorHandshake},
	}
	for _, test := range tests {
		if got := classifyHandshakeError(test.err); got != test.code {
			t.Errorf("classifyHandshakeError(%v) = %q, want %q", test.err, got, test.code)
		}
	}
}

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func TestCheckDistinguishesNotApplicableFromMissingPrerequisite(t *testing.T) {
	t.Parallel()
	check := New(nil)

	notApplicable := model.NewState(
		model.Target{Kind: model.TargetHTTP, UseTLS: false},
		model.DefaultDiagnoseOptions("http://example.test"),
	)
	if result := check.Run(context.Background(), notApplicable); result.Status != model.StatusNotApplicable {
		t.Fatalf("disabled TLS status = %q, want not_applicable", result.Status)
	}

	missingTCP := model.NewState(
		model.Target{Kind: model.TargetHTTP, UseTLS: true},
		model.DefaultDiagnoseOptions("https://example.test"),
	)
	if result := check.Run(context.Background(), missingTCP); result.Status != model.StatusSkipped {
		t.Fatalf("missing-prerequisite TLS status = %q, want skipped", result.Status)
	}
}

func TestCheckVerifiedCertificate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	certificate := makeCertificate(t, now)
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	check := New(dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _ = server.Close() }()
		return client, nil
	}))
	check.Now = func() time.Time { return now }
	check.RootCAs = roots
	check.Handshake = func(context.Context, net.Conn, *cryptotls.Config) (cryptotls.ConnectionState, error) {
		return cryptotls.ConnectionState{
			Version:            cryptotls.VersionTLS13,
			CipherSuite:        cryptotls.TLS_AES_128_GCM_SHA256,
			NegotiatedProtocol: "h2",
			PeerCertificates:   []*x509.Certificate{certificate},
		}, nil
	}
	options := model.DefaultDiagnoseOptions("https://example.com")
	state := model.NewState(model.Target{
		Kind: model.TargetHTTP, UseTLS: true, Host: "example.com", Port: 443,
	}, options)
	state.SetTCP([]model.TCPAttempt{{RemoteIP: net.ParseIP("192.0.2.1"), Success: true}})
	result := check.Run(context.Background(), state)
	if result.Status != model.StatusPassed {
		t.Fatalf("result = %#v", result)
	}
	tlsResult := state.TLS()
	if !tlsResult.Certificate.HostnameValid || !tlsResult.Certificate.SystemTrusted ||
		tlsResult.Version != "TLS 1.3" {
		t.Fatalf("TLS result = %#v", tlsResult)
	}
	details := result.Evidence[0].Details
	if details["dnsSANs"] != "example.com" || details["ipSANs"] != "192.0.2.10" {
		t.Fatalf("SAN evidence = %#v", details)
	}
	check.WarningBefore = 100 * 24 * time.Hour
	result = check.Run(context.Background(), state)
	if result.Status != model.StatusWarning {
		t.Fatalf("WarningBefore override result = %#v", result)
	}
}

func TestCheckVerificationFailures(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		dnsNames  []string
		notBefore time.Time
		notAfter  time.Time
		trust     bool
		wantCode  string
	}{
		{
			name:      "expired",
			dnsNames:  []string{"example.com"},
			notBefore: now.Add(-48 * time.Hour),
			notAfter:  now.Add(-time.Hour),
			trust:     true,
			wantCode:  ErrorExpired,
		},
		{
			name:      "hostname mismatch",
			dnsNames:  []string{"other.example"},
			notBefore: now.Add(-time.Hour),
			notAfter:  now.Add(24 * time.Hour),
			trust:     true,
			wantCode:  ErrorHostnameMismatch,
		},
		{
			name:      "unknown authority",
			dnsNames:  []string{"example.com"},
			notBefore: now.Add(-time.Hour),
			notAfter:  now.Add(24 * time.Hour),
			trust:     false,
			wantCode:  ErrorUnknownAuthority,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			certificate := makeCertificateWithValidity(
				t,
				test.dnsNames,
				test.notBefore,
				test.notAfter,
			)
			roots := x509.NewCertPool()
			if test.trust {
				roots.AddCert(certificate)
			}
			check := New(dialerFunc(func(context.Context, string, string) (net.Conn, error) {
				client, server := net.Pipe()
				go func() { _ = server.Close() }()
				return client, nil
			}))
			check.Now = func() time.Time { return now }
			check.RootCAs = roots
			check.Handshake = func(
				context.Context,
				net.Conn,
				*cryptotls.Config,
			) (cryptotls.ConnectionState, error) {
				return cryptotls.ConnectionState{
					Version:          cryptotls.VersionTLS13,
					CipherSuite:      cryptotls.TLS_AES_128_GCM_SHA256,
					PeerCertificates: []*x509.Certificate{certificate},
				}, nil
			}
			state := model.NewState(model.Target{
				Kind: model.TargetHTTP, UseTLS: true, Host: "example.com", Port: 443,
			}, model.DefaultDiagnoseOptions("https://example.com"))
			state.SetTCP([]model.TCPAttempt{{
				RemoteIP: net.ParseIP("192.0.2.1"),
				Success:  true,
			}})

			result := check.Run(context.Background(), state)
			if result.Status != model.StatusFailed || result.ErrorCode != test.wantCode {
				t.Fatalf("Check.Run() = %#v, want failed %s", result, test.wantCode)
			}
			if state.TLS().ErrorCode != test.wantCode {
				t.Fatalf("stored TLS result = %#v", state.TLS())
			}
		})
	}
}

func TestVersionName(t *testing.T) {
	t.Parallel()
	if VersionName(cryptotls.VersionTLS12) != "TLS 1.2" ||
		VersionName(0x9999) != "unknown (0x9999)" {
		t.Fatal("unexpected TLS version name")
	}
}

func makeCertificate(t *testing.T, now time.Time) *x509.Certificate {
	t.Helper()
	return makeCertificateWithValidity(
		t,
		[]string{"example.com"},
		now.Add(-time.Hour),
		now.Add(90*24*time.Hour),
	)
}

func makeCertificateWithValidity(
	t *testing.T,
	dnsNames []string,
	notBefore time.Time,
	notAfter time.Time,
) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		DNSNames:              append([]string(nil), dnsNames...),
		IPAddresses:           []net.IP{net.ParseIP("192.0.2.10")},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
