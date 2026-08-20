package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

func TestCheckClientEffectiveUsesSelectedTCPAttempt(t *testing.T) {
	base := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	certificate := makeCertificate(t, base)
	roots := x509.NewCertPool()
	roots.AddCert(certificate)

	var dialAddress string
	check := New(dialerFunc(func(_ context.Context, _, address string) (net.Conn, error) {
		dialAddress = address
		client, server := net.Pipe()
		go func() { _ = server.Close() }()
		return client, nil
	}))
	check.RootCAs = roots
	var clockMu sync.Mutex
	clockTick := 0
	check.Now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		value := base.Add(time.Duration(clockTick) * time.Millisecond)
		clockTick++
		return value
	}
	var receivedServerName string
	check.Handshake = func(
		_ context.Context,
		_ net.Conn,
		config *cryptotls.Config,
	) (cryptotls.ConnectionState, error) {
		receivedServerName = config.ServerName
		return successfulConnectionState(certificate), nil
	}

	state := model.NewState(model.Target{
		Normalized: "https://example.com/",
		Scheme:     "https",
		Host:       "example.com",
		Port:       443,
		Kind:       model.TargetHTTP,
		Mode:       model.TargetModeHTTPS,
		UseTLS:     true,
	}, model.DefaultDiagnoseOptions("https://example.com"))
	state.SetTCP([]model.TCPAttempt{
		{RemoteIP: net.ParseIP("192.0.2.1"), Success: true},
		{RemoteIP: net.ParseIP("192.0.2.2"), Success: true, Selected: true},
		{RemoteIP: net.ParseIP("192.0.2.3"), Success: true},
	})

	result := check.Run(context.Background(), state)
	if result.Status != model.StatusPassed {
		t.Fatalf("Check.Run() = %#v, want passed", result)
	}
	if dialAddress != "192.0.2.2:443" {
		t.Fatalf("dial address = %q, want selected TCP address", dialAddress)
	}
	if receivedServerName != "example.com" {
		t.Fatalf("SNI = %q, want example.com", receivedServerName)
	}

	attempts := state.TLSAttempts()
	if len(attempts) != 1 {
		t.Fatalf("TLS attempts = %#v, want one client-effective attempt", attempts)
	}
	attempt := attempts[0]
	if attempt.PathID != directPathID || attempt.HopID != originHopID ||
		attempt.AttemptID != "attempt-tls-001" || !attempt.Selected {
		t.Fatalf("TLS correlation = %#v", attempt.NetworkRef)
	}
	if attempt.TCPDuration != time.Millisecond ||
		attempt.HandshakeDuration != time.Millisecond ||
		attempt.Duration != 3*time.Millisecond {
		t.Fatalf("split durations = tcp %s, handshake %s, total %s",
			attempt.TCPDuration, attempt.HandshakeDuration, attempt.Duration)
	}
	legacy := state.TLS()
	if legacy.NetworkRef == nil || legacy.NetworkRef.AttemptID != attempt.AttemptID ||
		!legacy.RemoteIP.Equal(net.ParseIP("192.0.2.2")) {
		t.Fatalf("legacy selected projection = %#v", legacy)
	}
	paths := state.NetworkPaths()
	if len(paths) != 1 || len(paths[0].Hops) != 1 ||
		paths[0].Hops[0].SelectedAttemptID != attempt.AttemptID {
		t.Fatalf("TLS network path = %#v", paths)
	}
}

type addressedConn struct {
	net.Conn
	address string
}

func TestCheckAddressMatrixIsStableBoundedAndReportsPartialFailure(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	certificate := makeCertificate(t, now)
	roots := x509.NewCertPool()
	roots.AddCert(certificate)

	check := New(dialerFunc(func(_ context.Context, _, address string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _ = server.Close() }()
		return &addressedConn{Conn: client, address: address}, nil
	}))
	check.Now = func() time.Time { return now }
	check.RootCAs = roots
	var active atomic.Int32
	var maximum atomic.Int32
	var deadlines atomic.Int32
	check.Handshake = func(
		ctx context.Context,
		connection net.Conn,
		_ *cryptotls.Config,
	) (cryptotls.ConnectionState, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		if _, ok := ctx.Deadline(); ok {
			deadlines.Add(1)
		}
		time.Sleep(5 * time.Millisecond)
		if strings.HasPrefix(connection.(*addressedConn).address, "192.0.2.2:") {
			return cryptotls.ConnectionState{}, errors.New("backend handshake failed")
		}
		return successfulConnectionState(certificate), nil
	}

	options := model.DefaultDiagnoseOptions("https://example.com")
	options.ProbeMode = model.ProbeModeAddressMatrix
	options.AddressLimit = 3
	options.MaxConcurrency = 2
	options.CheckTimeout = 500 * time.Millisecond
	options.AddressMatrixBudget = 50 * time.Millisecond
	state := model.NewState(model.Target{
		Scheme: "https", Host: "example.com", Port: 443,
		Kind: model.TargetHTTP, Mode: model.TargetModeHTTPS, UseTLS: true,
	}, options)
	state.SetTCP([]model.TCPAttempt{
		{RemoteIP: net.ParseIP("192.0.2.1"), Success: true},
		{RemoteIP: net.ParseIP("192.0.2.2"), Success: false},
		{RemoteIP: net.ParseIP("192.0.2.3"), Success: true, Selected: true},
		{RemoteIP: net.ParseIP("192.0.2.4"), Success: true},
	})

	result := check.Run(context.Background(), state)
	if result.Status != model.StatusWarning || result.ErrorCode != ErrorPartialFailure {
		t.Fatalf("Check.Run() = %#v, want partial failure warning", result)
	}
	attempts := state.TLSAttempts()
	if len(attempts) != 3 {
		t.Fatalf("attempt count = %d, want address limit 3", len(attempts))
	}
	for index, attempt := range attempts {
		wantIP := net.ParseIP("192.0.2." + big.NewInt(int64(index+1)).String())
		wantID := "attempt-tls-00" + big.NewInt(int64(index+1)).String()
		if !attempt.RemoteIP.Equal(wantIP) || attempt.AttemptID != wantID {
			t.Fatalf("attempt[%d] = %#v, want %s/%s", index, attempt, wantIP, wantID)
		}
	}
	if attempts[1].ErrorCode != ErrorHandshake || attempts[1].Success {
		t.Fatalf("failing backend attempt = %#v", attempts[1])
	}
	if !state.TLS().RemoteIP.Equal(net.ParseIP("192.0.2.3")) {
		t.Fatalf("legacy projection did not retain selected successful backend: %#v", state.TLS())
	}
	if maximum.Load() > 2 {
		t.Fatalf("maximum TLS concurrency = %d, want <= 2", maximum.Load())
	}
	if deadlines.Load() != 3 {
		t.Fatalf("attempt contexts with deadlines = %d, want 3", deadlines.Load())
	}
}

func TestCheckCustomCAExtendsTrustAndRecordsFullChain(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	leaf, root, bundle := makeCertificateChain(t, now, "node.example.net")
	check := New(dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _ = server.Close() }()
		return client, nil
	}))
	check.Now = func() time.Time { return now }
	var receivedServerName string
	check.Handshake = func(
		_ context.Context,
		_ net.Conn,
		config *cryptotls.Config,
	) (cryptotls.ConnectionState, error) {
		receivedServerName = config.ServerName
		state := successfulConnectionState(leaf)
		state.PeerCertificates = []*x509.Certificate{leaf, root}
		return state, nil
	}

	options := model.DefaultDiagnoseOptions("https://service.invalid")
	options.ServerName = "node.example.net"
	options.CustomCAConfigured = true
	options.CustomCAPEM = bundle
	state := model.NewState(model.Target{
		Scheme: "https", Host: "service.invalid", Port: 443,
		Kind: model.TargetHTTP, Mode: model.TargetModeHTTPS, UseTLS: true,
	}, options)
	state.SetTCP([]model.TCPAttempt{{
		RemoteIP: net.ParseIP("192.0.2.20"), Success: true, Selected: true,
	}})

	result := check.Run(context.Background(), state)
	if result.Status != model.StatusPassed {
		t.Fatalf("Check.Run() = %#v, want custom-CA verification success", result)
	}
	if receivedServerName != "node.example.net" {
		t.Fatalf("effective SNI = %q", receivedServerName)
	}
	attempt := state.TLSAttempts()[0]
	if len(attempt.Chain) != 2 || attempt.Certificate.IsCA || !attempt.Chain[1].IsCA {
		t.Fatalf("certificate chain metadata = %#v", attempt.Chain)
	}
	if !attempt.Certificate.HostnameValid || !attempt.Certificate.SystemTrusted ||
		attempt.Certificate.PublicKeyAlgorithm != "ECDSA" ||
		attempt.Certificate.PublicKeyBits != 256 ||
		attempt.Certificate.PublicKeyCurve != "P-256" ||
		attempt.Certificate.SignatureAlgorithm == "" {
		t.Fatalf("leaf certificate metadata = %#v", attempt.Certificate)
	}
}

func TestCheckRejectsInvalidCustomCABeforeDial(t *testing.T) {
	var dialed atomic.Bool
	check := New(dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, errors.New("must not dial")
	}))
	options := model.DefaultDiagnoseOptions("https://example.com")
	options.CustomCAConfigured = true
	options.CustomCAPEM = []byte("not a PEM certificate")
	state := model.NewState(model.Target{
		Host: "example.com", Port: 443, Kind: model.TargetHTTP, UseTLS: true,
	}, options)
	state.SetTCP([]model.TCPAttempt{{RemoteIP: net.ParseIP("192.0.2.1"), Success: true}})

	result := check.Run(context.Background(), state)
	if result.Status != model.StatusFailed || result.ErrorCode != ErrorCustomCA {
		t.Fatalf("Check.Run() = %#v, want custom CA failure", result)
	}
	if dialed.Load() {
		t.Fatal("TLS dial started despite an invalid custom CA bundle")
	}
}

func successfulConnectionState(certificate *x509.Certificate) cryptotls.ConnectionState {
	return cryptotls.ConnectionState{
		Version:            cryptotls.VersionTLS13,
		CipherSuite:        cryptotls.TLS_AES_128_GCM_SHA256,
		NegotiatedProtocol: "h2",
		PeerCertificates:   []*x509.Certificate{certificate},
	}
}

func TestMatrixAttemptBudgetDoesNotExceedConfiguredShare(t *testing.T) {
	t.Parallel()
	options := model.DefaultDiagnoseOptions("tls://example.test:443")
	options.ProbeMode = model.ProbeModeAddressMatrix
	options.AddressLimit = 4
	options.AddressMatrixBudget = 40 * time.Millisecond
	options.CheckTimeout = time.Second
	if got := attemptBudget(options); got != 10*time.Millisecond {
		t.Fatalf("attemptBudget() = %s, want 10ms", got)
	}
}

func makeCertificateChain(
	t *testing.T,
	now time.Time,
	serverName string,
) (*x509.Certificate, *x509.Certificate, []byte) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Orynelo Test Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(
		rand.Reader,
		rootTemplate,
		rootTemplate,
		&rootKey.PublicKey,
		rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(101),
		Subject:               pkix.Name{CommonName: serverName},
		DNSNames:              []string{serverName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(
		rand.Reader,
		leafTemplate,
		root,
		&leafKey.PublicKey,
		rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
}
