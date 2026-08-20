//go:build integration

package diagnostics

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/checks"
	"github.com/Naenier/orynelo/internal/diagnostics/checks/environment"
	tlscheck "github.com/Naenier/orynelo/internal/diagnostics/checks/tls"
	"github.com/Naenier/orynelo/internal/diagnostics/engine"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

func TestIntegrationLoopbackHTTPPipeline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.UserAgent() == "" {
			t.Error("request did not include a user agent")
		}
		writer.Header().Set("X-Orynelo-Test", "loopback")
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	options := model.DefaultDiagnoseOptions(server.URL)
	options.NoProxy = true
	diagnosis, err := NewRunner().Diagnose(context.Background(), options, nil)
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if diagnosis.Summary.Status != model.StatusPassed {
		t.Fatalf("overall status = %s, checks = %#v", diagnosis.Summary.Status, diagnosis.Checks)
	}
	assertIntegrationCheck(t, diagnosis, "tcp", model.StatusPassed)
	assertIntegrationCheck(t, diagnosis, "http", model.StatusPassed)
	assertNetworkReferencesResolve(t, diagnosis)
}

func TestIntegrationLoopbackTLSPipeline(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(writer, "ok")
	}))
	defer server.Close()

	options := model.DefaultDiagnoseOptions(server.URL)
	options.NoProxy = true
	options.Insecure = true
	diagnosis, err := NewRunner().Diagnose(context.Background(), options, nil)
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	assertIntegrationCheck(t, diagnosis, "tcp", model.StatusPassed)
	assertIntegrationCheck(t, diagnosis, "tls", model.StatusWarning)
	assertIntegrationCheck(t, diagnosis, "http", model.StatusPassed)
	assertNetworkReferencesResolve(t, diagnosis)
}

func TestIntegrationRedirectChainHasDistinctCorrelatedHops(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/start":
			http.Redirect(writer, request, "/middle", http.StatusFound)
		case "/middle":
			http.Redirect(writer, request, "/final", http.StatusTemporaryRedirect)
		case "/final":
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	options := model.DefaultDiagnoseOptions(server.URL + "/start")
	options.NoProxy = true
	diagnosis, err := NewRunner().Diagnose(context.Background(), options, nil)
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	assertIntegrationCheck(t, diagnosis, "http", model.StatusPassed)

	var actual *model.NetworkPath
	for index := range diagnosis.NetworkPaths {
		if strings.HasPrefix(diagnosis.NetworkPaths[index].ID, "http-client-path-") {
			actual = &diagnosis.NetworkPaths[index]
			break
		}
	}
	if actual == nil || actual.Kind != model.NetworkPathDirect || len(actual.Hops) != 3 {
		t.Fatalf("redirect path = %#v; all paths = %#v", actual, diagnosis.NetworkPaths)
	}
	wantKinds := []model.NetworkHopKind{
		model.NetworkHopOrigin,
		model.NetworkHopRedirect,
		model.NetworkHopRedirect,
	}
	wantPaths := []string{"/start", "/middle", "/final"}
	for index, hop := range actual.Hops {
		parsed, parseErr := url.Parse(hop.URL)
		if parseErr != nil || parsed.Path != wantPaths[index] || hop.Kind != wantKinds[index] {
			t.Fatalf("redirect hop[%d] = %#v", index, hop)
		}
		if len(hop.Attempts) == 0 || hop.Attempts[len(hop.Attempts)-1].Kind != model.NetworkAttemptHTTP {
			t.Fatalf("redirect hop[%d] has no HTTP attempt: %#v", index, hop)
		}
	}
	assertNetworkReferencesResolve(t, diagnosis)
}

func TestIntegrationCONNECTProxySeparatesPeerAndOrigin(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := newIntegrationCONNECTProxy(t, originURL.Host)
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}

	lookup := func(key string) (string, bool) {
		if key == "HTTPS_PROXY" {
			return proxy.URL, true
		}
		return "", false
	}
	plan := checks.Default()
	plan[1] = []model.Check{&environment.Check{LookupEnv: lookup}}
	target := "https://origin.example:" + originURL.Port() + "/"
	options := model.DefaultDiagnoseOptions(target)
	options.Insecure = true
	diagnosis, err := NewRunner(WithPlan(plan)).Diagnose(context.Background(), options, nil)
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	assertIntegrationCheck(t, diagnosis, "http", model.StatusPassed)

	var effective []model.NetworkPath
	for _, path := range diagnosis.NetworkPaths {
		if path.Role == model.NetworkPathRoleClientEffective {
			effective = append(effective, path)
		}
		if path.ID == directPathID && path.Role != model.NetworkPathRoleAuxiliaryDirect {
			t.Fatalf("direct comparison role = %q", path.Role)
		}
	}
	if len(effective) != 1 || effective[0].Kind != model.NetworkPathHTTPSConnect ||
		len(effective[0].Hops) != 2 {
		t.Fatalf("client-effective CONNECT paths = %#v", effective)
	}
	peer, originHop := effective[0].Hops[0], effective[0].Hops[1]
	if peer.Kind != model.NetworkHopProxyPeer || peer.Host != proxyURL.Hostname() ||
		len(peer.Attempts) == 0 || peer.Attempts[0].RemoteIP == nil {
		t.Fatalf("proxy peer hop = %#v", peer)
	}
	if originHop.Kind != model.NetworkHopOrigin || originHop.Host != "origin.example" ||
		originHop.Host == peer.Host {
		t.Fatalf("origin hop = %#v; peer = %#v", originHop, peer)
	}
	assertNetworkReferencesResolve(t, diagnosis)
}

type integrationMatrixTCPCheck struct {
	addresses []net.IP
}

func (integrationMatrixTCPCheck) ID() string   { return "tcp" }
func (integrationMatrixTCPCheck) Name() string { return "matrix TCP fixture" }
func (check integrationMatrixTCPCheck) Run(
	_ context.Context,
	state *model.State,
) model.CheckResult {
	attempts := make([]model.TCPAttempt, len(check.addresses))
	refs := make([]model.NetworkRef, len(check.addresses))
	for index, address := range check.addresses {
		ref := model.NetworkRef{
			PathID: "path-direct", HopID: "hop-origin",
			AttemptID: fmt.Sprintf("attempt-tcp-%03d", index+1),
		}
		refs[index] = ref
		attempts[index] = model.TCPAttempt{
			NetworkRef: &ref, RemoteIP: append(net.IP(nil), address...),
			Success: true, State: model.AttemptStateCompleted, Selected: index == 0,
		}
	}
	state.SetTCP(attempts)
	return model.CheckResult{
		Status: model.StatusPassed, Summary: "fixture TCP candidates are reachable",
		NetworkRefs: refs,
	}
}

type integrationMappedDialer struct {
	addresses map[string]string
}

func (dialer integrationMappedDialer) DialContext(
	ctx context.Context,
	_ string,
	address string,
) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	destination, ok := dialer.addresses[host]
	if !ok {
		return nil, fmt.Errorf("no TLS fixture for %s", host)
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", destination)
}

func TestIntegrationTLSMatrixRetainsDifferentBackendCertificatesAndTimings(t *testing.T) {
	first, firstCertificate := newIntegrationTLSServer(t, 101, "backend-one")
	defer first.Close()
	second, secondCertificate := newIntegrationTLSServer(t, 202, "backend-two")
	defer second.Close()

	addresses := []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.11")}
	roots := x509.NewCertPool()
	roots.AddCert(firstCertificate)
	roots.AddCert(secondCertificate)
	tlsProbe := tlscheck.New(integrationMappedDialer{addresses: map[string]string{
		addresses[0].String(): first.Listener.Addr().String(),
		addresses[1].String(): second.Listener.Addr().String(),
	}})
	tlsProbe.RootCAs = roots
	plan := engine.Plan{
		{stage3DirectEnvironmentCheck{}},
		{integrationMatrixTCPCheck{addresses: addresses}},
		{tlsProbe},
	}
	options := model.DefaultDiagnoseOptions("tls://example.com:443")
	options.ProbeMode = model.ProbeModeAddressMatrix
	options.AddressLimit = 2
	options.MaxConcurrency = 2
	options.CertificateWarningThreshold = time.Hour
	diagnosis, err := NewRunner(WithPlan(plan)).Diagnose(context.Background(), options, nil)
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	assertIntegrationCheck(t, diagnosis, "tls", model.StatusPassed)

	var tlsResult *model.CheckResult
	for index := range diagnosis.Checks {
		if diagnosis.Checks[index].ID == "tls" {
			tlsResult = &diagnosis.Checks[index]
			break
		}
	}
	if tlsResult == nil || len(tlsResult.Evidence) != 2 {
		t.Fatalf("TLS matrix evidence = %#v", tlsResult)
	}
	serials := map[string]struct{}{}
	remoteIPs := map[string]struct{}{}
	for _, evidence := range tlsResult.Evidence {
		serials[evidence.Details["serialNumber"]] = struct{}{}
		remoteIPs[evidence.Details["remoteIp"]] = struct{}{}
	}
	if len(serials) != 2 || len(remoteIPs) != 2 {
		t.Fatalf("backend certificates were collapsed: evidence=%#v", tlsResult.Evidence)
	}

	var matrixPath *model.NetworkPath
	for index := range diagnosis.NetworkPaths {
		if diagnosis.NetworkPaths[index].ID == directPathID {
			matrixPath = &diagnosis.NetworkPaths[index]
			break
		}
	}
	if matrixPath == nil || matrixPath.Role != model.NetworkPathRoleAddressMatrix ||
		len(matrixPath.Hops) != 1 {
		t.Fatalf("TLS matrix path = %#v", matrixPath)
	}
	timingRefs := make(map[string]map[string]struct{})
	for _, timing := range matrixPath.Hops[0].Timings {
		if timing.Phase != "tcp" && timing.Phase != "tls_handshake" {
			continue
		}
		if timingRefs[timing.AttemptID] == nil {
			timingRefs[timing.AttemptID] = make(map[string]struct{})
		}
		timingRefs[timing.AttemptID][timing.Phase] = struct{}{}
	}
	if len(timingRefs) != 2 {
		t.Fatalf("per-backend TLS timings were collapsed: %#v", matrixPath.Hops[0].Timings)
	}
	for attemptID, phases := range timingRefs {
		if _, ok := phases["tcp"]; !ok {
			t.Fatalf("attempt %s has no TCP timing: %#v", attemptID, phases)
		}
		if _, ok := phases["tls_handshake"]; !ok {
			t.Fatalf("attempt %s has no handshake timing: %#v", attemptID, phases)
		}
	}
	assertNetworkReferencesResolve(t, diagnosis)
}

func assertIntegrationCheck(
	t *testing.T,
	diagnosis model.Diagnosis,
	id string,
	want model.Status,
) {
	t.Helper()
	for _, check := range diagnosis.Checks {
		if check.ID == id {
			if check.Status != want {
				t.Fatalf("%s status = %s, want %s: %#v", id, check.Status, want, check)
			}
			return
		}
	}
	t.Fatalf("diagnosis did not include %q: %#v", id, diagnosis.Checks)
}

func newIntegrationCONNECTProxy(t *testing.T, upstreamAddress string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect {
			http.Error(writer, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		upstream, err := net.Dial("tcp", upstreamAddress)
		if err != nil {
			http.Error(writer, "upstream unavailable", http.StatusBadGateway)
			return
		}
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			_ = upstream.Close()
			http.Error(writer, "hijacking unavailable", http.StatusInternalServerError)
			return
		}
		client, buffered, err := hijacker.Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		if _, err = io.WriteString(buffered, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			_ = client.Close()
			_ = upstream.Close()
			return
		}
		if err = buffered.Flush(); err != nil {
			_ = client.Close()
			_ = upstream.Close()
			return
		}

		done := make(chan struct{}, 2)
		go func() {
			_, _ = io.Copy(upstream, client)
			done <- struct{}{}
		}()
		go func() {
			_, _ = io.Copy(client, upstream)
			done <- struct{}{}
		}()
		<-done
		_ = client.Close()
		_ = upstream.Close()
		<-done
	}))
}

func newIntegrationTLSServer(
	t *testing.T,
	serial int64,
	commonName string,
) (*httptest.Server, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		DNSNames:              []string{"example.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := cryptotls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}),
	)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &cryptotls.Config{
		Certificates: []cryptotls.Certificate{pair},
		MinVersion:   cryptotls.VersionTLS12,
	}
	server.StartTLS()
	return server, certificate
}
