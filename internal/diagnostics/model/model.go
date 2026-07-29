// Package model contains the diagnostic domain model. It intentionally has no
// dependencies on presentation, persistence, or operating-system adapters.
package model

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Status is the lifecycle and outcome state of a diagnostic check.
type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusPassed    Status = "passed"
	StatusWarning   Status = "warning"
	StatusFailed    Status = "failed"
	StatusSkipped   Status = "skipped"
	StatusCancelled Status = "cancelled"
)

// Valid reports whether status is part of the stable domain vocabulary.
func (s Status) Valid() bool {
	switch s {
	case StatusPending, StatusRunning, StatusPassed, StatusWarning,
		StatusFailed, StatusSkipped, StatusCancelled:
		return true
	default:
		return false
	}
}

// Evidence is a factual observation produced by a check. Values are intended
// to be safe for reports; secrets must be removed before evidence is created.
type Evidence struct {
	ID      string            `json:"id,omitempty"`
	CheckID string            `json:"checkId,omitempty"`
	Code    string            `json:"code,omitempty"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
}

// Recommendation is an actionable follow-up tied to observed evidence.
type Recommendation struct {
	ID       string `json:"id,omitempty"`
	CheckID  string `json:"checkId,omitempty"`
	Priority string `json:"priority,omitempty"`
	Message  string `json:"message"`
}

// CheckResult is the stable output of one diagnostic check.
type CheckResult struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Status          Status           `json:"status"`
	StartedAt       time.Time        `json:"startedAt"`
	FinishedAt      time.Time        `json:"finishedAt"`
	Duration        time.Duration    `json:"duration"`
	Summary         string           `json:"summary"`
	Evidence        []Evidence       `json:"evidence,omitempty"`
	Recommendations []Recommendation `json:"recommendations,omitempty"`
	ErrorCode       string           `json:"errorCode,omitempty"`
}

// Complete normalizes timestamps and evidence ownership before returning a
// result from a Check implementation.
func (r CheckResult) Complete(started, finished time.Time) CheckResult {
	if r.StartedAt.IsZero() {
		r.StartedAt = started
	}
	if r.FinishedAt.IsZero() {
		r.FinishedAt = finished
	}
	if r.FinishedAt.Before(r.StartedAt) {
		r.FinishedAt = r.StartedAt
	}
	r.Duration = r.FinishedAt.Sub(r.StartedAt)
	for i := range r.Evidence {
		if r.Evidence[i].CheckID == "" {
			r.Evidence[i].CheckID = r.ID
		}
	}
	for i := range r.Recommendations {
		if r.Recommendations[i].CheckID == "" {
			r.Recommendations[i].CheckID = r.ID
		}
	}
	return r
}

// Check is a single, context-aware unit in a diagnostic plan.
type Check interface {
	ID() string
	Name() string
	Run(ctx context.Context, state *State) CheckResult
}

// CheckEventType identifies a streaming engine event.
type CheckEventType string

const (
	EventRunStarted     CheckEventType = "run_started"
	EventCheckStarted   CheckEventType = "check_started"
	EventCheckCompleted CheckEventType = "check_completed"
	EventRunCompleted   CheckEventType = "run_completed"
)

// CheckEvent can be consumed by a CLI or GUI while a diagnosis is running.
type CheckEvent struct {
	Type      CheckEventType `json:"type"`
	CheckID   string         `json:"checkId,omitempty"`
	CheckName string         `json:"checkName,omitempty"`
	Status    Status         `json:"status,omitempty"`
	At        time.Time      `json:"at"`
	Index     int            `json:"index,omitempty"`
	Result    *CheckResult   `json:"result,omitempty"`
}

// EventSink receives progress notifications. The engine invokes it
// synchronously so implementations must return promptly. GUI consumers should
// use NonBlockingEventSink or Runner.Stream.
type EventSink func(CheckEvent)

// NonBlockingEventSink adapts a channel to a best-effort bounded sink. Events
// are dropped when the consumer has not kept up, so diagnostics never block on
// UI delivery.
func NonBlockingEventSink(events chan<- CheckEvent) EventSink {
	if events == nil {
		return nil
	}
	return func(event CheckEvent) {
		select {
		case events <- event:
		default:
		}
	}
}

// TargetKind describes which upper-layer checks are meaningful.
type TargetKind string

const (
	TargetHTTP TargetKind = "http"
	TargetTCP  TargetKind = "tcp"
)

// Target is the parsed, privacy-safe representation of user input.
// RequestURL is excluded from serialization because it can contain query
// secrets. Original and Normalized are always redacted.
type Target struct {
	Original    string     `json:"original"`
	Normalized  string     `json:"normalized"`
	Scheme      string     `json:"scheme,omitempty"`
	Host        string     `json:"host"`
	DisplayHost string     `json:"displayHost,omitempty"`
	Port        uint16     `json:"port"`
	Path        string     `json:"path,omitempty"`
	Kind        TargetKind `json:"kind"`
	UseTLS      bool       `json:"useTLS"`
	RequestURL  string     `json:"-"`
}

// Address returns a dialable host:port pair with correct IPv6 brackets.
func (t Target) Address() string {
	return net.JoinHostPort(t.Host, fmt.Sprintf("%d", t.Port))
}

// ServerName returns a certificate SNI name, or an empty string for IP targets.
func (t Target) ServerName() string {
	if net.ParseIP(strings.TrimSuffix(t.Host, ".")) != nil {
		return ""
	}
	return strings.TrimSuffix(t.Host, ".")
}

// IPVersion controls address-family selection.
type IPVersion string

const (
	IPVersionAuto IPVersion = "auto"
	IPVersion4    IPVersion = "4"
	IPVersion6    IPVersion = "6"
)

// Valid reports whether an IP version is accepted.
func (v IPVersion) Valid() bool {
	return v == IPVersionAuto || v == IPVersion4 || v == IPVersion6
}

// ReportVerbosity controls optional human-readable technical context.
type ReportVerbosity string

const (
	ReportVerbosityNormal  ReportVerbosity = "normal"
	ReportVerbosityVerbose ReportVerbosity = "verbose"
)

// Valid reports whether the verbosity is supported.
func (v ReportVerbosity) Valid() bool {
	return v == ReportVerbosityNormal || v == ReportVerbosityVerbose
}

// DiagnoseOptions configures one run. Callers should start with
// DefaultDiagnoseOptions and override the desired fields.
type DiagnoseOptions struct {
	Target                      string          `json:"target"`
	Timeout                     time.Duration   `json:"timeout"`
	CheckTimeout                time.Duration   `json:"checkTimeout"`
	IPVersion                   IPVersion       `json:"ipVersion"`
	NoProxy                     bool            `json:"noProxy"`
	Insecure                    bool            `json:"insecure"`
	EnableTLS                   bool            `json:"enableTLS"`
	MaxRedirects                int             `json:"maxRedirects"`
	Method                      string          `json:"method"`
	ReportVerbosity             ReportVerbosity `json:"reportVerbosity"`
	UserAgent                   string          `json:"userAgent"`
	CertificateWarningThreshold time.Duration   `json:"certificateWarningThreshold"`
	MaxConcurrency              int             `json:"maxConcurrency"`
	BodyLimit                   int64           `json:"bodyLimit"`
}

// DefaultDiagnoseOptions returns conservative production defaults.
func DefaultDiagnoseOptions(target string) DiagnoseOptions {
	return DiagnoseOptions{
		Target:                      target,
		Timeout:                     15 * time.Second,
		CheckTimeout:                5 * time.Second,
		IPVersion:                   IPVersionAuto,
		MaxRedirects:                10,
		Method:                      "GET",
		ReportVerbosity:             ReportVerbosityNormal,
		UserAgent:                   "OpsDoctor/diagnostic",
		CertificateWarningThreshold: 30 * 24 * time.Hour,
		MaxConcurrency:              4,
		BodyLimit:                   64 << 10,
	}
}

// Summary is an evidence-based overall conclusion.
type Summary struct {
	Status          Status           `json:"status"`
	Title           string           `json:"title"`
	Description     string           `json:"description"`
	EvidenceRefs    []string         `json:"evidenceRefs,omitempty"`
	Recommendations []Recommendation `json:"recommendations,omitempty"`
}

// BuildInfo identifies the executable that produced a diagnosis.
type BuildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
	Dirty     bool   `json:"dirty"`
	GoVersion string `json:"goVersion"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Diagnosis is a complete run in deterministic check order.
type Diagnosis struct {
	ID         string          `json:"id"`
	Target     Target          `json:"target"`
	Options    DiagnoseOptions `json:"options"`
	StartedAt  time.Time       `json:"startedAt"`
	FinishedAt time.Time       `json:"finishedAt"`
	Duration   time.Duration   `json:"duration"`
	Checks     []CheckResult   `json:"checks"`
	Summary    Summary         `json:"summary"`
	Build      BuildInfo       `json:"build"`
}

// DiagnosticMode describes how the desktop application interprets a target.
type DiagnosticMode string

const (
	DiagnosticModeAuto DiagnosticMode = "auto"
	DiagnosticModeTCP  DiagnosticMode = "tcp"
	DiagnosticModeTLS  DiagnosticMode = "tls"
)

// Valid reports whether the desktop mode has defined execution semantics.
func (m DiagnosticMode) Valid() bool {
	return m == DiagnosticModeAuto || m == DiagnosticModeTCP || m == DiagnosticModeTLS
}

// Profile stores reusable, non-secret diagnostic settings.
type Profile struct {
	ID           int64          `json:"id,omitempty"`
	Name         string         `json:"name"`
	Target       string         `json:"target"`
	Mode         DiagnosticMode `json:"mode"`
	IPVersion    IPVersion      `json:"ipVersion"`
	Timeout      time.Duration  `json:"timeout"`
	CheckTimeout time.Duration  `json:"checkTimeout"`
	NoProxy      bool           `json:"noProxy"`
	EnableTLS    bool           `json:"enableTLS"`
	MaxRedirects int            `json:"maxRedirects"`
	Method       string         `json:"method"`
	CreatedAt    time.Time      `json:"createdAt"`
	UpdatedAt    time.Time      `json:"updatedAt"`
}

// HistoryEntry is the compact list view for a stored diagnosis.
type HistoryEntry struct {
	ID       string        `json:"id"`
	Date     time.Time     `json:"date"`
	Target   string        `json:"target"`
	Status   Status        `json:"status"`
	Duration time.Duration `json:"duration"`
	Version  string        `json:"version"`
}

// HistorySort selects a stable, predefined history ordering.
type HistorySort string

const (
	HistorySortDate     HistorySort = "date"
	HistorySortTarget   HistorySort = "target"
	HistorySortStatus   HistorySort = "status"
	HistorySortDuration HistorySort = "duration"
	HistorySortVersion  HistorySort = "version"
)

// HistoryQuery controls target search, status filtering, sorting, and paging.
type HistoryQuery struct {
	Search    string
	Status    Status
	Sort      HistorySort
	Ascending bool
	Limit     int
	Offset    int
}

// ProxyInfo records privacy-safe environment/proxy selection.
type ProxyInfo struct {
	Disabled    bool              `json:"disabled"`
	Selected    bool              `json:"selected"`
	Bypassed    bool              `json:"bypassed"`
	ProxyURL    string            `json:"proxyUrl,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}

// DNSResult stores canonical, de-duplicated resolver output.
type DNSResult struct {
	IPv4         []net.IP      `json:"ipv4,omitempty"`
	IPv6         []net.IP      `json:"ipv6,omitempty"`
	AError       string        `json:"aError,omitempty"`
	AAAAError    string        `json:"aaaaError,omitempty"`
	ADuration    time.Duration `json:"aDuration"`
	AAAADuration time.Duration `json:"aaaaDuration"`
}

// RouteInfo describes the source-side path selected for a remote address.
type RouteInfo struct {
	RemoteIP      net.IP `json:"remoteIp"`
	LocalIP       net.IP `json:"localIp,omitempty"`
	InterfaceName string `json:"interfaceName,omitempty"`
	InterfaceUp   bool   `json:"interfaceUp"`
	MTU           int    `json:"mtu,omitempty"`
	Family        string `json:"family"`
	Error         string `json:"error,omitempty"`
}

// TCPAttempt is a single bounded TCP connect attempt.
type TCPAttempt struct {
	RemoteIP  net.IP        `json:"remoteIp"`
	LocalAddr string        `json:"localAddr,omitempty"`
	Duration  time.Duration `json:"duration"`
	Success   bool          `json:"success"`
	ErrorCode string        `json:"errorCode,omitempty"`
	Error     string        `json:"error,omitempty"`
}

// CertificateInfo contains report-safe peer certificate metadata.
type CertificateInfo struct {
	Subject       string        `json:"subject,omitempty"`
	Issuer        string        `json:"issuer,omitempty"`
	SerialNumber  string        `json:"serialNumber,omitempty"`
	DNSNames      []string      `json:"dnsNames,omitempty"`
	IPAddresses   []string      `json:"ipAddresses,omitempty"`
	NotBefore     time.Time     `json:"notBefore,omitempty"`
	NotAfter      time.Time     `json:"notAfter,omitempty"`
	Remaining     time.Duration `json:"remaining,omitempty"`
	ChainLength   int           `json:"chainLength"`
	HostnameValid bool          `json:"hostnameValid"`
	SystemTrusted bool          `json:"systemTrusted"`
}

// TLSResult stores negotiated transport and certificate information.
type TLSResult struct {
	RemoteIP    net.IP          `json:"remoteIp,omitempty"`
	ServerName  string          `json:"serverName,omitempty"`
	Version     string          `json:"version,omitempty"`
	CipherSuite string          `json:"cipherSuite,omitempty"`
	ALPN        string          `json:"alpn,omitempty"`
	Certificate CertificateInfo `json:"certificate"`
	Insecure    bool            `json:"insecure"`
	Duration    time.Duration   `json:"duration"`
	ErrorCode   string          `json:"errorCode,omitempty"`
	Error       string          `json:"error,omitempty"`
}

// Redirect records one privacy-safe HTTP redirect.
type Redirect struct {
	From       string `json:"from"`
	To         string `json:"to"`
	StatusCode int    `json:"statusCode"`
}

// HTTPTimings exposes the major httptrace phases.
type HTTPTimings struct {
	DNS       time.Duration `json:"dns"`
	TCP       time.Duration `json:"tcp"`
	TLS       time.Duration `json:"tls"`
	FirstByte time.Duration `json:"firstByte"`
	Total     time.Duration `json:"total"`
}

// HTTPResult stores bounded, redacted application-response metadata.
type HTTPResult struct {
	Method        string              `json:"method"`
	FinalURL      string              `json:"finalUrl"`
	StatusCode    int                 `json:"statusCode"`
	Status        string              `json:"status"`
	Redirects     []Redirect          `json:"redirects,omitempty"`
	Headers       map[string][]string `json:"headers,omitempty"`
	Timings       HTTPTimings         `json:"timings"`
	RemoteIP      string              `json:"remoteIp,omitempty"`
	Protocol      string              `json:"protocol,omitempty"`
	BodyBytesRead int64               `json:"bodyBytesRead"`
	BodyTruncated bool                `json:"bodyTruncated"`
	ErrorCode     string              `json:"errorCode,omitempty"`
	Error         string              `json:"error,omitempty"`
}

// State carries mutable artifacts between checks. It is per diagnosis and
// guarded because independent checks may run concurrently.
type State struct {
	Target  Target
	Options DiagnoseOptions

	mu     sync.RWMutex
	proxy  ProxyInfo
	dns    DNSResult
	routes []RouteInfo
	tcp    []TCPAttempt
	tls    TLSResult
	http   HTTPResult
}

// NewState constructs isolated state for one run.
func NewState(target Target, options DiagnoseOptions) *State {
	return &State{Target: target, Options: options}
}

func (s *State) SetProxy(v ProxyInfo) { s.mu.Lock(); s.proxy = cloneProxy(v); s.mu.Unlock() }
func (s *State) Proxy() ProxyInfo     { s.mu.RLock(); defer s.mu.RUnlock(); return cloneProxy(s.proxy) }
func (s *State) SetDNS(v DNSResult)   { s.mu.Lock(); s.dns = cloneDNS(v); s.mu.Unlock() }
func (s *State) DNS() DNSResult       { s.mu.RLock(); defer s.mu.RUnlock(); return cloneDNS(s.dns) }
func (s *State) SetRoutes(v []RouteInfo) {
	s.mu.Lock()
	s.routes = cloneRoutes(v)
	s.mu.Unlock()
}
func (s *State) Routes() []RouteInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRoutes(s.routes)
}
func (s *State) SetTCP(v []TCPAttempt) {
	s.mu.Lock()
	s.tcp = cloneTCP(v)
	s.mu.Unlock()
}
func (s *State) TCP() []TCPAttempt {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneTCP(s.tcp)
}
func (s *State) SetTLS(v TLSResult)   { s.mu.Lock(); s.tls = cloneTLS(v); s.mu.Unlock() }
func (s *State) TLS() TLSResult       { s.mu.RLock(); defer s.mu.RUnlock(); return cloneTLS(s.tls) }
func (s *State) SetHTTP(v HTTPResult) { s.mu.Lock(); s.http = cloneHTTP(v); s.mu.Unlock() }
func (s *State) HTTP() HTTPResult     { s.mu.RLock(); defer s.mu.RUnlock(); return cloneHTTP(s.http) }

func cloneProxy(v ProxyInfo) ProxyInfo {
	v.Environment = cloneStringMap(v.Environment)
	return v
}

func cloneDNS(v DNSResult) DNSResult {
	v.IPv4 = cloneIPs(v.IPv4)
	v.IPv6 = cloneIPs(v.IPv6)
	return v
}

func cloneIPs(values []net.IP) []net.IP {
	if values == nil {
		return nil
	}
	out := make([]net.IP, len(values))
	for index, value := range values {
		out[index] = append(net.IP(nil), value...)
	}
	return out
}

func cloneRoutes(values []RouteInfo) []RouteInfo {
	if values == nil {
		return nil
	}
	out := append([]RouteInfo(nil), values...)
	for index := range out {
		out[index].RemoteIP = append(net.IP(nil), values[index].RemoteIP...)
		out[index].LocalIP = append(net.IP(nil), values[index].LocalIP...)
	}
	return out
}

func cloneTCP(values []TCPAttempt) []TCPAttempt {
	if values == nil {
		return nil
	}
	out := append([]TCPAttempt(nil), values...)
	for index := range out {
		out[index].RemoteIP = append(net.IP(nil), values[index].RemoteIP...)
	}
	return out
}

func cloneTLS(value TLSResult) TLSResult {
	value.RemoteIP = append(net.IP(nil), value.RemoteIP...)
	value.Certificate.DNSNames = append([]string(nil), value.Certificate.DNSNames...)
	value.Certificate.IPAddresses = append([]string(nil), value.Certificate.IPAddresses...)
	return value
}

func cloneHTTP(v HTTPResult) HTTPResult {
	v.Redirects = append([]Redirect(nil), v.Redirects...)
	if v.Headers != nil {
		headers := v.Headers
		v.Headers = make(map[string][]string, len(headers))
		for key, values := range headers {
			v.Headers[key] = append([]string(nil), values...)
		}
	}
	return v
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
