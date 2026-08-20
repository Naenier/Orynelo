// Package model contains the diagnostic domain model. It intentionally has no
// dependencies on presentation, persistence, or operating-system adapters.
package model

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Status is the lifecycle and outcome state of a diagnostic check.
type Status string

const (
	StatusPending       Status = "pending"
	StatusRunning       Status = "running"
	StatusPassed        Status = "passed"
	StatusWarning       Status = "warning"
	StatusFailed        Status = "failed"
	StatusSkipped       Status = "skipped"
	StatusNotApplicable Status = "not_applicable"
	StatusCancelled     Status = "cancelled"
)

// Valid reports whether status is part of the stable domain vocabulary.
func (s Status) Valid() bool {
	switch s {
	case StatusPending, StatusRunning, StatusPassed, StatusWarning,
		StatusFailed, StatusSkipped, StatusNotApplicable, StatusCancelled:
		return true
	default:
		return false
	}
}

// NetworkRef correlates an observation with one concrete network path, hop,
// and attempt. All fields are optional so snapshots written before path
// correlation was introduced remain valid.
type NetworkRef struct {
	PathID    string `json:"pathId,omitempty"`
	HopID     string `json:"hopId,omitempty"`
	AttemptID string `json:"attemptId,omitempty"`
}

// NetworkPathRole distinguishes the client-observed route from explicitly
// requested comparison probes.
type NetworkPathRole string

const (
	NetworkPathRoleClientEffective NetworkPathRole = "client_effective"
	NetworkPathRoleAddressMatrix   NetworkPathRole = "address_matrix"
	NetworkPathRoleAuxiliaryDirect NetworkPathRole = "auxiliary_direct"
)

// NetworkPathKind describes how an origin is reached.
type NetworkPathKind string

const (
	NetworkPathDirect       NetworkPathKind = "direct"
	NetworkPathHTTPProxy    NetworkPathKind = "http_proxy"
	NetworkPathHTTPSConnect NetworkPathKind = "https_connect"
)

// NetworkHopKind identifies the endpoint role within a concrete path.
type NetworkHopKind string

const (
	NetworkHopOrigin    NetworkHopKind = "origin"
	NetworkHopProxyPeer NetworkHopKind = "proxy_peer"
	NetworkHopRedirect  NetworkHopKind = "redirect"
)

// NetworkAttemptKind identifies the operation represented by one attempt.
type NetworkAttemptKind string

const (
	NetworkAttemptDNS   NetworkAttemptKind = "dns"
	NetworkAttemptRoute NetworkAttemptKind = "route"
	NetworkAttemptTCP   NetworkAttemptKind = "tcp"
	NetworkAttemptTLS   NetworkAttemptKind = "tls"
	NetworkAttemptHTTP  NetworkAttemptKind = "http"
)

// NetworkPath is one concrete direct or proxy route. Redirects that change
// the route create a new path linked through RedirectFromPathID.
type NetworkPath struct {
	ID                 string          `json:"id"`
	Role               NetworkPathRole `json:"role"`
	Kind               NetworkPathKind `json:"kind"`
	Sequence           int             `json:"sequence"`
	RedirectFromPathID string          `json:"redirectFromPathId,omitempty"`
	Hops               []NetworkHop    `json:"hops,omitempty"`
}

// NetworkHop is a report-safe endpoint within a path. A CONNECT route uses
// distinct proxy-peer and origin hops so peer addresses cannot be conflated.
type NetworkHop struct {
	ID                string           `json:"id"`
	PathID            string           `json:"pathId"`
	Sequence          int              `json:"sequence"`
	Kind              NetworkHopKind   `json:"kind"`
	URL               string           `json:"url,omitempty"`
	Scheme            string           `json:"scheme,omitempty"`
	Host              string           `json:"host,omitempty"`
	Port              uint16           `json:"port,omitempty"`
	Zone              string           `json:"zone,omitempty"`
	RemoteIP          net.IP           `json:"remoteIp,omitempty"`
	RemoteAddr        string           `json:"remoteAddr,omitempty"`
	LocalAddr         string           `json:"localAddr,omitempty"`
	Reused            bool             `json:"reused,omitempty"`
	SelectedAttemptID string           `json:"selectedAttemptId,omitempty"`
	Attempts          []NetworkAttempt `json:"attempts,omitempty"`
	Timings           []PhaseTiming    `json:"timings,omitempty"`
}

// NetworkAttempt records one independently attributable network operation.
// IDs are opaque within one diagnosis and must not contain addresses or other
// potentially identifying values.
type NetworkAttempt struct {
	ID            string             `json:"id"`
	PathID        string             `json:"pathId"`
	HopID         string             `json:"hopId"`
	Kind          NetworkAttemptKind `json:"kind"`
	State         AttemptState       `json:"state,omitempty"`
	Network       string             `json:"network,omitempty"`
	RemoteIP      net.IP             `json:"remoteIp,omitempty"`
	RemoteAddr    string             `json:"remoteAddr,omitempty"`
	LocalAddr     string             `json:"localAddr,omitempty"`
	InterfaceName string             `json:"interfaceName,omitempty"`
	InterfaceUp   bool               `json:"interfaceUp,omitempty"`
	MTU           int                `json:"mtu,omitempty"`
	StartedAt     time.Time          `json:"startedAt,omitempty"`
	FinishedAt    time.Time          `json:"finishedAt,omitempty"`
	Duration      time.Duration      `json:"duration"`
	Selected      bool               `json:"selected,omitempty"`
	Reused        bool               `json:"reused,omitempty"`
	ErrorCode     string             `json:"errorCode,omitempty"`
	Error         string             `json:"error,omitempty"`
}

// PhaseTiming records an individual DNS, connect, TLS, TTFB, or total phase
// without merging overlapping attempts.
type PhaseTiming struct {
	NetworkRef
	Phase      string        `json:"phase"`
	StartedAt  time.Time     `json:"startedAt,omitempty"`
	FinishedAt time.Time     `json:"finishedAt,omitempty"`
	Duration   time.Duration `json:"duration"`
}

// Evidence is a factual observation produced by a check. Values are intended
// to be safe for reports; secrets must be removed before evidence is created.
type Evidence struct {
	ID         string            `json:"id,omitempty"`
	CheckID    string            `json:"checkId,omitempty"`
	NetworkRef *NetworkRef       `json:"networkRef,omitempty"`
	Code       string            `json:"code,omitempty"`
	Message    string            `json:"message"`
	Details    map[string]string `json:"details,omitempty"`
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
	Role            CheckRole        `json:"role,omitempty"`
	NetworkRefs     []NetworkRef     `json:"networkRefs,omitempty"`
	StartedAt       time.Time        `json:"startedAt"`
	FinishedAt      time.Time        `json:"finishedAt"`
	Duration        time.Duration    `json:"duration"`
	Summary         string           `json:"summary"`
	Evidence        []Evidence       `json:"evidence,omitempty"`
	Recommendations []Recommendation `json:"recommendations,omitempty"`
	ErrorCode       string           `json:"errorCode,omitempty"`
}

// CheckRole distinguishes the actual client path from temporary comparison
// probes. It is intentionally optional for backward-compatible snapshots.
type CheckRole string

const (
	CheckRoleAuxiliaryDirectComparison CheckRole = "auxiliary_direct_comparison"
)

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
	EventRunStarted       CheckEventType = "run_started"
	EventCheckStarted     CheckEventType = "check_started"
	EventCheckCompleted   CheckEventType = "check_completed"
	EventRunCompleted     CheckEventType = "run_completed"
	EventDeliveryOverflow CheckEventType = "delivery_overflow"
)

// CheckEvent can be consumed by a CLI or GUI while a diagnosis is running.
type CheckEvent struct {
	Type          CheckEventType `json:"type"`
	CheckID       string         `json:"checkId,omitempty"`
	CheckName     string         `json:"checkName,omitempty"`
	Status        Status         `json:"status,omitempty"`
	At            time.Time      `json:"at"`
	Index         int            `json:"index,omitempty"`
	Result        *CheckResult   `json:"result,omitempty"`
	DroppedEvents uint64         `json:"droppedEvents,omitempty"`
}

// EventSink receives progress notifications. Runner isolates external sinks
// behind a bounded queue; lower-level engine users must still return promptly.
type EventSink func(CheckEvent)

// EventDeliveryStats makes backpressure and faulty event adapters observable
// without allowing them to stop diagnostic execution.
type EventDeliveryStats struct {
	Dropped        uint64 `json:"dropped,omitempty"`
	ConsumerPanics uint64 `json:"consumerPanics,omitempty"`
	DrainTimedOut  bool   `json:"drainTimedOut,omitempty"`
}

// Empty reports whether event delivery completed without degradation.
func (stats EventDeliveryStats) Empty() bool {
	return stats.Dropped == 0 && stats.ConsumerPanics == 0 && !stats.DrainTimedOut
}

// NonBlockingEventSink is a low-level best-effort channel adapter. It drops
// silently when full; application consumers should prefer Runner, whose queue
// exposes overflow through EventDeliveryStats.
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

// TargetMode is the explicit effective protocol selected for a target. It is
// additive to the legacy Kind and UseTLS fields, which remain populated for
// older readers.
type TargetMode string

const (
	TargetModeTCP   TargetMode = "tcp"
	TargetModeTLS   TargetMode = "tls"
	TargetModeHTTP  TargetMode = "http"
	TargetModeHTTPS TargetMode = "https"
)

// Valid reports whether the target mode has defined transport semantics.
func (m TargetMode) Valid() bool {
	switch m {
	case TargetModeTCP, TargetModeTLS, TargetModeHTTP, TargetModeHTTPS:
		return true
	default:
		return false
	}
}

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
	Mode        TargetMode `json:"mode,omitempty"`
	Zone        string     `json:"zone,omitempty"`
	// PrivacyRedacted records that parsing removed credentials or a secret-like
	// query value. It lets profile-save UI warn even when userinfo was removed
	// without leaving a replacement marker in the display URL.
	PrivacyRedacted bool   `json:"privacyRedacted,omitempty"`
	RequestURL      string `json:"-"`
}

// Address returns a dialable host:port pair with correct IPv6 brackets.
func (t Target) Address() string {
	host := t.Host
	if t.Zone != "" {
		host += "%" + t.Zone
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", t.Port))
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

// ProbeMode selects either the bounded client-like route or an explicit
// multi-address comparison.
type ProbeMode string

const (
	ProbeModeClientEffective ProbeMode = "client_effective"
	ProbeModeAddressMatrix   ProbeMode = "address_matrix"
)

// Valid reports whether the probe mode is supported.
func (m ProbeMode) Valid() bool {
	return m == ProbeModeClientEffective || m == ProbeModeAddressMatrix
}

// DiagnoseOptions configures one run. Callers should start with
// DefaultDiagnoseOptions and override the desired fields.
type DiagnoseOptions struct {
	Target                      string          `json:"target"`
	Timeout                     time.Duration   `json:"timeout"`
	CheckTimeout                time.Duration   `json:"checkTimeout"`
	IPVersion                   IPVersion       `json:"ipVersion"`
	ProbeMode                   ProbeMode       `json:"probeMode,omitempty"`
	AddressLimit                int             `json:"addressLimit,omitempty"`
	AddressMatrixBudget         time.Duration   `json:"addressMatrixBudget,omitempty"`
	NoProxy                     bool            `json:"noProxy"`
	Insecure                    bool            `json:"insecure"`
	EnableTLS                   bool            `json:"enableTLS"`
	MaxRedirects                int             `json:"maxRedirects"`
	MaxRedirectLocationBytes    int             `json:"maxRedirectLocationBytes"`
	AllowInsecureRedirects      bool            `json:"allowInsecureRedirects"`
	AllowPrivateRedirects       bool            `json:"allowPrivateRedirects"`
	ActualHTTPReserve           time.Duration   `json:"actualHttpReserve"`
	Method                      string          `json:"method"`
	ReportVerbosity             ReportVerbosity `json:"reportVerbosity"`
	UserAgent                   string          `json:"userAgent"`
	CertificateWarningThreshold time.Duration   `json:"certificateWarningThreshold"`
	MaxConcurrency              int             `json:"maxConcurrency"`
	BodyLimit                   int64           `json:"bodyLimit"`
	ExpectedStatusMin           int             `json:"expectedStatusMin,omitempty"`
	ExpectedStatusMax           int             `json:"expectedStatusMax,omitempty"`
	ExpectedStatusConfigured    bool            `json:"expectedStatusConfigured,omitempty"`
	LatencyThreshold            time.Duration   `json:"latencyThreshold,omitempty"`
	ConnectIP                   string          `json:"connectIp,omitempty"`
	ServerName                  string          `json:"serverName,omitempty"`
	HTTPHost                    string          `json:"httpHost,omitempty"`
	CollectDNSDetails           bool            `json:"collectDnsDetails,omitempty"`
	InspectBody                 bool            `json:"inspectBody,omitempty"`
	CustomCAConfigured          bool            `json:"customCaConfigured,omitempty"`
	RequestHeaderNames          []string        `json:"requestHeaderNames,omitempty"`
	// CustomCABundlePath, CustomCAPEM, and RequestHeaders are request-capable
	// transient inputs. They must never be persisted, exported, or logged.
	CustomCABundlePath string            `json:"-"`
	CustomCAPEM        []byte            `json:"-"`
	RequestHeaders     map[string]string `json:"-"`
}

// DefaultDiagnoseOptions returns conservative production defaults.
func DefaultDiagnoseOptions(target string) DiagnoseOptions {
	return DiagnoseOptions{
		Target:                      target,
		Timeout:                     15 * time.Second,
		CheckTimeout:                5 * time.Second,
		IPVersion:                   IPVersionAuto,
		ProbeMode:                   ProbeModeClientEffective,
		AddressLimit:                4,
		AddressMatrixBudget:         5 * time.Second,
		MaxRedirects:                10,
		MaxRedirectLocationBytes:    8 << 10,
		Method:                      "GET",
		ReportVerbosity:             ReportVerbosityNormal,
		UserAgent:                   "Orynelo/diagnostic",
		CertificateWarningThreshold: 30 * 24 * time.Hour,
		MaxConcurrency:              4,
		BodyLimit:                   64 << 10,
		ExpectedStatusMin:           200,
		ExpectedStatusMax:           399,
		InspectBody:                 false,
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
	ID            string              `json:"id"`
	Target        Target              `json:"target"`
	Options       DiagnoseOptions     `json:"options"`
	StartedAt     time.Time           `json:"startedAt"`
	FinishedAt    time.Time           `json:"finishedAt"`
	Duration      time.Duration       `json:"duration"`
	Checks        []CheckResult       `json:"checks"`
	NetworkPaths  []NetworkPath       `json:"networkPaths,omitempty"`
	Summary       Summary             `json:"summary"`
	Build         BuildInfo           `json:"build"`
	EventDelivery *EventDeliveryStats `json:"eventDelivery,omitempty"`
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

// ProxySelectionValidity describes whether a configured proxy can safely be
// used for the target. Invalid selections must never degrade to direct HTTP.
type ProxySelectionValidity string

const (
	ProxyValidityNotConfigured ProxySelectionValidity = "not_configured"
	ProxyValidityValid         ProxySelectionValidity = "valid"
	ProxyValidityInvalid       ProxySelectionValidity = "invalid"
	ProxyValidityNotApplicable ProxySelectionValidity = "not_applicable"
)

// ProxyBypassReason makes every direct route chosen in the presence of proxy
// configuration explicit and reportable.
type ProxyBypassReason string

const (
	ProxyBypassNone          ProxyBypassReason = ""
	ProxyBypassDisabled      ProxyBypassReason = "explicitly_disabled"
	ProxyBypassNoProxy       ProxyBypassReason = "no_proxy_match"
	ProxyBypassLoopback      ProxyBypassReason = "loopback_target"
	ProxyBypassNotApplicable ProxyBypassReason = "target_not_applicable"
)

// ProxySelection is the typed result of applying one immutable environment
// snapshot to a target. RequestURL may contain credentials and is therefore
// runtime-only; URL is its redacted, report-safe representation.
type ProxySelection struct {
	SourceVariable string                 `json:"sourceVariable,omitempty"`
	URL            string                 `json:"url,omitempty"`
	Validity       ProxySelectionValidity `json:"validity"`
	BypassReason   ProxyBypassReason      `json:"bypassReason,omitempty"`
	ErrorCode      string                 `json:"errorCode,omitempty"`
	Error          string                 `json:"error,omitempty"`
	RequestURL     string                 `json:"-"`
}

// ProxyInfo records privacy-safe environment/proxy selection. The legacy
// summary fields remain populated for old snapshot and presentation readers.
type ProxyInfo struct {
	Disabled     bool                          `json:"disabled"`
	Selected     bool                          `json:"selected"`
	Bypassed     bool                          `json:"bypassed"`
	ProxyURL     string                        `json:"proxyUrl,omitempty"`
	Environment  map[string]string             `json:"environment,omitempty"`
	Selection    ProxySelection                `json:"selection"`
	SelectForURL func(*url.URL) ProxySelection `json:"-"`
}

// DNSFamilyStatus classifies the outcome of one address-family lookup without
// relying on platform-specific resolver error text.
type DNSFamilyStatus string

const (
	DNSFamilyStatusSuccess         DNSFamilyStatus = "success"
	DNSFamilyStatusNXDOMAIN        DNSFamilyStatus = "nxdomain"
	DNSFamilyStatusNoData          DNSFamilyStatus = "nodata"
	DNSFamilyStatusNotFoundUnknown DNSFamilyStatus = "not_found_unknown"
	DNSFamilyStatusSERVFAIL        DNSFamilyStatus = "servfail"
	DNSFamilyStatusTimeout         DNSFamilyStatus = "timeout"
	DNSFamilyStatusCancelled       DNSFamilyStatus = "cancelled"
	DNSFamilyStatusFamilyMismatch  DNSFamilyStatus = "family_mismatch"
	DNSFamilyStatusError           DNSFamilyStatus = "error"
)

// DNSFamilyResult contains the typed, correlated result of one A or AAAA
// lookup. The legacy DNSResult summary fields remain populated for old readers.
type DNSFamilyResult struct {
	NetworkRef *NetworkRef     `json:"networkRef,omitempty"`
	Family     string          `json:"family"`
	RecordType string          `json:"recordType"`
	Status     DNSFamilyStatus `json:"status"`
	Addresses  []net.IP        `json:"addresses,omitempty"`
	Duration   time.Duration   `json:"duration"`
	ErrorCode  string          `json:"errorCode,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// DNSResult stores canonical, de-duplicated resolver output.
type DNSResult struct {
	IPv4           []net.IP          `json:"ipv4,omitempty"`
	IPv6           []net.IP          `json:"ipv6,omitempty"`
	AError         string            `json:"aError,omitempty"`
	AAAAError      string            `json:"aaaaError,omitempty"`
	ADuration      time.Duration     `json:"aDuration"`
	AAAADuration   time.Duration     `json:"aaaaDuration"`
	Families       []DNSFamilyResult `json:"families,omitempty"`
	CNAMEs         []string          `json:"cnames,omitempty"`
	TTL            time.Duration     `json:"ttl,omitempty"`
	ResolverSource string            `json:"resolverSource,omitempty"`
	SearchDomains  []string          `json:"searchDomains,omitempty"`
}

// AttemptState describes the lifecycle of one address-specific network
// attempt. The field is optional in serialized snapshots so diagnoses written
// before attempt states were introduced remain readable.
type AttemptState string

const (
	AttemptStateQueued    AttemptState = "queued"
	AttemptStateRunning   AttemptState = "running"
	AttemptStateCompleted AttemptState = "completed"
	AttemptStateCancelled AttemptState = "cancelled"
	AttemptStateSkipped   AttemptState = "skipped"
)

// Valid reports whether state is part of the stable attempt vocabulary.
func (s AttemptState) Valid() bool {
	switch s {
	case AttemptStateQueued, AttemptStateRunning, AttemptStateCompleted,
		AttemptStateCancelled, AttemptStateSkipped:
		return true
	default:
		return false
	}
}

// RouteInfo describes the source-side path selected for a remote address.
type RouteInfo struct {
	NetworkRef    *NetworkRef  `json:"networkRef,omitempty"`
	RemoteIP      net.IP       `json:"remoteIp"`
	LocalIP       net.IP       `json:"localIp,omitempty"`
	InterfaceName string       `json:"interfaceName,omitempty"`
	InterfaceUp   bool         `json:"interfaceUp"`
	MTU           int          `json:"mtu,omitempty"`
	Family        string       `json:"family"`
	Error         string       `json:"error,omitempty"`
	State         AttemptState `json:"state,omitempty"`
	Selected      bool         `json:"selected,omitempty"`
}

// TCPAttempt is a single bounded TCP connect attempt.
type TCPAttempt struct {
	NetworkRef *NetworkRef   `json:"networkRef,omitempty"`
	RemoteIP   net.IP        `json:"remoteIp"`
	LocalAddr  string        `json:"localAddr,omitempty"`
	Duration   time.Duration `json:"duration"`
	Success    bool          `json:"success"`
	ErrorCode  string        `json:"errorCode,omitempty"`
	Error      string        `json:"error,omitempty"`
	State      AttemptState  `json:"state,omitempty"`
	Selected   bool          `json:"selected,omitempty"`
}

// CertificateInfo contains report-safe peer certificate metadata.
type CertificateInfo struct {
	Subject            string        `json:"subject,omitempty"`
	Issuer             string        `json:"issuer,omitempty"`
	SerialNumber       string        `json:"serialNumber,omitempty"`
	DNSNames           []string      `json:"dnsNames,omitempty"`
	IPAddresses        []string      `json:"ipAddresses,omitempty"`
	NotBefore          time.Time     `json:"notBefore,omitempty"`
	NotAfter           time.Time     `json:"notAfter,omitempty"`
	Remaining          time.Duration `json:"remaining,omitempty"`
	ChainLength        int           `json:"chainLength"`
	HostnameValid      bool          `json:"hostnameValid"`
	SystemTrusted      bool          `json:"systemTrusted"`
	PublicKeyAlgorithm string        `json:"publicKeyAlgorithm,omitempty"`
	PublicKeyCurve     string        `json:"publicKeyCurve,omitempty"`
	PublicKeyBits      int           `json:"publicKeyBits,omitempty"`
	SignatureAlgorithm string        `json:"signatureAlgorithm,omitempty"`
	IsCA               bool          `json:"isCa,omitempty"`
}

// TLSResult stores negotiated transport and certificate information.
type TLSResult struct {
	NetworkRef        *NetworkRef       `json:"networkRef,omitempty"`
	RemoteIP          net.IP            `json:"remoteIp,omitempty"`
	ServerName        string            `json:"serverName,omitempty"`
	Version           string            `json:"version,omitempty"`
	CipherSuite       string            `json:"cipherSuite,omitempty"`
	ALPN              string            `json:"alpn,omitempty"`
	Certificate       CertificateInfo   `json:"certificate"`
	Chain             []CertificateInfo `json:"chain,omitempty"`
	Insecure          bool              `json:"insecure"`
	Duration          time.Duration     `json:"duration"`
	TCPDuration       time.Duration     `json:"tcpDuration,omitempty"`
	HandshakeDuration time.Duration     `json:"handshakeDuration,omitempty"`
	ErrorCode         string            `json:"errorCode,omitempty"`
	Error             string            `json:"error,omitempty"`
}

// TLSAttempt is one address-specific TCP connection and TLS negotiation. The
// legacy TLSResult remains the selected-attempt projection for old readers.
type TLSAttempt struct {
	NetworkRef
	State             AttemptState      `json:"state,omitempty"`
	RemoteIP          net.IP            `json:"remoteIp,omitempty"`
	ServerName        string            `json:"serverName,omitempty"`
	StartedAt         time.Time         `json:"startedAt,omitempty"`
	FinishedAt        time.Time         `json:"finishedAt,omitempty"`
	Duration          time.Duration     `json:"duration"`
	TCPDuration       time.Duration     `json:"tcpDuration,omitempty"`
	HandshakeDuration time.Duration     `json:"handshakeDuration,omitempty"`
	Success           bool              `json:"success"`
	Selected          bool              `json:"selected,omitempty"`
	Version           string            `json:"version,omitempty"`
	CipherSuite       string            `json:"cipherSuite,omitempty"`
	ALPN              string            `json:"alpn,omitempty"`
	Certificate       CertificateInfo   `json:"certificate"`
	Chain             []CertificateInfo `json:"chain,omitempty"`
	Insecure          bool              `json:"insecure"`
	ErrorCode         string            `json:"errorCode,omitempty"`
	Error             string            `json:"error,omitempty"`
}

// Redirect records one privacy-safe HTTP redirect.
type Redirect struct {
	From                    string         `json:"from"`
	To                      string         `json:"to"`
	StatusCode              int            `json:"statusCode"`
	CrossOrigin             bool           `json:"crossOrigin"`
	SensitiveHeadersRemoved []string       `json:"sensitiveHeadersRemoved,omitempty"`
	PolicyDecision          string         `json:"policyDecision"`
	FromNetworkScope        string         `json:"fromNetworkScope,omitempty"`
	ToNetworkScope          string         `json:"toNetworkScope,omitempty"`
	Route                   string         `json:"route"`
	ProxySelection          ProxySelection `json:"proxySelection"`
	FromNetworkRef          *NetworkRef    `json:"fromNetworkRef,omitempty"`
	ToNetworkRef            *NetworkRef    `json:"toNetworkRef,omitempty"`
}

// HTTPTimings exposes the major httptrace phases.
type HTTPTimings struct {
	DNS       time.Duration `json:"dns"`
	TCP       time.Duration `json:"tcp"`
	TLS       time.Duration `json:"tls"`
	FirstByte time.Duration `json:"firstByte"`
	Total     time.Duration `json:"total"`
}

// HTTPConnectAttempt is one connect callback observed by httptrace.
type HTTPConnectAttempt struct {
	NetworkRef
	Network    string        `json:"network,omitempty"`
	Address    string        `json:"address,omitempty"`
	StartedAt  time.Time     `json:"startedAt,omitempty"`
	FinishedAt time.Time     `json:"finishedAt,omitempty"`
	Duration   time.Duration `json:"duration"`
	Selected   bool          `json:"selected,omitempty"`
	ErrorCode  string        `json:"errorCode,omitempty"`
	Error      string        `json:"error,omitempty"`
}

// HTTPHop records one request/response leg, including redirects, without
// collapsing independent connect attempts into aggregate timing fields.
type HTTPHop struct {
	NetworkRef
	URL             string               `json:"url,omitempty"`
	StatusCode      int                  `json:"statusCode,omitempty"`
	Status          string               `json:"status,omitempty"`
	Timings         HTTPTimings          `json:"timings"`
	RemoteIP        string               `json:"remoteIp,omitempty"`
	LocalIP         string               `json:"localIp,omitempty"`
	Reused          bool                 `json:"reused,omitempty"`
	Route           string               `json:"route,omitempty"`
	ProxySelection  ProxySelection       `json:"proxySelection"`
	ConnectAttempts []HTTPConnectAttempt `json:"connectAttempts,omitempty"`
}

// HTTPResult stores bounded, redacted application-response metadata.
type HTTPResult struct {
	Method            string                 `json:"method"`
	FinalURL          string                 `json:"finalUrl"`
	StatusCode        int                    `json:"statusCode"`
	Status            string                 `json:"status"`
	Redirects         []Redirect             `json:"redirects,omitempty"`
	Hops              []HTTPHop              `json:"hops,omitempty"`
	Headers           map[string][]string    `json:"headers,omitempty"`
	Timings           HTTPTimings            `json:"timings"`
	RemoteIP          string                 `json:"remoteIp,omitempty"`
	Protocol          string                 `json:"protocol,omitempty"`
	BodyBytesRead     int64                  `json:"bodyBytesRead"`
	BodyTruncated     bool                   `json:"bodyTruncated"`
	Route             string                 `json:"route"`
	ProxySource       string                 `json:"proxySource,omitempty"`
	ProxyURL          string                 `json:"proxyUrl,omitempty"`
	ProxyValidity     ProxySelectionValidity `json:"proxyValidity,omitempty"`
	ProxyBypassReason ProxyBypassReason      `json:"proxyBypassReason,omitempty"`
	ErrorCode         string                 `json:"errorCode,omitempty"`
	Error             string                 `json:"error,omitempty"`
}

// State carries mutable artifacts between checks. It is per diagnosis and
// guarded because independent checks may run concurrently.
type State struct {
	Target  Target
	Options DiagnoseOptions

	mu           sync.RWMutex
	proxy        ProxyInfo
	dns          DNSResult
	routes       []RouteInfo
	tcp          []TCPAttempt
	tls          TLSResult
	tlsAttempts  []TLSAttempt
	http         HTTPResult
	networkPaths []NetworkPath
}

// NewState constructs isolated state for one run.
func NewState(target Target, options DiagnoseOptions) *State {
	return &State{Target: target, Options: cloneDiagnoseOptions(options)}
}

// SetProxy stores the privacy-safe proxy selection state.
func (s *State) SetProxy(v ProxyInfo) { s.mu.Lock(); s.proxy = cloneProxy(v); s.mu.Unlock() }

// Proxy returns an independent copy of the proxy selection state.
func (s *State) Proxy() ProxyInfo { s.mu.RLock(); defer s.mu.RUnlock(); return cloneProxy(s.proxy) }

// SetDNS stores resolver output for later checks.
func (s *State) SetDNS(v DNSResult) { s.mu.Lock(); s.dns = cloneDNS(v); s.mu.Unlock() }

// DNS returns an independent copy of resolver output.
func (s *State) DNS() DNSResult { s.mu.RLock(); defer s.mu.RUnlock(); return cloneDNS(s.dns) }

// SetRoutes stores discovered routes for later checks.
func (s *State) SetRoutes(v []RouteInfo) {
	s.mu.Lock()
	s.routes = cloneRoutes(v)
	s.mu.Unlock()
}

// Routes returns an independent copy of discovered routes.
func (s *State) Routes() []RouteInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRoutes(s.routes)
}

// SetTCP stores address-specific TCP attempts.
func (s *State) SetTCP(v []TCPAttempt) {
	s.mu.Lock()
	s.tcp = cloneTCP(v)
	s.mu.Unlock()
}

// TCP returns an independent copy of TCP attempts.
func (s *State) TCP() []TCPAttempt {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneTCP(s.tcp)
}

// SetTLS stores the TLS result for later checks and reports.
func (s *State) SetTLS(v TLSResult) { s.mu.Lock(); s.tls = cloneTLS(v); s.mu.Unlock() }

// TLS returns an independent copy of the TLS result.
func (s *State) TLS() TLSResult { s.mu.RLock(); defer s.mu.RUnlock(); return cloneTLS(s.tls) }

// SetTLSAttempts stores all address-specific TLS attempts.
func (s *State) SetTLSAttempts(v []TLSAttempt) {
	s.mu.Lock()
	s.tlsAttempts = cloneTLSAttempts(v)
	s.mu.Unlock()
}

// TLSAttempts returns an independent copy of all address-specific TLS attempts.
func (s *State) TLSAttempts() []TLSAttempt {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneTLSAttempts(s.tlsAttempts)
}

// SetHTTP stores the HTTP result for later checks and reports.
func (s *State) SetHTTP(v HTTPResult) { s.mu.Lock(); s.http = cloneHTTP(v); s.mu.Unlock() }

// HTTP returns an independent copy of the HTTP result.
func (s *State) HTTP() HTTPResult { s.mu.RLock(); defer s.mu.RUnlock(); return cloneHTTP(s.http) }

// SetNetworkPaths stores the correlated network graph for this diagnosis.
func (s *State) SetNetworkPaths(v []NetworkPath) {
	s.mu.Lock()
	s.networkPaths = cloneNetworkPaths(v)
	s.mu.Unlock()
}

// NetworkPaths returns an independent copy of the correlated network graph.
func (s *State) NetworkPaths() []NetworkPath {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneNetworkPaths(s.networkPaths)
}

func cloneProxy(v ProxyInfo) ProxyInfo {
	v.Environment = cloneStringMap(v.Environment)
	return v
}

func cloneDNS(v DNSResult) DNSResult {
	v.IPv4 = cloneIPs(v.IPv4)
	v.IPv6 = cloneIPs(v.IPv6)
	if v.Families != nil {
		families := append([]DNSFamilyResult(nil), v.Families...)
		for index := range families {
			families[index].NetworkRef = cloneNetworkRef(v.Families[index].NetworkRef)
			families[index].Addresses = cloneIPs(v.Families[index].Addresses)
		}
		v.Families = families
	}
	v.CNAMEs = append([]string(nil), v.CNAMEs...)
	v.SearchDomains = append([]string(nil), v.SearchDomains...)
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
		out[index].NetworkRef = cloneNetworkRef(values[index].NetworkRef)
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
		out[index].NetworkRef = cloneNetworkRef(values[index].NetworkRef)
		out[index].RemoteIP = append(net.IP(nil), values[index].RemoteIP...)
	}
	return out
}

func cloneTLS(value TLSResult) TLSResult {
	value.NetworkRef = cloneNetworkRef(value.NetworkRef)
	value.RemoteIP = append(net.IP(nil), value.RemoteIP...)
	value.Certificate = cloneCertificate(value.Certificate)
	value.Chain = cloneCertificates(value.Chain)
	return value
}

func cloneTLSAttempts(values []TLSAttempt) []TLSAttempt {
	if values == nil {
		return nil
	}
	out := append([]TLSAttempt(nil), values...)
	for index := range out {
		out[index].RemoteIP = append(net.IP(nil), values[index].RemoteIP...)
		out[index].Certificate = cloneCertificate(values[index].Certificate)
		out[index].Chain = cloneCertificates(values[index].Chain)
	}
	return out
}

func cloneCertificate(value CertificateInfo) CertificateInfo {
	value.DNSNames = append([]string(nil), value.DNSNames...)
	value.IPAddresses = append([]string(nil), value.IPAddresses...)
	return value
}

func cloneCertificates(values []CertificateInfo) []CertificateInfo {
	if values == nil {
		return nil
	}
	out := append([]CertificateInfo(nil), values...)
	for index := range out {
		out[index] = cloneCertificate(values[index])
	}
	return out
}

func cloneHTTP(v HTTPResult) HTTPResult {
	v.Redirects = append([]Redirect(nil), v.Redirects...)
	for index := range v.Redirects {
		v.Redirects[index].FromNetworkRef = cloneNetworkRef(v.Redirects[index].FromNetworkRef)
		v.Redirects[index].ToNetworkRef = cloneNetworkRef(v.Redirects[index].ToNetworkRef)
		v.Redirects[index].SensitiveHeadersRemoved = append(
			[]string(nil),
			v.Redirects[index].SensitiveHeadersRemoved...,
		)
	}
	if v.Headers != nil {
		headers := v.Headers
		v.Headers = make(map[string][]string, len(headers))
		for key, values := range headers {
			v.Headers[key] = append([]string(nil), values...)
		}
	}
	if v.Hops != nil {
		v.Hops = append([]HTTPHop(nil), v.Hops...)
		for index := range v.Hops {
			v.Hops[index].ConnectAttempts = append(
				[]HTTPConnectAttempt(nil),
				v.Hops[index].ConnectAttempts...,
			)
		}
	}
	return v
}

func cloneNetworkPaths(values []NetworkPath) []NetworkPath {
	if values == nil {
		return nil
	}
	out := append([]NetworkPath(nil), values...)
	for pathIndex := range out {
		out[pathIndex].Hops = append([]NetworkHop(nil), values[pathIndex].Hops...)
		for hopIndex := range out[pathIndex].Hops {
			hop := &out[pathIndex].Hops[hopIndex]
			hop.RemoteIP = append(net.IP(nil), values[pathIndex].Hops[hopIndex].RemoteIP...)
			hop.Attempts = append(
				[]NetworkAttempt(nil),
				values[pathIndex].Hops[hopIndex].Attempts...,
			)
			for attemptIndex := range hop.Attempts {
				hop.Attempts[attemptIndex].RemoteIP = append(
					net.IP(nil),
					values[pathIndex].Hops[hopIndex].Attempts[attemptIndex].RemoteIP...,
				)
			}
			hop.Timings = append(
				[]PhaseTiming(nil),
				values[pathIndex].Hops[hopIndex].Timings...,
			)
		}
	}
	return out
}

func cloneNetworkRef(value *NetworkRef) *NetworkRef {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneDiagnoseOptions(value DiagnoseOptions) DiagnoseOptions {
	value.CustomCAPEM = append([]byte(nil), value.CustomCAPEM...)
	value.RequestHeaderNames = append([]string(nil), value.RequestHeaderNames...)
	value.RequestHeaders = cloneStringMap(value.RequestHeaders)
	return value
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
