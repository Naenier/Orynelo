package http

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

const httpConnectAttemptError = "HTTP_CONNECT_ATTEMPT_FAILED"

type tracingRoundTripper struct {
	base        stdhttp.RoundTripper
	recorder    *httpTraceRecorder
	inspectBody bool
}

func (t *tracingRoundTripper) RoundTrip(request *stdhttp.Request) (*stdhttp.Response, error) {
	hop := t.recorder.begin(request)
	traced := request.WithContext(httptrace.WithClientTrace(request.Context(), hop.trace()))
	response, err := t.base.RoundTrip(traced)
	hop.recordResponse(response)
	if err != nil {
		hop.finish()
		return response, err
	}
	if response == nil {
		hop.finish()
		return nil, nil
	}
	if response.Request == nil {
		response.Request = traced
	}
	if response.Body == nil {
		hop.finish()
		return response, nil
	}
	if !t.inspectBody {
		response.Body = &uninspectedResponseBody{ReadCloser: response.Body}
	}
	response.Body = &tracedResponseBody{
		ReadCloser: response.Body,
		finish:     hop.finish,
	}
	return response, nil
}

type uninspectedResponseBody struct {
	io.ReadCloser
}

func (*uninspectedResponseBody) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (t *tracingRoundTripper) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

type tracedResponseBody struct {
	io.ReadCloser
	once   sync.Once
	finish func()
}

func (b *tracedResponseBody) Read(buffer []byte) (int, error) {
	n, err := b.ReadCloser.Read(buffer)
	if errors.Is(err, io.EOF) {
		b.once.Do(b.finish)
	}
	return n, err
}

func (b *tracedResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.finish)
	return err
}

type httpTraceRecorder struct {
	mu             sync.Mutex
	now            func() time.Time
	selectProxy    func(*url.URL) model.ProxySelection
	hops           []*httpHopTrace
	paths          []*httpPathTrace
	currentPath    *httpPathTrace
	overallStarted time.Time
}

type httpPathTrace struct {
	id                 string
	role               model.NetworkPathRole
	kind               model.NetworkPathKind
	sequence           int
	redirectFromPathID string
	signature          string
	nextHopSequence    int
}

func newHTTPTraceRecorder(
	now func() time.Time,
	overallStarted time.Time,
	selectProxy func(*url.URL) model.ProxySelection,
) *httpTraceRecorder {
	if now == nil {
		now = time.Now
	}
	return &httpTraceRecorder{
		now:            now,
		selectProxy:    selectProxy,
		overallStarted: overallStarted,
	}
}

func (r *httpTraceRecorder) begin(request *stdhttp.Request) *httpHopTrace {
	r.mu.Lock()
	defer r.mu.Unlock()

	selection := model.ProxySelection{Validity: model.ProxyValidityNotConfigured}
	if r.selectProxy != nil && request != nil {
		selection = r.selectProxy(request.URL)
	}
	selection = reportableProxySelection(selection)
	route := proxySelectionRoute(selection)
	kind := pathKindForRequest(request, route)
	signature := pathSignature(kind, selection)
	if r.currentPath == nil || r.currentPath.signature != signature {
		pathSequence := len(r.paths) + 1
		redirectFrom := ""
		if r.currentPath != nil {
			redirectFrom = r.currentPath.id
		}
		r.currentPath = &httpPathTrace{
			id:                 fmt.Sprintf("http-client-path-%d", pathSequence),
			role:               model.NetworkPathRoleClientEffective,
			kind:               kind,
			sequence:           pathSequence,
			redirectFromPathID: redirectFrom,
			signature:          signature,
		}
		r.paths = append(r.paths, r.currentPath)
	}

	path := r.currentPath
	globalSequence := len(r.hops) + 1
	var peerRef model.NetworkRef
	if route == "proxy" {
		peerRef = model.NetworkRef{
			PathID: path.id,
			HopID:  path.nextHopID(),
		}
	}
	originRef := model.NetworkRef{
		PathID: path.id,
		HopID:  path.nextHopID(),
	}
	connectRef := originRef
	if peerRef.HopID != "" {
		connectRef = peerRef
	}
	httpAttemptID := originRef.HopID + "-http"
	originRef.AttemptID = httpAttemptID

	var requestURL *url.URL
	if request != nil {
		requestURL = cloneURL(request.URL)
	}
	hop := &httpHopTrace{
		now:            r.now,
		sequence:       globalSequence,
		requestURL:     requestURL,
		safeURL:        SafeURL(requestURL),
		selection:      selection,
		route:          route,
		originRef:      originRef,
		peerRef:        peerRef,
		connectRef:     connectRef,
		httpAttemptID:  httpAttemptID,
		requestStarted: r.now(),
	}
	r.hops = append(r.hops, hop)
	return hop
}

func (p *httpPathTrace) nextHopID() string {
	p.nextHopSequence++
	return fmt.Sprintf("%s-hop-%d", p.id, p.nextHopSequence)
}

func pathKindForRequest(request *stdhttp.Request, route string) model.NetworkPathKind {
	if route != "proxy" {
		return model.NetworkPathDirect
	}
	if request != nil && request.URL != nil && strings.EqualFold(request.URL.Scheme, "https") {
		return model.NetworkPathHTTPSConnect
	}
	return model.NetworkPathHTTPProxy
}

func pathSignature(kind model.NetworkPathKind, selection model.ProxySelection) string {
	return strings.Join([]string{
		string(kind),
		selection.SourceVariable,
		selection.URL,
		string(selection.Validity),
		string(selection.BypassReason),
	}, "\x00")
}

type httpHopTrace struct {
	mu sync.Mutex

	now             func() time.Time
	sequence        int
	requestURL      *url.URL
	safeURL         string
	selection       model.ProxySelection
	route           string
	originRef       model.NetworkRef
	peerRef         model.NetworkRef
	connectRef      model.NetworkRef
	httpAttemptID   string
	requestStarted  time.Time
	requestFinished time.Time
	statusCode      int
	status          string
	remoteAddress   string
	localAddress    string
	reused          bool
	firstByte       time.Time
	dnsAttempts     []*httpPhaseAttempt
	tlsAttempts     []*httpPhaseAttempt
	connectAttempts []*httpConnectAttemptTrace
}

type httpPhaseAttempt struct {
	id         string
	startedAt  time.Time
	finishedAt time.Time
	errorCode  string
	error      string
}

type httpConnectAttemptTrace struct {
	id         string
	network    string
	address    string
	startedAt  time.Time
	finishedAt time.Time
	selected   bool
	errorCode  string
	error      string
}

func (h *httpHopTrace) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			h.mu.Lock()
			h.dnsAttempts = append(h.dnsAttempts, &httpPhaseAttempt{
				id:        fmt.Sprintf("%s-dns-%d", h.connectRef.HopID, len(h.dnsAttempts)+1),
				startedAt: h.now(),
			})
			h.mu.Unlock()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			h.mu.Lock()
			attempt := firstOpenPhase(h.dnsAttempts)
			if attempt != nil {
				attempt.finishedAt = h.now()
				attempt.errorCode, attempt.error = safeAttemptFailure(info.Err)
			}
			h.mu.Unlock()
		},
		ConnectStart: func(network, address string) {
			h.mu.Lock()
			h.connectAttempts = append(h.connectAttempts, &httpConnectAttemptTrace{
				id:        fmt.Sprintf("%s-connect-%d", h.connectRef.HopID, len(h.connectAttempts)+1),
				network:   network,
				address:   address,
				startedAt: h.now(),
			})
			h.mu.Unlock()
		},
		ConnectDone: func(network, address string, err error) {
			h.mu.Lock()
			attempt := firstOpenConnect(h.connectAttempts, network, address)
			if attempt != nil {
				attempt.finishedAt = h.now()
				attempt.errorCode, attempt.error = safeAttemptFailure(err)
			}
			h.mu.Unlock()
		},
		TLSHandshakeStart: func() {
			h.mu.Lock()
			h.tlsAttempts = append(h.tlsAttempts, &httpPhaseAttempt{
				id:        fmt.Sprintf("%s-tls-%d", h.originRef.HopID, len(h.tlsAttempts)+1),
				startedAt: h.now(),
			})
			h.mu.Unlock()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			h.mu.Lock()
			attempt := firstOpenPhase(h.tlsAttempts)
			if attempt != nil {
				attempt.finishedAt = h.now()
				attempt.errorCode, attempt.error = safeAttemptFailure(err)
			}
			h.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			h.mu.Lock()
			if h.firstByte.IsZero() {
				h.firstByte = h.now()
			}
			h.mu.Unlock()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			h.mu.Lock()
			h.reused = info.Reused
			if info.Conn != nil {
				h.remoteAddress = info.Conn.RemoteAddr().String()
				h.localAddress = info.Conn.LocalAddr().String()
			}
			if !info.Reused {
				selectConnectAttempt(h.connectAttempts, h.remoteAddress)
			}
			h.mu.Unlock()
		},
	}
}

func firstOpenPhase(attempts []*httpPhaseAttempt) *httpPhaseAttempt {
	for _, attempt := range attempts {
		if attempt != nil && attempt.finishedAt.IsZero() {
			return attempt
		}
	}
	return nil
}

func firstOpenConnect(
	attempts []*httpConnectAttemptTrace,
	network string,
	address string,
) *httpConnectAttemptTrace {
	for _, attempt := range attempts {
		if attempt != nil && attempt.finishedAt.IsZero() &&
			attempt.network == network && attempt.address == address {
			return attempt
		}
	}
	return nil
}

func selectConnectAttempt(attempts []*httpConnectAttemptTrace, remote string) {
	for index := len(attempts) - 1; index >= 0; index-- {
		attempt := attempts[index]
		if attempt == nil || attempt.errorCode != "" {
			continue
		}
		if sameDialEndpoint(attempt.address, remote) {
			attempt.selected = true
			return
		}
	}
	for index := len(attempts) - 1; index >= 0; index-- {
		attempt := attempts[index]
		if attempt != nil && attempt.errorCode == "" && !attempt.finishedAt.IsZero() {
			attempt.selected = true
			return
		}
	}
}

func sameDialEndpoint(left, right string) bool {
	leftHost, leftPort, leftErr := net.SplitHostPort(left)
	rightHost, rightPort, rightErr := net.SplitHostPort(right)
	if leftErr == nil && rightErr == nil {
		return strings.EqualFold(leftHost, rightHost) && leftPort == rightPort
	}
	return strings.EqualFold(left, right)
}

func safeAttemptFailure(err error) (string, string) {
	if err == nil {
		return "", ""
	}
	code := httpConnectAttemptError
	message := "network attempt failed"
	switch {
	case errors.Is(err, context.Canceled):
		code = ErrorCancelled
		message = "network attempt was cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		code = ErrorTimeout
		message = "network attempt timed out"
	default:
		var netError net.Error
		if errors.As(err, &netError) && netError.Timeout() {
			code = ErrorTimeout
			message = "network attempt timed out"
		}
	}
	return code, message
}

func (h *httpHopTrace) recordResponse(response *stdhttp.Response) {
	if response == nil {
		return
	}
	h.mu.Lock()
	h.statusCode = response.StatusCode
	h.status = response.Status
	h.mu.Unlock()
}

func (h *httpHopTrace) finish() {
	h.mu.Lock()
	if h.requestFinished.IsZero() {
		h.requestFinished = h.now()
	}
	h.mu.Unlock()
}

type httpTraceSnapshot struct {
	hops        []model.HTTPHop
	paths       []model.NetworkPath
	timings     model.HTTPTimings
	remoteIP    string
	networkRefs []model.NetworkRef
}

func (r *httpTraceRecorder) snapshot(overallFinished time.Time) httpTraceSnapshot {
	r.mu.Lock()
	hops := append([]*httpHopTrace(nil), r.hops...)
	paths := append([]*httpPathTrace(nil), r.paths...)
	overallStarted := r.overallStarted
	r.mu.Unlock()

	result := httpTraceSnapshot{
		hops: make([]model.HTTPHop, 0, len(hops)),
	}
	for _, trace := range hops {
		trace.finish()
		hop := trace.snapshotHTTPHop()
		result.hops = append(result.hops, hop)
		result.networkRefs = append(result.networkRefs, hop.NetworkRef)
		result.timings.DNS += hop.Timings.DNS
		result.timings.TCP += hop.Timings.TCP
		result.timings.TLS += hop.Timings.TLS
		if result.timings.FirstByte == 0 && hop.Timings.FirstByte > 0 {
			result.timings.FirstByte = trace.firstByteOffset(overallStarted)
		}
		if trace.remoteHost() != "" {
			result.remoteIP = trace.remoteHost()
		}
	}
	if overallFinished.IsZero() {
		overallFinished = r.now()
	}
	if !overallStarted.IsZero() && overallFinished.After(overallStarted) {
		result.timings.Total = overallFinished.Sub(overallStarted)
	}
	result.paths = snapshotNetworkPaths(paths, hops)
	return result
}

func (r *httpTraceRecorder) lastRemoteAddress() string {
	r.mu.Lock()
	if len(r.hops) == 0 {
		r.mu.Unlock()
		return ""
	}
	hop := r.hops[len(r.hops)-1]
	r.mu.Unlock()
	return hop.remoteHost()
}

func (h *httpHopTrace) snapshotHTTPHop() model.HTTPHop {
	h.mu.Lock()
	defer h.mu.Unlock()

	remoteIP := hostOnly(h.remoteAddress)
	localIP := hostOnly(h.localAddress)
	// For a proxy route these socket endpoints belong to the proxy peer, not
	// the origin represented by the HTTP hop reference. They remain available
	// on the proxy-peer NetworkHop and connect attempts instead.
	if h.route == "proxy" {
		remoteIP = ""
		localIP = ""
	}
	return model.HTTPHop{
		NetworkRef:      h.originRef,
		URL:             h.safeURL,
		StatusCode:      h.statusCode,
		Status:          h.status,
		Timings:         h.timingsLocked(),
		RemoteIP:        remoteIP,
		LocalIP:         localIP,
		Reused:          h.reused,
		Route:           h.route,
		ProxySelection:  h.selection,
		ConnectAttempts: h.connectAttemptSnapshotsLocked(),
	}
}

func (h *httpHopTrace) timingsLocked() model.HTTPTimings {
	var timings model.HTTPTimings
	for _, attempt := range h.dnsAttempts {
		timings.DNS += phaseDuration(attempt.startedAt, attempt.finishedAt)
	}
	for _, attempt := range h.connectAttempts {
		if attempt.selected {
			timings.TCP = phaseDuration(attempt.startedAt, attempt.finishedAt)
			break
		}
	}
	if timings.TCP == 0 {
		for _, attempt := range h.connectAttempts {
			timings.TCP += phaseDuration(attempt.startedAt, attempt.finishedAt)
		}
	}
	for _, attempt := range h.tlsAttempts {
		timings.TLS += phaseDuration(attempt.startedAt, attempt.finishedAt)
	}
	if !h.firstByte.IsZero() {
		timings.FirstByte = phaseDuration(h.requestStarted, h.firstByte)
	}
	timings.Total = phaseDuration(h.requestStarted, h.requestFinished)
	return timings
}

func (h *httpHopTrace) connectAttemptSnapshotsLocked() []model.HTTPConnectAttempt {
	if len(h.connectAttempts) == 0 {
		return nil
	}
	attempts := make([]model.HTTPConnectAttempt, 0, len(h.connectAttempts))
	for _, attempt := range h.connectAttempts {
		attempts = append(attempts, model.HTTPConnectAttempt{
			NetworkRef: model.NetworkRef{
				PathID:    h.connectRef.PathID,
				HopID:     h.connectRef.HopID,
				AttemptID: attempt.id,
			},
			Network:    attempt.network,
			Address:    attempt.address,
			StartedAt:  attempt.startedAt,
			FinishedAt: attempt.finishedAt,
			Duration:   phaseDuration(attempt.startedAt, attempt.finishedAt),
			Selected:   attempt.selected,
			ErrorCode:  attempt.errorCode,
			Error:      attempt.error,
		})
	}
	return attempts
}

func (h *httpHopTrace) firstByteOffset(start time.Time) time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	return phaseDuration(start, h.firstByte)
}

func (h *httpHopTrace) remoteHost() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return hostOnly(h.remoteAddress)
}

func phaseDuration(start, finish time.Time) time.Duration {
	if start.IsZero() || finish.IsZero() || finish.Before(start) {
		return 0
	}
	return finish.Sub(start)
}

func hostOnly(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return host
	}
	return address
}

func snapshotNetworkPaths(
	paths []*httpPathTrace,
	hops []*httpHopTrace,
) []model.NetworkPath {
	result := make([]model.NetworkPath, 0, len(paths))
	for _, pathTrace := range paths {
		path := model.NetworkPath{
			ID:                 pathTrace.id,
			Role:               pathTrace.role,
			Kind:               pathTrace.kind,
			Sequence:           pathTrace.sequence,
			RedirectFromPathID: pathTrace.redirectFromPathID,
		}
		for _, hopTrace := range hops {
			if hopTrace.originRef.PathID != pathTrace.id {
				continue
			}
			peer, origin := hopTrace.snapshotNetworkHops()
			if peer != nil {
				peer.Sequence = len(path.Hops) + 1
				path.Hops = append(path.Hops, *peer)
			}
			origin.Sequence = len(path.Hops) + 1
			path.Hops = append(path.Hops, origin)
		}
		result = append(result, path)
	}
	return result
}

func (h *httpHopTrace) snapshotNetworkHops() (*model.NetworkHop, model.NetworkHop) {
	h.mu.Lock()
	defer h.mu.Unlock()

	origin := networkHopForURL(h.originRef, h.requestURL, h.sequence)
	if h.route != "proxy" {
		origin.RemoteIP = parseAddressIP(h.remoteAddress)
		origin.RemoteAddr = h.remoteAddress
		origin.LocalAddr = h.localAddress
		origin.Reused = h.reused
	}
	origin.Attempts = append(origin.Attempts, h.tlsNetworkAttemptsLocked()...)
	origin.Attempts = append(origin.Attempts, h.httpNetworkAttemptLocked())
	origin.Timings = append(origin.Timings, h.tlsPhaseTimingsLocked()...)
	origin.Timings = append(origin.Timings, h.responsePhaseTimingsLocked()...)

	if h.peerRef.HopID == "" {
		origin.Attempts = append(h.connectNetworkAttemptsLocked(), origin.Attempts...)
		origin.Attempts = append(h.dnsNetworkAttemptsLocked(), origin.Attempts...)
		origin.Timings = append(h.connectionPhaseTimingsLocked(), origin.Timings...)
		origin.SelectedAttemptID = selectedConnectAttemptID(h.connectAttempts)
		return nil, origin
	}

	peerURL, _ := url.Parse(h.selection.URL)
	peer := networkHopForURL(h.peerRef, peerURL, h.sequence)
	peer.Kind = model.NetworkHopProxyPeer
	peer.RemoteIP = parseAddressIP(h.remoteAddress)
	peer.RemoteAddr = h.remoteAddress
	peer.LocalAddr = h.localAddress
	peer.Reused = h.reused
	peer.Attempts = append(peer.Attempts, h.dnsNetworkAttemptsLocked()...)
	peer.Attempts = append(peer.Attempts, h.connectNetworkAttemptsLocked()...)
	peer.Timings = append(peer.Timings, h.connectionPhaseTimingsLocked()...)
	peer.SelectedAttemptID = selectedConnectAttemptID(h.connectAttempts)
	return &peer, origin
}

func networkHopForURL(ref model.NetworkRef, value *url.URL, globalSequence int) model.NetworkHop {
	host, zone := urlHostAndZone(value)
	hop := model.NetworkHop{
		ID:     ref.HopID,
		PathID: ref.PathID,
		Kind:   model.NetworkHopOrigin,
		URL:    SafeURL(value),
		Host:   host,
		Zone:   zone,
	}
	if globalSequence > 1 {
		hop.Kind = model.NetworkHopRedirect
	}
	if value != nil {
		hop.Scheme = strings.ToLower(value.Scheme)
		if parsed, err := strconv.ParseUint(effectivePort(value), 10, 16); err == nil {
			hop.Port = uint16(parsed)
		}
	}
	return hop
}

func urlHostAndZone(value *url.URL) (string, string) {
	if value == nil {
		return "", ""
	}
	host := value.Hostname()
	if index := strings.LastIndex(host, "%"); index >= 0 {
		return host[:index], strings.TrimPrefix(host[index+1:], "25")
	}
	return host, ""
}

func (h *httpHopTrace) dnsNetworkAttemptsLocked() []model.NetworkAttempt {
	attempts := make([]model.NetworkAttempt, 0, len(h.dnsAttempts))
	for _, attempt := range h.dnsAttempts {
		attempts = append(attempts, networkAttemptFromPhase(
			h.connectRef,
			attempt,
			model.NetworkAttemptDNS,
		))
	}
	return attempts
}

func (h *httpHopTrace) connectNetworkAttemptsLocked() []model.NetworkAttempt {
	attempts := make([]model.NetworkAttempt, 0, len(h.connectAttempts))
	for _, attempt := range h.connectAttempts {
		remoteIP := parseAddressIP(attempt.address)
		remoteAddress := attempt.address
		localAddress := ""
		if attempt.selected {
			if actual := parseAddressIP(h.remoteAddress); actual != nil {
				remoteIP = actual
			}
			if h.remoteAddress != "" {
				remoteAddress = h.remoteAddress
			}
			localAddress = h.localAddress
		}
		attempts = append(attempts, model.NetworkAttempt{
			ID:         attempt.id,
			PathID:     h.connectRef.PathID,
			HopID:      h.connectRef.HopID,
			Kind:       model.NetworkAttemptTCP,
			State:      completedAttemptState(attempt.finishedAt),
			Network:    attempt.network,
			RemoteIP:   remoteIP,
			RemoteAddr: remoteAddress,
			LocalAddr:  localAddress,
			StartedAt:  attempt.startedAt,
			FinishedAt: attempt.finishedAt,
			Duration:   phaseDuration(attempt.startedAt, attempt.finishedAt),
			Selected:   attempt.selected,
			Reused:     h.reused,
			ErrorCode:  attempt.errorCode,
			Error:      attempt.error,
		})
	}
	return attempts
}

func (h *httpHopTrace) tlsNetworkAttemptsLocked() []model.NetworkAttempt {
	attempts := make([]model.NetworkAttempt, 0, len(h.tlsAttempts))
	for _, attempt := range h.tlsAttempts {
		attempts = append(attempts, networkAttemptFromPhase(
			h.originRef,
			attempt,
			model.NetworkAttemptTLS,
		))
	}
	return attempts
}

func (h *httpHopTrace) httpNetworkAttemptLocked() model.NetworkAttempt {
	return model.NetworkAttempt{
		ID:         h.httpAttemptID,
		PathID:     h.originRef.PathID,
		HopID:      h.originRef.HopID,
		Kind:       model.NetworkAttemptHTTP,
		State:      completedAttemptState(h.requestFinished),
		StartedAt:  h.requestStarted,
		FinishedAt: h.requestFinished,
		Duration:   phaseDuration(h.requestStarted, h.requestFinished),
		Selected:   true,
		Reused:     h.reused,
	}
}

func networkAttemptFromPhase(
	ref model.NetworkRef,
	attempt *httpPhaseAttempt,
	kind model.NetworkAttemptKind,
) model.NetworkAttempt {
	return model.NetworkAttempt{
		ID:         attempt.id,
		PathID:     ref.PathID,
		HopID:      ref.HopID,
		Kind:       kind,
		State:      completedAttemptState(attempt.finishedAt),
		StartedAt:  attempt.startedAt,
		FinishedAt: attempt.finishedAt,
		Duration:   phaseDuration(attempt.startedAt, attempt.finishedAt),
		ErrorCode:  attempt.errorCode,
		Error:      attempt.error,
	}
}

func completedAttemptState(finished time.Time) model.AttemptState {
	if finished.IsZero() {
		return model.AttemptStateRunning
	}
	return model.AttemptStateCompleted
}

func (h *httpHopTrace) connectionPhaseTimingsLocked() []model.PhaseTiming {
	timings := make([]model.PhaseTiming, 0, len(h.dnsAttempts)+len(h.connectAttempts))
	for _, attempt := range h.dnsAttempts {
		timings = append(timings, phaseTiming(
			h.connectRef,
			attempt.id,
			"dns",
			attempt.startedAt,
			attempt.finishedAt,
		))
	}
	for _, attempt := range h.connectAttempts {
		timings = append(timings, phaseTiming(
			h.connectRef,
			attempt.id,
			"tcp",
			attempt.startedAt,
			attempt.finishedAt,
		))
	}
	return timings
}

func (h *httpHopTrace) tlsPhaseTimingsLocked() []model.PhaseTiming {
	timings := make([]model.PhaseTiming, 0, len(h.tlsAttempts))
	for _, attempt := range h.tlsAttempts {
		timings = append(timings, phaseTiming(
			h.originRef,
			attempt.id,
			"tls",
			attempt.startedAt,
			attempt.finishedAt,
		))
	}
	return timings
}

func (h *httpHopTrace) responsePhaseTimingsLocked() []model.PhaseTiming {
	timings := make([]model.PhaseTiming, 0, 2)
	if !h.firstByte.IsZero() {
		timings = append(timings, phaseTiming(
			h.originRef,
			h.httpAttemptID,
			"ttfb",
			h.requestStarted,
			h.firstByte,
		))
	}
	timings = append(timings, phaseTiming(
		h.originRef,
		h.httpAttemptID,
		"total",
		h.requestStarted,
		h.requestFinished,
	))
	return timings
}

func phaseTiming(
	ref model.NetworkRef,
	attemptID string,
	phase string,
	started time.Time,
	finished time.Time,
) model.PhaseTiming {
	ref.AttemptID = attemptID
	return model.PhaseTiming{
		NetworkRef: ref,
		Phase:      phase,
		StartedAt:  started,
		FinishedAt: finished,
		Duration:   phaseDuration(started, finished),
	}
}

func selectedConnectAttemptID(attempts []*httpConnectAttemptTrace) string {
	for _, attempt := range attempts {
		if attempt != nil && attempt.selected {
			return attempt.id
		}
	}
	return ""
}

func parseAddressIP(address string) net.IP {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if index := strings.LastIndex(host, "%"); index >= 0 {
		host = host[:index]
	}
	return net.ParseIP(host)
}

func correlateRedirects(
	redirects []model.Redirect,
	hops []model.HTTPHop,
) []model.Redirect {
	for index := range redirects {
		if index < len(hops) {
			ref := hops[index].NetworkRef
			redirects[index].FromNetworkRef = &ref
		}
		if index+1 < len(hops) {
			ref := hops[index+1].NetworkRef
			redirects[index].ToNetworkRef = &ref
		}
	}
	return redirects
}

func appendHTTPNetworkPaths(state *model.State, paths []model.NetworkPath) {
	if state == nil || len(paths) == 0 {
		return
	}
	existing := state.NetworkPaths()
	state.SetNetworkPaths(append(existing, paths...))
}
