// Package http performs bounded HTTP diagnostics with redirect tracking,
// privacy-safe metadata, and httptrace phase timings.
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
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/checks/environment"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/redaction"
)

const (
	ErrorTransport         = "HTTP_TRANSPORT_ERROR"
	ErrorTimeout           = "HTTP_TIMEOUT"
	ErrorCancelled         = "HTTP_CANCELLED"
	ErrorProxyConfig       = environment.ErrorProxyConfigInvalid
	ErrorProxyUnavailable  = "PROXY_SELECTION_UNAVAILABLE"
	ErrorProxyConnect      = "HTTP_PROXY_CONNECT_FAILED"
	ErrorRedirectLoop      = "HTTP_REDIRECT_LOOP"
	ErrorTooManyRedirects  = "HTTP_TOO_MANY_REDIRECTS"
	ErrorRedirectDowngrade = "HTTP_REDIRECT_HTTPS_DOWNGRADE_BLOCKED"
	ErrorRedirectPrivate   = "HTTP_REDIRECT_PRIVATE_NETWORK_BLOCKED"
	ErrorRedirectResolve   = "HTTP_REDIRECT_RESOLUTION_FAILED"
	ErrorLocationTooLarge  = "HTTP_REDIRECT_LOCATION_TOO_LARGE"
	ErrorBodyRead          = "HTTP_BODY_READ_ERROR"
	ErrorClientResponse    = "HTTP_CLIENT_ERROR"
	ErrorServerResponse    = "HTTP_SERVER_ERROR"
)

var (
	errRedirectLoop      = errors.New("redirect loop detected")
	errTooMany           = errors.New("maximum redirects exceeded")
	errRedirectDowngrade = errors.New("HTTPS to HTTP redirect blocked")
	errRedirectPrivate   = errors.New("public to private network redirect blocked")
	errRedirectResolve   = errors.New("redirect network scope resolution failed")
	errProxyConfig       = errors.New("proxy policy selected an invalid proxy")
	errProxyUnavailable  = errors.New("proxy policy selection is unavailable")
	errProxyConnect      = errors.New("proxy rejected CONNECT request")
	errLocationTooLarge  = errors.New("redirect Location exceeds configured limit")
)

// Resolver makes redirect network-scope classification deterministic in
// tests. net.Resolver satisfies this interface.
type Resolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

// RoundTripperFactory permits fully offline HTTP tests.
type RoundTripperFactory func(*model.State) stdhttp.RoundTripper

// DialContextFunc is an internal test seam below the production redirect-IP
// pinning policy. It must not be used to bypass policy decisions.
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

// Check performs one bounded request.
type Check struct {
	TransportFactory RoundTripperFactory
	Resolver         Resolver
	DialContext      DialContextFunc
	// RequestHeaders is an internal test seam. Production constructors leave
	// it nil because Orynelo never accepts arbitrary outbound headers.
	RequestHeaders stdhttp.Header
	Now            func() time.Time
}

// New constructs an HTTP check.
func New() *Check { return &Check{Now: time.Now} }

// ID returns the stable diagnostic identifier.
func (*Check) ID() string { return "http" }

// Name returns the human-readable check name.
func (*Check) Name() string { return "HTTP request" }

// Run performs the bounded HTTP request and records redirects, policy, and timing.
func (c *Check) Run(ctx context.Context, state *model.State) model.CheckResult {
	if state.Target.Kind != model.TargetHTTP {
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusNotApplicable,
			Summary: "HTTP is not enabled for this TCP target.",
		}
	}
	proxyInfo := state.Proxy()
	if proxyInfo.Selection.Validity == "" {
		result := model.HTTPResult{
			Method:    strings.ToUpper(strings.TrimSpace(state.Options.Method)),
			FinalURL:  SafeURL(mustParseURL(state.Target.RequestURL)),
			Route:     "blocked_by_proxy_policy",
			ErrorCode: ErrorProxyUnavailable,
			Error:     "proxy selection did not complete",
		}
		state.SetHTTP(result)
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusFailed,
			Summary:   "HTTP was not sent because proxy selection did not complete.",
			ErrorCode: ErrorProxyUnavailable,
			Evidence: []model.Evidence{{
				ID:      "http.proxy_selection_unavailable",
				Code:    ErrorProxyUnavailable,
				Message: "The HTTP check failed closed before transport because proxy policy was unresolved.",
			}},
		}
	}
	if proxyInfo.Selection.Validity == model.ProxyValidityInvalid {
		result := model.HTTPResult{
			Method:    strings.ToUpper(strings.TrimSpace(state.Options.Method)),
			FinalURL:  SafeURL(mustParseURL(state.Target.RequestURL)),
			ErrorCode: ErrorProxyConfig,
			Error:     "configured proxy is invalid; direct fallback is blocked",
		}
		applyRouteMetadata(&result, proxyInfo.Selection)
		state.SetHTTP(result)
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusFailed,
			Summary:   "HTTP was not sent because the configured proxy is invalid.",
			ErrorCode: ErrorProxyConfig,
			Evidence: []model.Evidence{{
				ID:      "http.proxy_policy",
				Code:    ErrorProxyConfig,
				Message: "The HTTP check failed closed instead of using a direct fallback.",
				Details: map[string]string{
					"route":          result.Route,
					"sourceVariable": result.ProxySource,
					"proxy":          result.ProxyURL,
					"proxyValidity":  string(result.ProxyValidity),
				},
			}},
		}
	}

	method := strings.ToUpper(strings.TrimSpace(state.Options.Method))
	if method == "" {
		method = stdhttp.MethodGet
	}
	request, err := stdhttp.NewRequestWithContext(ctx, method, state.Target.RequestURL, nil)
	if err != nil {
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusFailed,
			Summary:   "The HTTP request could not be constructed.",
			ErrorCode: ErrorTransport,
		}
	}
	request.Header.Set("User-Agent", state.Options.UserAgent)
	for name, values := range c.RequestHeaders {
		request.Header[name] = append([]string(nil), values...)
	}

	timing := &traceTimings{requestStarted: c.now(), now: c.now}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), timing.trace()))
	activeProxySelection := proxySelectionForURL(
		proxyInfo,
		state.Options.NoProxy,
		request.URL,
	)
	routeHistory := newHTTPRouteHistory(activeProxySelection)
	if activeProxySelection.Validity == "" {
		result := model.HTTPResult{
			Method:    method,
			FinalURL:  SafeURL(request.URL),
			ErrorCode: ErrorProxyUnavailable,
			Error:     "captured proxy policy did not return a selection",
		}
		applyRouteMetadata(&result, activeProxySelection)
		state.SetHTTP(result)
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusFailed,
			Summary:   errorSummary(ErrorProxyUnavailable),
			ErrorCode: ErrorProxyUnavailable,
			Evidence:  httpEvidence(result),
		}
	}
	if activeProxySelection.Validity == model.ProxyValidityInvalid {
		result := model.HTTPResult{
			Method:    method,
			FinalURL:  SafeURL(request.URL),
			ErrorCode: ErrorProxyConfig,
			Error:     "captured proxy policy selected an invalid proxy",
		}
		applyRouteMetadata(&result, activeProxySelection)
		state.SetHTTP(result)
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusFailed,
			Summary:   errorSummary(ErrorProxyConfig),
			ErrorCode: ErrorProxyConfig,
			Evidence:  httpEvidence(result),
		}
	}

	approvedTargets := newApprovedDialTargets()
	transport, transportErr := c.transport(state, approvedTargets)
	if transportErr != nil {
		result := model.HTTPResult{
			Method:    method,
			FinalURL:  SafeURL(request.URL),
			ErrorCode: ErrorProxyConfig,
			Error:     "validated proxy selection could not be constructed",
		}
		applyRouteMetadata(&result, activeProxySelection)
		state.SetHTTP(result)
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusFailed,
			Summary:   "HTTP was not sent because the proxy selection is unusable.",
			ErrorCode: ErrorProxyConfig,
			Evidence:  httpEvidence(result),
		}
	}
	if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
		defer closer.CloseIdleConnections()
	}
	redirects := make([]model.Redirect, 0)
	lastAttemptedURL := cloneURL(request.URL)
	seen := map[string]struct{}{canonicalRedirectURL(request.URL): {}}
	maxRedirects := state.Options.MaxRedirects
	if maxRedirects < 0 {
		maxRedirects = 0
	}
	maxLocationBytes := state.Options.MaxRedirectLocationBytes
	if maxLocationBytes <= 0 {
		maxLocationBytes = 8 << 10
	}
	client := &stdhttp.Client{
		Transport: transport,
		CheckRedirect: func(next *stdhttp.Request, via []*stdhttp.Request) error {
			var fromURL *url.URL
			statusCode := 0
			if next.Response != nil {
				fromURL = next.Response.Request.URL
				statusCode = next.Response.StatusCode
			} else if len(via) > 0 {
				fromURL = via[len(via)-1].URL
			}
			redirect := model.Redirect{
				From:           SafeURL(fromURL),
				To:             SafeURL(next.URL),
				StatusCode:     statusCode,
				CrossOrigin:    !sameOrigin(fromURL, next.URL),
				PolicyDecision: "followed",
			}
			// A server-controlled Location must never introduce URL userinfo,
			// including on a same-origin hop.
			next.URL.User = nil
			if redirect.CrossOrigin {
				var previousHeaders stdhttp.Header
				if len(via) > 0 {
					previousHeaders = via[len(via)-1].Header
				}
				redirect.SensitiveHeadersRemoved = removeSensitiveHeaders(
					next.Header,
					previousHeaders,
				)
				redirect.PolicyDecision = "followed_cross_origin"
				if len(redirect.SensitiveHeadersRemoved) > 0 {
					redirect.PolicyDecision = "followed_cross_origin_headers_removed"
				}
			}
			rawLocation := ""
			if next.Response != nil {
				rawLocation = next.Response.Header.Get("Location")
			}
			if len([]byte(rawLocation)) > maxLocationBytes {
				redirect.PolicyDecision = "blocked_location_too_large"
				redirects = append(redirects, redirect)
				return errLocationTooLarge
			}
			key := canonicalRedirectURL(next.URL)
			if _, duplicate := seen[key]; duplicate {
				redirect.PolicyDecision = "blocked_loop"
				redirects = append(redirects, redirect)
				return errRedirectLoop
			}
			seen[key] = struct{}{}
			if len(via) > maxRedirects {
				redirect.PolicyDecision = "blocked_hop_limit"
				redirects = append(redirects, redirect)
				return errTooMany
			}
			if isHTTPSDowngrade(fromURL, next.URL) {
				if !state.Options.AllowInsecureRedirects {
					redirect.PolicyDecision = "blocked_https_downgrade"
					redirects = append(redirects, redirect)
					return errRedirectDowngrade
				}
				redirect.PolicyDecision = "followed_https_downgrade_opt_in"
			}
			nextProxy := proxySelectionForURL(
				proxyInfo,
				state.Options.NoProxy,
				next.URL,
			)
			redirect.Route = proxySelectionRoute(nextProxy)
			redirect.ProxySelection = reportableProxySelection(nextProxy)
			if nextProxy.Validity == "" {
				redirect.PolicyDecision = "blocked_proxy_selection_unavailable"
				redirects = append(redirects, redirect)
				return errProxyUnavailable
			}
			if nextProxy.Validity == model.ProxyValidityInvalid {
				redirect.PolicyDecision = "blocked_invalid_proxy"
				redirects = append(redirects, redirect)
				return errProxyConfig
			}
			fromScope, fromErr := c.previousNetworkScope(
				ctx,
				fromURL,
				timing,
				activeProxySelection,
			)
			toScope, approvedAddresses, toErr := c.resolveNetworkScope(ctx, next.URL)
			redirect.FromNetworkScope = fromScope
			redirect.ToNetworkScope = toScope
			if fromErr != nil || toErr != nil {
				redirect.PolicyDecision = "blocked_resolution_failure"
				redirects = append(redirects, redirect)
				return errRedirectResolve
			}
			if canBePublic(fromScope) && canBePrivate(toScope) {
				if !state.Options.AllowPrivateRedirects {
					redirect.PolicyDecision = "blocked_public_to_private"
					redirects = append(redirects, redirect)
					return errRedirectPrivate
				}
				redirect.PolicyDecision = "followed_public_to_private_opt_in"
			}
			if proxySelectionRoute(nextProxy) == "direct" {
				approvedTargets.approve(next.URL, approvedAddresses)
			}
			next.Header.Set("User-Agent", state.Options.UserAgent)
			activeProxySelection = nextProxy
			routeHistory.add(nextProxy)
			lastAttemptedURL = cloneURL(next.URL)
			redirects = append(redirects, redirect)
			return nil
		},
	}

	response, err := client.Do(request)
	total := c.now().Sub(timing.requestStarted)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		result := model.HTTPResult{
			Method:    method,
			FinalURL:  SafeURL(lastAttemptedURL),
			Redirects: redirects,
			Timings:   timing.snapshot(total),
			RemoteIP:  timing.remoteAddress(),
			ErrorCode: classifyError(err),
			Error:     redaction.RedactText(safeTransportError(err)),
		}
		applyRouteMetadata(&result, activeProxySelection)
		result.Route = routeHistory.route()
		state.SetHTTP(result)
		status := model.StatusFailed
		if result.ErrorCode == ErrorCancelled {
			status = model.StatusCancelled
		}
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    status,
			Summary:   errorSummary(result.ErrorCode),
			ErrorCode: result.ErrorCode,
			Evidence:  httpEvidence(result),
		}
	}
	defer response.Body.Close()

	bodyLimit := state.Options.BodyLimit
	if bodyLimit <= 0 {
		bodyLimit = 64 << 10
	}
	read, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, bodyLimit+1))
	total = c.now().Sub(timing.requestStarted)
	truncated := read > bodyLimit
	if read > bodyLimit {
		read = bodyLimit
	}
	result := model.HTTPResult{
		Method:        method,
		FinalURL:      SafeURL(response.Request.URL),
		StatusCode:    response.StatusCode,
		Status:        response.Status,
		Redirects:     redirects,
		Headers:       RedactHeaders(response.Header),
		Timings:       timing.snapshot(total),
		RemoteIP:      timing.remoteAddress(),
		Protocol:      response.Proto,
		BodyBytesRead: read,
		BodyTruncated: truncated,
	}
	applyRouteMetadata(&result, activeProxySelection)
	result.Route = routeHistory.route()
	if readErr != nil {
		result.ErrorCode = ErrorBodyRead
		result.Error = readErr.Error()
	}
	state.SetHTTP(result)
	evidence := httpEvidence(result)

	if readErr != nil {
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusWarning,
			Summary:   "The HTTP response arrived, but its bounded body could not be read completely.",
			ErrorCode: ErrorBodyRead,
			Evidence:  evidence,
		}
	}
	if response.StatusCode >= 500 {
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusWarning,
			Summary:   fmt.Sprintf("HTTP transport succeeded; the application returned %s.", response.Status),
			ErrorCode: ErrorServerResponse,
			Evidence:  evidence,
			Recommendations: []model.Recommendation{{
				ID:       "http.investigate_server",
				Priority: "high",
				Message:  "Inspect service health, upstream dependencies, and server logs.",
			}},
		}
	}
	if response.StatusCode >= 400 {
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusWarning,
			Summary:   fmt.Sprintf("HTTP transport succeeded; the application returned %s.", response.Status),
			ErrorCode: ErrorClientResponse,
			Evidence:  evidence,
			Recommendations: []model.Recommendation{{
				ID:       "http.verify_request",
				Priority: "medium",
				Message:  "Verify the URL, request method, access policy, and required authentication.",
			}},
		}
	}
	return model.CheckResult{
		ID:       c.ID(),
		Name:     c.Name(),
		Status:   model.StatusPassed,
		Summary:  fmt.Sprintf("HTTP request succeeded with %s.", response.Status),
		Evidence: evidence,
	}
}

func (c *Check) transport(
	state *model.State,
	approved ...*approvedDialTargets,
) (stdhttp.RoundTripper, error) {
	if c.TransportFactory != nil {
		return c.TransportFactory(state), nil
	}
	proxyInfo := state.Proxy()
	proxy := func(request *stdhttp.Request) (*url.URL, error) {
		selection := proxySelectionForURL(
			proxyInfo,
			state.Options.NoProxy,
			request.URL,
		)
		if selection.Validity == model.ProxyValidityInvalid {
			return nil, errProxyConfig
		}
		if selection.Validity == "" {
			return nil, errProxyUnavailable
		}
		if proxySelectionRoute(selection) != "proxy" {
			return nil, nil
		}
		selected, err := url.Parse(selection.RequestURL)
		if err != nil || selected.Hostname() == "" {
			return nil, errProxyConfig
		}
		return selected, nil
	}
	dialer := &net.Dialer{}
	dialContext := dialer.DialContext
	if c.DialContext != nil {
		dialContext = c.DialContext
	}
	approvedTargets := newApprovedDialTargets()
	if len(approved) > 0 && approved[0] != nil {
		approvedTargets = approved[0]
	}
	return &stdhttp.Transport{
		Proxy: proxy,
		OnProxyConnectResponse: func(
			_ context.Context,
			_ *url.URL,
			_ *stdhttp.Request,
			response *stdhttp.Response,
		) error {
			if response != nil && response.StatusCode >= 200 && response.StatusCode < 300 {
				return nil
			}
			return errProxyConnect
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return approvedTargets.dial(
				ctx,
				networkForIPVersion(network, state.Options.IPVersion),
				address,
				state.Options.IPVersion,
				dialContext,
			)
		},
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        &tls.Config{InsecureSkipVerify: state.Options.Insecure}, //nolint:gosec
		TLSHandshakeTimeout:    state.Options.CheckTimeout,
		ResponseHeaderTimeout:  state.Options.CheckTimeout,
		MaxResponseHeaderBytes: 64 << 10,
		IdleConnTimeout:        30 * time.Second,
		DisableKeepAlives:      true,
	}, nil
}

type approvedDialTargets struct {
	mu        sync.RWMutex
	addresses map[string][]net.IP
}

func newApprovedDialTargets() *approvedDialTargets {
	return &approvedDialTargets{addresses: make(map[string][]net.IP)}
}

func (targets *approvedDialTargets) approve(target *url.URL, addresses []net.IP) {
	if targets == nil || target == nil || len(addresses) == 0 {
		return
	}
	key := urlDialAddress(target)
	if key == "" {
		return
	}
	approved := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		if address == nil {
			continue
		}
		approved = append(approved, append(net.IP(nil), address...))
	}
	if len(approved) == 0 {
		return
	}
	targets.mu.Lock()
	targets.addresses[key] = approved
	targets.mu.Unlock()
}

func (targets *approvedDialTargets) dial(
	ctx context.Context,
	network string,
	address string,
	ipVersion model.IPVersion,
	dial DialContextFunc,
) (net.Conn, error) {
	if targets == nil || dial == nil {
		return nil, errors.New("HTTP dial policy is unavailable")
	}
	key, port := canonicalDialAddress(address)
	targets.mu.RLock()
	approved, pinned := targets.addresses[key]
	approved = cloneIPs(approved)
	targets.mu.RUnlock()
	if !pinned {
		return dial(ctx, network, address)
	}
	var lastErr error
	for _, candidate := range approved {
		if !matchesIPVersion(candidate, ipVersion) {
			continue
		}
		connection, err := dial(ctx, network, net.JoinHostPort(candidate.String(), port))
		if err == nil {
			return connection, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no approved redirect address matches the requested IP family")
	}
	return nil, fmt.Errorf("approved redirect address dial failed: %w", lastErr)
}

func urlDialAddress(value *url.URL) string {
	if value == nil || value.Hostname() == "" || effectivePort(value) == "" {
		return ""
	}
	return net.JoinHostPort(
		strings.TrimSuffix(strings.ToLower(value.Hostname()), "."),
		effectivePort(value),
	)
}

func canonicalDialAddress(address string) (string, string) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return strings.ToLower(address), ""
	}
	return net.JoinHostPort(
		strings.TrimSuffix(strings.ToLower(host), "."),
		port,
	), port
}

func cloneIPs(values []net.IP) []net.IP {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]net.IP, 0, len(values))
	for _, value := range values {
		cloned = append(cloned, append(net.IP(nil), value...))
	}
	return cloned
}

func matchesIPVersion(address net.IP, version model.IPVersion) bool {
	switch version {
	case model.IPVersion4:
		return address.To4() != nil
	case model.IPVersion6:
		return address.To4() == nil && address.To16() != nil
	default:
		return address != nil
	}
}

func applyRouteMetadata(result *model.HTTPResult, selection model.ProxySelection) {
	if result == nil {
		return
	}
	result.Route = proxySelectionRoute(selection)
	result.ProxySource = selection.SourceVariable
	result.ProxyURL = selection.URL
	result.ProxyValidity = selection.Validity
	result.ProxyBypassReason = selection.BypassReason
}

func proxySelectionForURL(
	proxy model.ProxyInfo,
	noProxy bool,
	target *url.URL,
) model.ProxySelection {
	selection := proxy.Selection
	if proxy.SelectForURL != nil {
		selection = proxy.SelectForURL(target)
	}
	if noProxy && selection.BypassReason == model.ProxyBypassNone &&
		(selection.Validity == model.ProxyValidityValid ||
			selection.Validity == model.ProxyValidityInvalid) {
		selection.Validity = model.ProxyValidityNotApplicable
		selection.BypassReason = model.ProxyBypassDisabled
		selection.Error = ""
		selection.ErrorCode = ""
		selection.RequestURL = ""
	}
	return selection
}

type httpRouteHistory struct {
	direct bool
	proxy  bool
}

func newHTTPRouteHistory(selection model.ProxySelection) *httpRouteHistory {
	history := &httpRouteHistory{}
	history.add(selection)
	return history
}

func (h *httpRouteHistory) add(selection model.ProxySelection) {
	if h == nil {
		return
	}
	switch proxySelectionRoute(selection) {
	case "direct":
		h.direct = true
	case "proxy":
		h.proxy = true
	}
}

func (h *httpRouteHistory) route() string {
	if h == nil {
		return ""
	}
	if h.direct && h.proxy {
		return "mixed"
	}
	if h.proxy {
		return "proxy"
	}
	if h.direct {
		return "direct"
	}
	return "blocked_by_proxy_policy"
}

func proxySelectionRoute(selection model.ProxySelection) string {
	if selection.Validity == model.ProxyValidityInvalid || selection.Validity == "" {
		return "blocked_by_proxy_policy"
	}
	if selection.Validity == model.ProxyValidityValid &&
		selection.BypassReason == model.ProxyBypassNone {
		return "proxy"
	}
	return "direct"
}

func reportableProxySelection(selection model.ProxySelection) model.ProxySelection {
	selection.RequestURL = ""
	return selection
}

func mustParseURL(raw string) *url.URL {
	parsed, _ := url.Parse(raw)
	return parsed
}

func cloneURL(value *url.URL) *url.URL {
	if value == nil {
		return nil
	}
	cloned := *value
	if value.User != nil {
		userinfo := *value.User
		cloned.User = &userinfo
	}
	return &cloned
}

func sameOrigin(left, right *url.URL) bool {
	if left == nil || right == nil {
		return false
	}
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Hostname(), right.Hostname()) &&
		effectivePort(left) == effectivePort(right)
}

func effectivePort(value *url.URL) string {
	if value == nil {
		return ""
	}
	if port := value.Port(); port != "" {
		return port
	}
	switch strings.ToLower(value.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func isHTTPSDowngrade(from, to *url.URL) bool {
	return from != nil && to != nil && strings.EqualFold(from.Scheme, "https") &&
		strings.EqualFold(to.Scheme, "http")
}

func removeSensitiveHeaders(headers, previous stdhttp.Header) []string {
	removedSet := make(map[string]struct{})
	for name, values := range previous {
		if len(values) > 0 && redaction.IsSensitiveHeader(name) {
			// net/http may already have removed this header while constructing
			// the redirect request. Recording it is accurate because it was
			// present on the prior hop and absent from the outbound next hop.
			removedSet[stdhttp.CanonicalHeaderKey(name)] = struct{}{}
		}
	}
	for name := range headers {
		if !redaction.IsSensitiveHeader(name) {
			continue
		}
		removedSet[stdhttp.CanonicalHeaderKey(name)] = struct{}{}
		headers.Del(name)
	}
	if headers.Get("Referer") != "" {
		removedSet["Referer"] = struct{}{}
		headers.Del("Referer")
	}
	removed := make([]string, 0, len(removedSet))
	for name := range removedSet {
		removed = append(removed, name)
	}
	sort.Strings(removed)
	return removed
}

func (c *Check) networkScope(ctx context.Context, value *url.URL) (string, error) {
	scope, _, err := c.resolveNetworkScope(ctx, value)
	return scope, err
}

func (c *Check) resolveNetworkScope(
	ctx context.Context,
	value *url.URL,
) (string, []net.IP, error) {
	if value == nil || value.Hostname() == "" {
		return "unknown", nil, errors.New("redirect URL has no host")
	}
	host := strings.TrimSuffix(strings.ToLower(value.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return "private_or_local", []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
		}, nil
	}
	if parsed := net.ParseIP(host); parsed != nil {
		return ipNetworkScope(parsed), []net.IP{parsed}, nil
	}
	resolver := c.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addresses, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return "unknown", nil, errors.New("redirect host resolution failed")
	}
	usableAddresses := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		if address != nil && address.To16() != nil {
			usableAddresses = append(usableAddresses, address)
		}
	}
	if len(usableAddresses) == 0 {
		return "unknown", nil, errors.New("redirect host resolution returned no usable address")
	}
	hasPublic := false
	hasPrivate := false
	for _, address := range usableAddresses {
		if ipNetworkScope(address) == "public" {
			hasPublic = true
		} else {
			hasPrivate = true
		}
	}
	if hasPublic && hasPrivate {
		return "mixed", cloneIPs(usableAddresses), nil
	}
	if hasPrivate {
		return "private_or_local", cloneIPs(usableAddresses), nil
	}
	return "public", cloneIPs(usableAddresses), nil
}

func (c *Check) previousNetworkScope(
	ctx context.Context,
	value *url.URL,
	timing *traceTimings,
	selection model.ProxySelection,
) (string, error) {
	// A proxy resolves or otherwise reaches the origin outside this process,
	// so local DNS cannot truthfully establish the previous peer's scope.
	// Treat it as potentially public: a subsequent direct private hop must
	// still require the explicit private-redirect opt-in.
	if proxySelectionRoute(selection) == "proxy" {
		return "proxy_origin_unknown", nil
	}
	// For a direct route, httptrace gives the address actually used by the
	// prior hop. Prefer that over another DNS lookup so a mixed answer cannot
	// hide the fact that the connection was public.
	if proxySelectionRoute(selection) == "direct" && timing != nil {
		if address := net.ParseIP(timing.remoteAddress()); address != nil {
			return ipNetworkScope(address), nil
		}
	}
	return c.networkScope(ctx, value)
}

func canBePublic(scope string) bool {
	return scope == "public" || scope == "mixed" || scope == "proxy_origin_unknown"
}

func canBePrivate(scope string) bool {
	return scope == "private_or_local" || scope == "mixed"
}

func ipNetworkScope(ip net.IP) string {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "private_or_local"
	}
	address = address.Unmap()
	if address.IsUnspecified() || address.IsLoopback() || address.IsPrivate() ||
		address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() ||
		address.IsInterfaceLocalMulticast() || address.IsMulticast() ||
		!address.IsGlobalUnicast() {
		return "private_or_local"
	}
	for _, prefix := range nonPublicSpecialPrefixes {
		if prefix.Contains(address) {
			return "private_or_local"
		}
	}
	return "public"
}

var nonPublicSpecialPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

func networkForIPVersion(network string, version model.IPVersion) string {
	if !strings.HasPrefix(network, "tcp") {
		return network
	}
	switch version {
	case model.IPVersion4:
		return "tcp4"
	case model.IPVersion6:
		return "tcp6"
	default:
		return network
	}
}

type traceTimings struct {
	mu             sync.Mutex
	now            func() time.Time
	requestStarted time.Time
	dnsStarted     time.Time
	connectStarted time.Time
	tlsStarted     time.Time
	dns            time.Duration
	tcp            time.Duration
	tls            time.Duration
	firstByte      time.Duration
	remote         string
}

func (t *traceTimings) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			t.mu.Lock()
			t.dnsStarted = t.now()
			t.mu.Unlock()
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			t.mu.Lock()
			if !t.dnsStarted.IsZero() {
				t.dns += t.now().Sub(t.dnsStarted)
				t.dnsStarted = time.Time{}
			}
			t.mu.Unlock()
		},
		ConnectStart: func(_, _ string) {
			t.mu.Lock()
			t.connectStarted = t.now()
			t.mu.Unlock()
		},
		ConnectDone: func(_, _ string, _ error) {
			t.mu.Lock()
			if !t.connectStarted.IsZero() {
				t.tcp += t.now().Sub(t.connectStarted)
				t.connectStarted = time.Time{}
			}
			t.mu.Unlock()
		},
		TLSHandshakeStart: func() {
			t.mu.Lock()
			t.tlsStarted = t.now()
			t.mu.Unlock()
		},
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			t.mu.Lock()
			if !t.tlsStarted.IsZero() {
				t.tls += t.now().Sub(t.tlsStarted)
				t.tlsStarted = time.Time{}
			}
			t.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			t.mu.Lock()
			if t.firstByte == 0 {
				t.firstByte = t.now().Sub(t.requestStarted)
			}
			t.mu.Unlock()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			t.mu.Lock()
			t.remote = info.Conn.RemoteAddr().String()
			t.mu.Unlock()
		},
	}
}

func (t *traceTimings) snapshot(total time.Duration) model.HTTPTimings {
	t.mu.Lock()
	defer t.mu.Unlock()
	return model.HTTPTimings{
		DNS:       t.dns,
		TCP:       t.tcp,
		TLS:       t.tls,
		FirstByte: t.firstByte,
		Total:     total,
	}
}

func (t *traceTimings) remoteAddress() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	host, _, err := net.SplitHostPort(t.remote)
	if err == nil {
		return host
	}
	return t.remote
}

func classifyError(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return ErrorCancelled
	case errors.Is(err, context.DeadlineExceeded):
		return ErrorTimeout
	case errors.Is(err, errRedirectDowngrade):
		return ErrorRedirectDowngrade
	case errors.Is(err, errProxyConfig):
		return ErrorProxyConfig
	case errors.Is(err, errProxyUnavailable):
		return ErrorProxyUnavailable
	case errors.Is(err, errRedirectPrivate):
		return ErrorRedirectPrivate
	case errors.Is(err, errRedirectResolve):
		return ErrorRedirectResolve
	case errors.Is(err, errLocationTooLarge):
		return ErrorLocationTooLarge
	case errors.Is(err, errRedirectLoop):
		return ErrorRedirectLoop
	case errors.Is(err, errTooMany):
		return ErrorTooManyRedirects
	case isProxyConnectError(err):
		return ErrorProxyConnect
	}
	var urlError *url.Error
	if errors.As(err, &urlError) {
		return classifyError(urlError.Err)
	}
	var netError net.Error
	if errors.As(err, &netError) && netError.Timeout() {
		return ErrorTimeout
	}
	return ErrorTransport
}

func safeTransportError(err error) string {
	var urlError *url.Error
	if errors.As(err, &urlError) {
		return safeTransportError(urlError.Err)
	}
	switch {
	case isProxyConnectError(err):
		return "proxy CONNECT failed"
	case errors.Is(err, errRedirectDowngrade):
		return "HTTPS to HTTP redirect blocked by policy"
	case errors.Is(err, errProxyConfig):
		return "captured proxy policy selected an invalid proxy"
	case errors.Is(err, errProxyUnavailable):
		return "captured proxy policy did not return a selection"
	case errors.Is(err, errRedirectPrivate):
		return "public to private network redirect blocked by policy"
	case errors.Is(err, errRedirectResolve):
		return "redirect blocked because network scope could not be resolved"
	case errors.Is(err, errLocationTooLarge):
		return "redirect Location exceeded the configured byte limit"
	case errors.Is(err, errRedirectLoop):
		return "redirect loop detected"
	case errors.Is(err, errTooMany):
		return "maximum redirects exceeded"
	default:
		return err.Error()
	}
}

func errorSummary(code string) string {
	switch code {
	case ErrorCancelled:
		return "The HTTP request was cancelled."
	case ErrorTimeout:
		return "The HTTP request timed out."
	case ErrorProxyConfig:
		return "The configured proxy is invalid; direct fallback was blocked."
	case ErrorProxyUnavailable:
		return "Proxy selection did not complete, so the HTTP request was blocked."
	case ErrorProxyConnect:
		return "The selected proxy could not establish the HTTP connection."
	case ErrorRedirectDowngrade:
		return "An HTTPS to HTTP redirect was blocked by policy."
	case ErrorRedirectPrivate:
		return "A public to private-network redirect was blocked by policy."
	case ErrorRedirectResolve:
		return "A redirect was blocked because its network scope could not be resolved safely."
	case ErrorLocationTooLarge:
		return "A redirect Location exceeded the configured byte limit."
	case ErrorRedirectLoop:
		return "The HTTP redirect chain contains a loop."
	case ErrorTooManyRedirects:
		return "The HTTP response exceeded the configured redirect limit."
	default:
		return "The HTTP transport request failed."
	}
}

func isProxyConnectError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errProxyConnect) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "proxyconnect") ||
		strings.Contains(message, "proxy connect") ||
		strings.Contains(message, "connect tunnel")
}

func httpEvidence(result model.HTTPResult) []model.Evidence {
	details := map[string]string{
		"method":        result.Method,
		"finalUrl":      result.FinalURL,
		"statusCode":    strconv.Itoa(result.StatusCode),
		"status":        result.Status,
		"redirects":     strconv.Itoa(len(result.Redirects)),
		"dnsDuration":   result.Timings.DNS.String(),
		"tcpDuration":   result.Timings.TCP.String(),
		"tlsDuration":   result.Timings.TLS.String(),
		"firstByte":     result.Timings.FirstByte.String(),
		"totalDuration": result.Timings.Total.String(),
		"remoteIp":      result.RemoteIP,
		"protocol":      result.Protocol,
		"bodyBytesRead": strconv.FormatInt(result.BodyBytesRead, 10),
		"bodyTruncated": strconv.FormatBool(result.BodyTruncated),
		"route":         result.Route,
	}
	if result.ProxySource != "" {
		details["proxySource"] = result.ProxySource
	}
	if result.ProxyURL != "" {
		details["proxy"] = result.ProxyURL
	}
	if result.ProxyValidity != "" {
		details["proxyValidity"] = string(result.ProxyValidity)
	}
	if result.ProxyBypassReason != model.ProxyBypassNone {
		details["proxyBypassReason"] = string(result.ProxyBypassReason)
	}
	if result.Error != "" {
		details["error"] = result.Error
	}
	for name, values := range result.Headers {
		details["responseHeader."+name] = strings.Join(values, ", ")
	}
	evidence := []model.Evidence{{
		ID:      "http.response",
		Code:    httpEvidenceCode(result),
		Message: "Bounded HTTP transport and response metadata were collected.",
		Details: details,
	}}
	for index, redirect := range result.Redirects {
		redirectDetails := map[string]string{
			"from":           redirect.From,
			"to":             redirect.To,
			"statusCode":     strconv.Itoa(redirect.StatusCode),
			"crossOrigin":    strconv.FormatBool(redirect.CrossOrigin),
			"policyDecision": redirect.PolicyDecision,
			"route":          redirect.Route,
		}
		if redirect.ProxySelection.SourceVariable != "" {
			redirectDetails["proxySource"] = redirect.ProxySelection.SourceVariable
		}
		if redirect.ProxySelection.URL != "" {
			redirectDetails["proxy"] = redirect.ProxySelection.URL
		}
		if redirect.ProxySelection.Validity != "" {
			redirectDetails["proxyValidity"] = string(redirect.ProxySelection.Validity)
		}
		if redirect.ProxySelection.BypassReason != model.ProxyBypassNone {
			redirectDetails["proxyBypassReason"] = string(
				redirect.ProxySelection.BypassReason,
			)
		}
		if len(redirect.SensitiveHeadersRemoved) > 0 {
			redirectDetails["sensitiveHeadersRemoved"] = strings.Join(
				redirect.SensitiveHeadersRemoved, ", ",
			)
		}
		if redirect.FromNetworkScope != "" {
			redirectDetails["fromNetworkScope"] = redirect.FromNetworkScope
		}
		if redirect.ToNetworkScope != "" {
			redirectDetails["toNetworkScope"] = redirect.ToNetworkScope
		}
		message := "HTTP redirect policy allowed this hop."
		if strings.HasPrefix(redirect.PolicyDecision, "blocked_") {
			message = "HTTP redirect policy blocked this hop."
		} else if redirect.CrossOrigin && len(redirect.SensitiveHeadersRemoved) > 0 {
			message = "Cross-origin redirect followed after sensitive headers were removed."
		} else if redirect.CrossOrigin {
			message = "Cross-origin redirect followed with sensitive-header forwarding blocked by policy."
		}
		evidence = append(evidence, model.Evidence{
			ID:      fmt.Sprintf("http.redirect.%d", index+1),
			Code:    redirectEvidenceCode(redirect),
			Message: message,
			Details: redirectDetails,
		})
	}
	return evidence
}

func httpEvidenceCode(result model.HTTPResult) string {
	if result.ErrorCode != "" {
		return result.ErrorCode
	}
	return "HTTP_RESPONSE"
}

func redirectEvidenceCode(redirect model.Redirect) string {
	switch redirect.PolicyDecision {
	case "blocked_https_downgrade":
		return ErrorRedirectDowngrade
	case "blocked_invalid_proxy":
		return ErrorProxyConfig
	case "blocked_proxy_selection_unavailable":
		return ErrorProxyUnavailable
	case "blocked_public_to_private":
		return ErrorRedirectPrivate
	case "blocked_resolution_failure":
		return ErrorRedirectResolve
	case "blocked_location_too_large":
		return ErrorLocationTooLarge
	case "blocked_loop":
		return ErrorRedirectLoop
	case "blocked_hop_limit":
		return ErrorTooManyRedirects
	default:
		if redirect.CrossOrigin {
			return "HTTP_REDIRECT_CROSS_ORIGIN"
		}
		return "HTTP_REDIRECT"
	}
}

// RedactHeaders returns a deep copy with credential-bearing headers replaced.
func RedactHeaders(headers stdhttp.Header) map[string][]string {
	return redaction.RedactHeaders(headers)
}

// SafeURL strips userinfo, fragments, and sensitive query values.
func SafeURL(value *url.URL) string {
	if value == nil {
		return ""
	}
	copy := *value
	copy.Fragment = ""
	return redaction.RedactParsedURL(&copy).String()
}

func canonicalRedirectURL(value *url.URL) string {
	if value == nil {
		return ""
	}
	copy := *value
	copy.Fragment = ""
	return copy.String()
}

func (c *Check) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
