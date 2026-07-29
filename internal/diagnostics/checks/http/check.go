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
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Naenier/opsdoctor/internal/diagnostics/checks/environment"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/redaction"
)

const (
	ErrorTransport        = "HTTP_TRANSPORT_ERROR"
	ErrorTimeout          = "HTTP_TIMEOUT"
	ErrorCancelled        = "HTTP_CANCELLED"
	ErrorRedirectLoop     = "HTTP_REDIRECT_LOOP"
	ErrorTooManyRedirects = "HTTP_TOO_MANY_REDIRECTS"
	ErrorBodyRead         = "HTTP_BODY_READ_ERROR"
	ErrorClientResponse   = "HTTP_CLIENT_ERROR"
	ErrorServerResponse   = "HTTP_SERVER_ERROR"
)

var (
	errRedirectLoop = errors.New("redirect loop detected")
	errTooMany      = errors.New("maximum redirects exceeded")
)

// RoundTripperFactory permits fully offline HTTP tests.
type RoundTripperFactory func(*model.State) stdhttp.RoundTripper

// Check performs one bounded request.
type Check struct {
	TransportFactory RoundTripperFactory
	Now              func() time.Time
}

// New constructs an HTTP check.
func New() *Check { return &Check{Now: time.Now} }

func (*Check) ID() string   { return "http" }
func (*Check) Name() string { return "HTTP request" }

func (c *Check) Run(ctx context.Context, state *model.State) model.CheckResult {
	if state.Target.Kind != model.TargetHTTP {
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusSkipped,
			Summary: "HTTP is not enabled for this TCP target.",
		}
	}
	if state.Target.UseTLS &&
		state.TLS().ErrorCode != "" &&
		!state.Options.Insecure &&
		!state.Proxy().Selected {
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusSkipped,
			Summary: "HTTP was skipped because TLS verification did not succeed.",
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

	timing := &traceTimings{requestStarted: c.now(), now: c.now}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), timing.trace()))

	transport := c.transport(state)
	if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
		defer closer.CloseIdleConnections()
	}
	redirects := make([]model.Redirect, 0)
	seen := map[string]struct{}{canonicalRedirectURL(request.URL): {}}
	maxRedirects := state.Options.MaxRedirects
	if maxRedirects < 0 {
		maxRedirects = 0
	}
	client := &stdhttp.Client{
		Transport: transport,
		CheckRedirect: func(next *stdhttp.Request, via []*stdhttp.Request) error {
			from := ""
			statusCode := 0
			if next.Response != nil {
				from = SafeURL(next.Response.Request.URL)
				statusCode = next.Response.StatusCode
			} else if len(via) > 0 {
				from = SafeURL(via[len(via)-1].URL)
			}
			redirects = append(redirects, model.Redirect{
				From:       from,
				To:         SafeURL(next.URL),
				StatusCode: statusCode,
			})
			key := canonicalRedirectURL(next.URL)
			if _, duplicate := seen[key]; duplicate {
				return errRedirectLoop
			}
			seen[key] = struct{}{}
			if len(via) > maxRedirects {
				return errTooMany
			}
			next.Header.Set("User-Agent", state.Options.UserAgent)
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
			FinalURL:  SafeURL(request.URL),
			Redirects: redirects,
			Timings:   timing.snapshot(total),
			RemoteIP:  timing.remoteAddress(),
			ErrorCode: classifyError(err),
			Error:     redaction.RedactText(safeTransportError(err)),
		}
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

func (c *Check) transport(state *model.State) stdhttp.RoundTripper {
	if c.TransportFactory != nil {
		return c.TransportFactory(state)
	}
	proxyForURL := environment.ProxyFunc(state.Options.NoProxy)
	var proxy func(*stdhttp.Request) (*url.URL, error)
	if proxyForURL != nil {
		proxy = func(request *stdhttp.Request) (*url.URL, error) {
			return proxyForURL(request.URL)
		}
	}
	dialer := &net.Dialer{}
	return &stdhttp.Transport{
		Proxy: proxy,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, networkForIPVersion(network, state.Options.IPVersion), address)
		},
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        &tls.Config{InsecureSkipVerify: state.Options.Insecure}, //nolint:gosec
		TLSHandshakeTimeout:    state.Options.CheckTimeout,
		ResponseHeaderTimeout:  state.Options.CheckTimeout,
		MaxResponseHeaderBytes: 64 << 10,
		IdleConnTimeout:        30 * time.Second,
		DisableKeepAlives:      true,
	}
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
	case errors.Is(err, errRedirectLoop):
		return ErrorRedirectLoop
	case errors.Is(err, errTooMany):
		return ErrorTooManyRedirects
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
	case ErrorRedirectLoop:
		return "The HTTP redirect chain contains a loop."
	case ErrorTooManyRedirects:
		return "The HTTP response exceeded the configured redirect limit."
	default:
		return "The HTTP transport request failed."
	}
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
	}
	if result.Error != "" {
		details["error"] = result.Error
	}
	for name, values := range result.Headers {
		details["responseHeader."+name] = strings.Join(values, ", ")
	}
	return []model.Evidence{{
		ID:      "http.response",
		Code:    "HTTP_RESPONSE",
		Message: "Bounded HTTP transport and response metadata were collected.",
		Details: details,
	}}
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
