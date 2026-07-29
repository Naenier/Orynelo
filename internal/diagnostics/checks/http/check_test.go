package http

import (
	"context"
	"io"
	stdhttp "net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

type roundTripFunc func(*stdhttp.Request) (*stdhttp.Response, error)

func (f roundTripFunc) RoundTrip(request *stdhttp.Request) (*stdhttp.Response, error) {
	return f(request)
}

func TestCheckBoundsBodyAndRedactsHeaders(t *testing.T) {
	t.Parallel()
	check := New()
	check.TransportFactory = func(*model.State) stdhttp.RoundTripper {
		return roundTripFunc(func(request *stdhttp.Request) (*stdhttp.Response, error) {
			return &stdhttp.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Proto:      "HTTP/1.1",
				Header: stdhttp.Header{
					"Content-Type": {"text/plain"},
					"Set-Cookie":   {"session=secret"},
				},
				Body:    io.NopCloser(strings.NewReader("0123456789")),
				Request: request,
			}, nil
		})
	}
	options := model.DefaultDiagnoseOptions("http://example.com")
	options.BodyLimit = 4
	state := model.NewState(model.Target{
		Kind:       model.TargetHTTP,
		Scheme:     "http",
		Host:       "example.com",
		Port:       80,
		RequestURL: "http://example.com:80/?token=secret",
	}, options)
	result := check.Run(context.Background(), state)
	if result.Status != model.StatusPassed {
		t.Fatalf("result = %#v", result)
	}
	httpResult := state.HTTP()
	if httpResult.BodyBytesRead != 4 || !httpResult.BodyTruncated {
		t.Fatalf("body metadata = %#v", httpResult)
	}
	if got := httpResult.Headers["Set-Cookie"]; len(got) != 1 || got[0] != "[REDACTED]" {
		t.Fatalf("headers = %#v", httpResult.Headers)
	}
	if got := result.Evidence[0].Details["responseHeader.Set-Cookie"]; got != "[REDACTED]" {
		t.Fatalf("redacted response header missing from persisted evidence: %#v", result.Evidence)
	}
	if got := result.Evidence[0].Details["responseHeader.Content-Type"]; got != "text/plain" {
		t.Fatalf("response content type missing from evidence: %#v", result.Evidence)
	}
	if strings.Contains(httpResult.FinalURL, "secret") {
		t.Fatalf("final URL leaked query secret: %s", httpResult.FinalURL)
	}
}

func TestCheckKeepsHTTPErrorAsApplicationWarning(t *testing.T) {
	t.Parallel()
	check := New()
	check.TransportFactory = func(*model.State) stdhttp.RoundTripper {
		return roundTripFunc(func(request *stdhttp.Request) (*stdhttp.Response, error) {
			return &stdhttp.Response{
				StatusCode: 503,
				Status:     "503 Service Unavailable",
				Proto:      "HTTP/2.0",
				Header:     make(stdhttp.Header),
				Body:       io.NopCloser(strings.NewReader("unavailable")),
				Request:    request,
			}, nil
		})
	}
	options := model.DefaultDiagnoseOptions("http://example.com")
	options.UserAgent = "OpsDoctor-test/1"
	state := model.NewState(model.Target{
		Kind:       model.TargetHTTP,
		Host:       "example.com",
		Port:       80,
		RequestURL: "http://example.com:80/",
	}, options)
	result := check.Run(context.Background(), state)
	if result.Status != model.StatusWarning || result.ErrorCode != ErrorServerResponse {
		t.Fatalf("result = %#v", result)
	}
}

func TestCheckClassifiesHTTPClientError(t *testing.T) {
	t.Parallel()
	check := New()
	check.TransportFactory = func(*model.State) stdhttp.RoundTripper {
		return roundTripFunc(func(request *stdhttp.Request) (*stdhttp.Response, error) {
			return &stdhttp.Response{
				StatusCode: 404,
				Status:     "404 Not Found",
				Proto:      "HTTP/1.1",
				Header:     make(stdhttp.Header),
				Body:       io.NopCloser(strings.NewReader("not found")),
				Request:    request,
			}, nil
		})
	}
	options := model.DefaultDiagnoseOptions("http://example.com/missing")
	state := model.NewState(model.Target{
		Kind:       model.TargetHTTP,
		Host:       "example.com",
		Port:       80,
		RequestURL: "http://example.com:80/missing",
	}, options)

	result := check.Run(context.Background(), state)

	if result.Status != model.StatusWarning || result.ErrorCode != ErrorClientResponse {
		t.Fatalf("result = %#v", result)
	}
	if got := state.HTTP().StatusCode; got != 404 {
		t.Fatalf("HTTP status = %d, want 404", got)
	}
}

func TestCheckFollowsAndRecordsRedirect(t *testing.T) {
	t.Parallel()
	check := New()
	check.TransportFactory = func(*model.State) stdhttp.RoundTripper {
		return roundTripFunc(func(request *stdhttp.Request) (*stdhttp.Response, error) {
			response := &stdhttp.Response{
				Proto:   "HTTP/1.1",
				Header:  make(stdhttp.Header),
				Body:    io.NopCloser(strings.NewReader("")),
				Request: request,
			}
			if request.URL.Path == "/start" {
				response.StatusCode = stdhttp.StatusFound
				response.Status = "302 Found"
				response.Header.Set("Location", "/final?api_key=redirect-secret&view=full")
				return response, nil
			}
			response.StatusCode = stdhttp.StatusNoContent
			response.Status = "204 No Content"
			return response, nil
		})
	}
	options := model.DefaultDiagnoseOptions("http://example.com/start")
	state := model.NewState(model.Target{
		Kind:       model.TargetHTTP,
		Host:       "example.com",
		Port:       80,
		RequestURL: "http://example.com:80/start?token=request-secret",
	}, options)

	result := check.Run(context.Background(), state)

	if result.Status != model.StatusPassed {
		t.Fatalf("result = %#v", result)
	}
	httpResult := state.HTTP()
	if httpResult.StatusCode != stdhttp.StatusNoContent ||
		httpResult.FinalURL != "http://example.com:80/final?api_key=[REDACTED]&view=full" {
		t.Fatalf("HTTP result = %#v", httpResult)
	}
	if len(httpResult.Redirects) != 1 {
		t.Fatalf("redirects = %#v, want one redirect", httpResult.Redirects)
	}
	redirect := httpResult.Redirects[0]
	if redirect.StatusCode != stdhttp.StatusFound ||
		redirect.From != "http://example.com:80/start?token=[REDACTED]" ||
		redirect.To != "http://example.com:80/final?api_key=[REDACTED]&view=full" {
		t.Fatalf("redirect = %#v", redirect)
	}
}

func TestCheckDetectsRedirectLoop(t *testing.T) {
	t.Parallel()
	check := New()
	check.TransportFactory = func(*model.State) stdhttp.RoundTripper {
		return roundTripFunc(func(request *stdhttp.Request) (*stdhttp.Response, error) {
			location := "/b"
			if request.URL.Path == "/b" {
				location = "/a"
			}
			if got := request.Header.Get("User-Agent"); got != "OpsDoctor-test/1" {
				t.Errorf("User-Agent = %q", got)
			}
			return &stdhttp.Response{
				StatusCode: 302,
				Status:     "302 Found",
				Proto:      "HTTP/1.1",
				Header:     stdhttp.Header{"Location": {location}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    request,
			}, nil
		})
	}
	options := model.DefaultDiagnoseOptions("http://example.com/a")
	options.UserAgent = "OpsDoctor-test/1"
	state := model.NewState(model.Target{
		Kind:       model.TargetHTTP,
		Host:       "example.com",
		Port:       80,
		RequestURL: "http://example.com:80/a",
	}, options)
	result := check.Run(context.Background(), state)
	if result.Status != model.StatusFailed || result.ErrorCode != ErrorRedirectLoop {
		t.Fatalf("result = %#v", result)
	}
	if got := len(state.HTTP().Redirects); got != 2 {
		t.Fatalf("redirect count = %d", got)
	}
}

func TestNetworkForIPVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		network string
		version model.IPVersion
		want    string
	}{
		{name: "automatic TCP", network: "tcp", version: model.IPVersionAuto, want: "tcp"},
		{name: "IPv4 TCP", network: "tcp", version: model.IPVersion4, want: "tcp4"},
		{name: "IPv6 TCP", network: "tcp4", version: model.IPVersion6, want: "tcp6"},
		{name: "non-TCP unchanged", network: "udp", version: model.IPVersion4, want: "udp"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := networkForIPVersion(test.network, test.version); got != test.want {
				t.Fatalf("networkForIPVersion() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSafeURLAndRedactHeaders(t *testing.T) {
	t.Parallel()
	value, err := url.Parse("https://user:pass@example.com/a?api_key=secret&view=full#fragment")
	if err != nil {
		t.Fatal(err)
	}
	safe := SafeURL(value)
	for _, forbidden := range []string{"user", "pass", "secret", "fragment"} {
		if strings.Contains(safe, forbidden) {
			t.Fatalf("SafeURL leaked %q: %s", forbidden, safe)
		}
	}
	headers := RedactHeaders(stdhttp.Header{
		"Authorization":       {"Bearer secret"},
		"Proxy-Authorization": {"Basic secret"},
		"Cookie":              {"token=secret"},
		"X-Request-ID":        {"abc"},
	})
	if headers["Authorization"][0] != "[REDACTED]" ||
		headers["Proxy-Authorization"][0] != "[REDACTED]" ||
		headers["Cookie"][0] != "[REDACTED]" ||
		headers["X-Request-ID"][0] != "abc" {
		t.Fatalf("headers = %#v", headers)
	}
}
