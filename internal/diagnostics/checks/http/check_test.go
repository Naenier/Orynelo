package http

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	environmentcheck "github.com/Naenier/opsdoctor/internal/diagnostics/checks/environment"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

type roundTripFunc func(*stdhttp.Request) (*stdhttp.Response, error)

func (f roundTripFunc) RoundTrip(request *stdhttp.Request) (*stdhttp.Response, error) {
	return f(request)
}

type resolverFunc func(context.Context, string, string) ([]net.IP, error)

func (f resolverFunc) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return f(ctx, network, host)
}

func TestCheckReportsTCPTargetAsNotApplicable(t *testing.T) {
	t.Parallel()
	state := model.NewState(
		model.Target{Kind: model.TargetTCP},
		model.DefaultDiagnoseOptions("example.test:443"),
	)
	result := New().Run(context.Background(), state)
	if result.Status != model.StatusNotApplicable {
		t.Fatalf("status = %q, want not_applicable", result.Status)
	}
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
	setNoProxyConfigured(state)
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
	setNoProxyConfigured(state)
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
	setNoProxyConfigured(state)

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
	check.Resolver = publicResolver()
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
	setNoProxyConfigured(state)

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

func TestCheckReportsLastAttemptedURLAfterRedirectTransportFailure(t *testing.T) {
	t.Parallel()
	check := New()
	check.Resolver = publicResolver()
	check.TransportFactory = func(*model.State) stdhttp.RoundTripper {
		return roundTripFunc(func(request *stdhttp.Request) (*stdhttp.Response, error) {
			if request.URL.Hostname() == "origin.example" {
				return redirectResponse(request, "https://next.example/final?token=redirect-secret"), nil
			}
			return nil, errors.New("connection refused")
		})
	}
	state := testHTTPState("https://origin.example/start")

	result := check.Run(context.Background(), state)

	if result.Status != model.StatusFailed || result.ErrorCode != ErrorTransport {
		t.Fatalf("result = %#v", result)
	}
	httpResult := state.HTTP()
	if httpResult.FinalURL != "https://next.example/final?token=[REDACTED]" {
		t.Fatalf("FinalURL = %q, want last attempted redirect URL", httpResult.FinalURL)
	}
	if strings.Contains(fmt.Sprintf("%#v", result), "redirect-secret") {
		t.Fatalf("result leaked redirect secret: %#v", result)
	}
}

func TestCheckDetectsRedirectLoop(t *testing.T) {
	t.Parallel()
	check := New()
	check.Resolver = publicResolver()
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
	setNoProxyConfigured(state)
	result := check.Run(context.Background(), state)
	if result.Status != model.StatusFailed || result.ErrorCode != ErrorRedirectLoop {
		t.Fatalf("result = %#v", result)
	}
	if got := len(state.HTTP().Redirects); got != 2 {
		t.Fatalf("redirect count = %d", got)
	}
}

func TestCheckInvalidProxyNeverInvokesTransport(t *testing.T) {
	t.Parallel()
	called := false
	check := New()
	check.TransportFactory = func(*model.State) stdhttp.RoundTripper {
		called = true
		return roundTripFunc(func(*stdhttp.Request) (*stdhttp.Response, error) {
			return nil, errors.New("must not be called")
		})
	}
	state := testHTTPState("https://example.com/start")
	state.SetProxy(model.ProxyInfo{Selection: model.ProxySelection{
		SourceVariable: "HTTPS_PROXY",
		URL:            "[configured proxy]",
		Validity:       model.ProxyValidityInvalid,
		ErrorCode:      ErrorProxyConfig,
	}})

	result := check.Run(context.Background(), state)

	if called || result.Status != model.StatusFailed || result.ErrorCode != ErrorProxyConfig {
		t.Fatalf("called=%t result=%#v", called, result)
	}
}

func TestCheckBlocksHTTPSDowngradeUnlessExplicitlyAllowed(t *testing.T) {
	t.Parallel()
	for _, allow := range []bool{false, true} {
		allow := allow
		t.Run(strconv.FormatBool(allow), func(t *testing.T) {
			t.Parallel()
			check := redirectCheck("http://example.com/final")
			state := testHTTPState("https://example.com/start")
			state.Options.AllowInsecureRedirects = allow

			result := check.Run(context.Background(), state)

			if allow {
				if result.Status != model.StatusPassed {
					t.Fatalf("opt-in result = %#v", result)
				}
				if got := state.HTTP().Redirects[0].PolicyDecision; got != "followed_https_downgrade_opt_in" {
					t.Fatalf("decision = %q", got)
				}
			} else if result.Status != model.StatusFailed || result.ErrorCode != ErrorRedirectDowngrade {
				t.Fatalf("default result = %#v", result)
			}
		})
	}
}

func TestCheckBlocksPublicToPrivateRedirectUnlessExplicitlyAllowed(t *testing.T) {
	t.Parallel()
	for _, allow := range []bool{false, true} {
		allow := allow
		t.Run(strconv.FormatBool(allow), func(t *testing.T) {
			t.Parallel()
			check := redirectCheck("https://127.0.0.1/private")
			state := testHTTPState("https://93.184.216.34/start")
			state.Options.AllowPrivateRedirects = allow

			result := check.Run(context.Background(), state)

			if allow {
				if result.Status != model.StatusPassed {
					t.Fatalf("opt-in result = %#v", result)
				}
				if got := state.HTTP().Redirects[0].PolicyDecision; got != "followed_public_to_private_opt_in" {
					t.Fatalf("decision = %q", got)
				}
			} else if result.Status != model.StatusFailed || result.ErrorCode != ErrorRedirectPrivate {
				t.Fatalf("default result = %#v", result)
			}
		})
	}
}

func TestCheckBlocksProxyOriginToDirectPrivateRedirect(t *testing.T) {
	t.Parallel()
	requests := 0
	check := redirectCheck("https://127.0.0.1/private")
	baseFactory := check.TransportFactory
	check.TransportFactory = func(state *model.State) stdhttp.RoundTripper {
		base := baseFactory(state)
		return roundTripFunc(func(request *stdhttp.Request) (*stdhttp.Response, error) {
			requests++
			return base.RoundTrip(request)
		})
	}
	check.Resolver = resolverFunc(func(_ context.Context, _, host string) ([]net.IP, error) {
		if host == "proxied.example" {
			return []net.IP{net.ParseIP("10.0.0.10")}, nil
		}
		return nil, fmt.Errorf("unexpected local resolution for %q", host)
	})
	state := testHTTPState("https://proxied.example/start")
	applyProxyEnvironment(t, state, map[string]string{
		"HTTPS_PROXY": "http://proxy.example:8080",
		"NO_PROXY":    "127.0.0.1",
	})

	result := check.Run(context.Background(), state)

	if result.Status != model.StatusFailed || result.ErrorCode != ErrorRedirectPrivate || requests != 1 {
		t.Fatalf("requests=%d result=%#v", requests, result)
	}
	redirect := state.HTTP().Redirects[0]
	if redirect.Route != "direct" ||
		redirect.ProxySelection.BypassReason != model.ProxyBypassLoopback ||
		redirect.FromNetworkScope != "proxy_origin_unknown" ||
		redirect.ToNetworkScope != "private_or_local" ||
		redirect.PolicyDecision != "blocked_public_to_private" {
		t.Fatalf("redirect = %#v", redirect)
	}
}

func TestCheckTreatsMixedSourceDNSAsPotentiallyPublic(t *testing.T) {
	t.Parallel()
	check := redirectCheck("https://127.0.0.1/private")
	check.Resolver = resolverFunc(func(_ context.Context, _, host string) ([]net.IP, error) {
		if host != "mixed.example" {
			t.Fatalf("unexpected lookup for %q", host)
		}
		return []net.IP{
			net.ParseIP("93.184.216.34"),
			net.ParseIP("10.0.0.10"),
		}, nil
	})
	state := testHTTPState("https://mixed.example/start")

	result := check.Run(context.Background(), state)

	if result.Status != model.StatusFailed || result.ErrorCode != ErrorRedirectPrivate {
		t.Fatalf("result = %#v", result)
	}
	redirect := state.HTTP().Redirects[0]
	if redirect.FromNetworkScope != "mixed" ||
		redirect.ToNetworkScope != "private_or_local" ||
		redirect.PolicyDecision != "blocked_public_to_private" {
		t.Fatalf("redirect = %#v", redirect)
	}
}

func TestCheckBlocksSameHostDNSRebinding(t *testing.T) {
	t.Parallel()
	check := redirectCheck("/final")
	lookups := 0
	check.Resolver = resolverFunc(func(_ context.Context, _, host string) ([]net.IP, error) {
		if host != "rebind.example" {
			t.Fatalf("unexpected lookup for %q", host)
		}
		lookups++
		if lookups == 1 {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		}
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	})
	state := testHTTPState("https://rebind.example/start")

	result := check.Run(context.Background(), state)

	if result.Status != model.StatusFailed || result.ErrorCode != ErrorRedirectPrivate {
		t.Fatalf("result = %#v", result)
	}
	redirect := state.HTTP().Redirects[0]
	if lookups != 2 || redirect.FromNetworkScope != "public" ||
		redirect.ToNetworkScope != "private_or_local" {
		t.Fatalf("lookups=%d redirect=%#v", lookups, redirect)
	}
}

func TestCheckFailsClosedWhenRedirectResolutionFails(t *testing.T) {
	t.Parallel()
	check := redirectCheck("https://unresolved.example/final")
	check.Resolver = resolverFunc(func(context.Context, string, string) ([]net.IP, error) {
		return nil, errors.New("resolver unavailable")
	})
	state := testHTTPState("https://public.example/start")

	result := check.Run(context.Background(), state)

	if result.Status != model.StatusFailed || result.ErrorCode != ErrorRedirectResolve {
		t.Fatalf("result = %#v", result)
	}
	if got := state.HTTP().Redirects[0].PolicyDecision; got != "blocked_resolution_failure" {
		t.Fatalf("decision = %q", got)
	}
}

func TestRedirectProxyPolicyIsReevaluatedFromCapturedEnvironment(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		initialURL       string
		location         string
		environment      map[string]string
		wantRoute        string
		wantSource       string
		wantBypass       model.ProxyBypassReason
		wantError        string
		wantRequestCount int
		wantFinalRoute   string
	}{
		{
			name:       "initial NO_PROXY then outside uses proxy",
			initialURL: "https://bypass.example/start",
			location:   "https://outside.example/final",
			environment: map[string]string{
				"HTTPS_PROXY": "http://user:password@proxy.example:8443",
				"NO_PROXY":    "bypass.example",
			},
			wantRoute:        "proxy",
			wantSource:       "HTTPS_PROXY",
			wantRequestCount: 2,
			wantFinalRoute:   "mixed",
		},
		{
			name:       "selected then NO_PROXY becomes direct",
			initialURL: "https://selected.example/start",
			location:   "https://bypass.example/final",
			environment: map[string]string{
				"HTTPS_PROXY": "http://proxy.example:8443",
				"NO_PROXY":    "bypass.example",
			},
			wantRoute:        "direct",
			wantSource:       "HTTPS_PROXY",
			wantBypass:       model.ProxyBypassNoProxy,
			wantRequestCount: 2,
			wantFinalRoute:   "mixed",
		},
		{
			name:       "HTTP to HTTPS switches source",
			initialURL: "http://switch.example/start",
			location:   "https://switch.example/final",
			environment: map[string]string{
				"HTTP_PROXY":  "http://http-proxy.example:8080",
				"HTTPS_PROXY": "http://https-proxy.example:8443",
			},
			wantRoute:        "proxy",
			wantSource:       "HTTPS_PROXY",
			wantRequestCount: 2,
			wantFinalRoute:   "proxy",
		},
		{
			name:       "invalid redirect scheme proxy fails closed",
			initialURL: "http://valid.example/start",
			location:   "https://invalid.example/final",
			environment: map[string]string{
				"HTTP_PROXY":  "http://http-proxy.example:8080",
				"HTTPS_PROXY": "%%%",
			},
			wantRoute:        "blocked_by_proxy_policy",
			wantSource:       "HTTPS_PROXY",
			wantError:        ErrorProxyConfig,
			wantRequestCount: 1,
			wantFinalRoute:   "proxy",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			requests := 0
			check := redirectCheck(test.location)
			baseFactory := check.TransportFactory
			check.TransportFactory = func(state *model.State) stdhttp.RoundTripper {
				base := baseFactory(state)
				return roundTripFunc(func(request *stdhttp.Request) (*stdhttp.Response, error) {
					requests++
					return base.RoundTrip(request)
				})
			}
			state := testHTTPState(test.initialURL)
			applyProxyEnvironment(t, state, test.environment)

			result := check.Run(context.Background(), state)

			if result.ErrorCode != test.wantError {
				t.Fatalf("result = %#v", result)
			}
			if requests != test.wantRequestCount {
				t.Fatalf("requests = %d, want %d", requests, test.wantRequestCount)
			}
			if got := state.HTTP().Route; got != test.wantFinalRoute {
				t.Fatalf("final route = %q, want %q; HTTP=%#v", got, test.wantFinalRoute, state.HTTP())
			}
			redirect := state.HTTP().Redirects[0]
			if redirect.Route != test.wantRoute ||
				redirect.ProxySelection.SourceVariable != test.wantSource ||
				redirect.ProxySelection.BypassReason != test.wantBypass {
				t.Fatalf("redirect = %#v", redirect)
			}
			if redirect.ProxySelection.RequestURL != "" {
				t.Fatalf("redirect retained request-capable proxy URL: %#v", redirect.ProxySelection)
			}
			foundRouteEvidence := false
			for _, evidence := range result.Evidence {
				if evidence.ID == "http.redirect.1" &&
					evidence.Details["route"] == test.wantRoute &&
					evidence.Details["proxySource"] == test.wantSource {
					foundRouteEvidence = true
				}
			}
			if !foundRouteEvidence {
				t.Fatalf("route evidence missing: %#v", result.Evidence)
			}
		})
	}
}

func TestRedirectFailsClosedWhenCapturedProxySelectionIsUnavailable(t *testing.T) {
	t.Parallel()
	requests := 0
	check := redirectCheck("https://next.example/final")
	baseFactory := check.TransportFactory
	check.TransportFactory = func(state *model.State) stdhttp.RoundTripper {
		base := baseFactory(state)
		return roundTripFunc(func(request *stdhttp.Request) (*stdhttp.Response, error) {
			requests++
			return base.RoundTrip(request)
		})
	}
	state := testHTTPState("https://initial.example/start")
	state.SetProxy(model.ProxyInfo{
		Selection: model.ProxySelection{Validity: model.ProxyValidityNotConfigured},
		SelectForURL: func(target *url.URL) model.ProxySelection {
			if target.Hostname() == "initial.example" {
				return model.ProxySelection{Validity: model.ProxyValidityNotConfigured}
			}
			return model.ProxySelection{}
		},
	})

	result := check.Run(context.Background(), state)

	if result.Status != model.StatusFailed || result.ErrorCode != ErrorProxyUnavailable || requests != 1 {
		t.Fatalf("requests=%d result=%#v", requests, result)
	}
	redirect := state.HTTP().Redirects[0]
	if redirect.PolicyDecision != "blocked_proxy_selection_unavailable" ||
		redirect.Route != "blocked_by_proxy_policy" {
		t.Fatalf("redirect = %#v", redirect)
	}
}

func TestTransportAppliesCapturedProxyPolicyForEveryRequest(t *testing.T) {
	t.Parallel()
	state := testHTTPState("https://bypass.example/start")
	applyProxyEnvironment(t, state, map[string]string{
		"HTTPS_PROXY": "http://user:password@proxy.example:8443",
		"NO_PROXY":    "bypass.example",
	})
	transport, err := New().transport(state)
	if err != nil {
		t.Fatal(err)
	}
	actual := transport.(*stdhttp.Transport)

	initial, _ := stdhttp.NewRequest(stdhttp.MethodGet, "https://bypass.example/start", nil)
	selected, _ := stdhttp.NewRequest(stdhttp.MethodGet, "https://outside.example/final", nil)
	initialProxy, err := actual.Proxy(initial)
	if err != nil || initialProxy != nil {
		t.Fatalf("initial proxy = %v, %v", initialProxy, err)
	}
	redirectProxy, err := actual.Proxy(selected)
	if err != nil || redirectProxy == nil || redirectProxy.Host != "proxy.example:8443" ||
		redirectProxy.User == nil {
		t.Fatalf("redirect proxy = %v, %v", redirectProxy, err)
	}
}

func TestCheckCrossOriginRemovesSensitiveHeadersAndRecordsPolicy(t *testing.T) {
	t.Parallel()
	check := New()
	check.Resolver = resolverFunc(func(_ context.Context, _, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	})
	check.RequestHeaders = stdhttp.Header{
		"Authorization":       {"Bearer secret"},
		"Cookie":              {"session=secret"},
		"Proxy-Authorization": {"Basic secret"},
		"X-Api-Key":           {"api-secret"},
	}
	check.TransportFactory = func(*model.State) stdhttp.RoundTripper {
		return roundTripFunc(func(request *stdhttp.Request) (*stdhttp.Response, error) {
			if request.URL.Hostname() == "origin.example" {
				return redirectResponse(request, "https://other.example/final"), nil
			}
			for _, name := range []string{
				"Authorization", "Cookie", "Proxy-Authorization", "X-Api-Key",
			} {
				if value := request.Header.Get(name); value != "" {
					t.Errorf("%s forwarded cross-origin: %q", name, value)
				}
			}
			return successResponse(request), nil
		})
	}
	state := testHTTPState("https://origin.example/start")

	result := check.Run(context.Background(), state)

	if result.Status != model.StatusPassed {
		t.Fatalf("result = %#v", result)
	}
	redirect := state.HTTP().Redirects[0]
	wantRemoved := "Authorization,Cookie,Proxy-Authorization,Referer,X-Api-Key"
	if !redirect.CrossOrigin ||
		strings.Join(redirect.SensitiveHeadersRemoved, ",") != wantRemoved ||
		redirect.PolicyDecision != "followed_cross_origin_headers_removed" {
		t.Fatalf("redirect = %#v", redirect)
	}
	found := false
	for _, evidence := range result.Evidence {
		if evidence.Code == "HTTP_REDIRECT_CROSS_ORIGIN" &&
			strings.Contains(evidence.Details["sensitiveHeadersRemoved"], "Authorization") {
			found = true
		}
	}
	if !found {
		t.Fatalf("cross-origin evidence missing: %#v", result.Evidence)
	}
}

func TestCheckCrossOriginDoesNotClaimAbsentHeadersWereRemoved(t *testing.T) {
	t.Parallel()
	check := redirectCheck("https://other.example/final")
	check.Resolver = resolverFunc(func(_ context.Context, _, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	})
	state := testHTTPState("https://origin.example/start")

	result := check.Run(context.Background(), state)

	if result.Status != model.StatusPassed {
		t.Fatalf("result = %#v", result)
	}
	redirect := state.HTTP().Redirects[0]
	if !redirect.CrossOrigin ||
		strings.Join(redirect.SensitiveHeadersRemoved, ",") != "Referer" ||
		redirect.PolicyDecision != "followed_cross_origin_headers_removed" {
		t.Fatalf("redirect = %#v", redirect)
	}
}

func TestCheckDropsSecretBearingRefererCrossOrigin(t *testing.T) {
	t.Parallel()
	check := redirectCheck("https://other.example/final")
	baseFactory := check.TransportFactory
	check.TransportFactory = func(state *model.State) stdhttp.RoundTripper {
		base := baseFactory(state)
		return roundTripFunc(func(request *stdhttp.Request) (*stdhttp.Response, error) {
			if request.URL.Hostname() == "other.example" && request.Header.Get("Referer") != "" {
				t.Errorf("Referer forwarded cross-origin: %q", request.Header.Get("Referer"))
			}
			return base.RoundTrip(request)
		})
	}
	state := testHTTPState("https://origin.example/start?token=referer-secret")

	result := check.Run(context.Background(), state)

	if result.Status != model.StatusPassed {
		t.Fatalf("result = %#v", result)
	}
	redirect := state.HTTP().Redirects[0]
	if strings.Join(redirect.SensitiveHeadersRemoved, ",") != "Referer" {
		t.Fatalf("redirect = %#v", redirect)
	}
	if strings.Contains(fmt.Sprintf("%#v", result), "referer-secret") {
		t.Fatalf("result leaked Referer query secret: %#v", result)
	}
}

func TestCheckStripsRedirectURLUserinfoEvenSameOrigin(t *testing.T) {
	t.Parallel()
	check := New()
	check.Resolver = publicResolver()
	check.TransportFactory = func(*model.State) stdhttp.RoundTripper {
		return roundTripFunc(func(request *stdhttp.Request) (*stdhttp.Response, error) {
			if request.URL.Path == "/start" {
				return redirectResponse(
					request,
					"https://redirect-user:redirect-password@example.com/final",
				), nil
			}
			if request.URL.User != nil || request.Header.Get("Authorization") != "" {
				t.Errorf("redirect userinfo was forwarded: URL=%v headers=%v", request.URL, request.Header)
			}
			return successResponse(request), nil
		})
	}
	state := testHTTPState("https://example.com/start")

	result := check.Run(context.Background(), state)

	if result.Status != model.StatusPassed {
		t.Fatalf("result = %#v", result)
	}
}

func TestCheckLimitsEachRedirectLocation(t *testing.T) {
	t.Parallel()
	check := redirectCheck("/" + strings.Repeat("x", 64))
	state := testHTTPState("https://example.com/start")
	state.Options.MaxRedirectLocationBytes = 16

	result := check.Run(context.Background(), state)

	if result.Status != model.StatusFailed || result.ErrorCode != ErrorLocationTooLarge {
		t.Fatalf("result = %#v", result)
	}
}

func TestIPNetworkScopeCoversLocalAndPrivateRanges(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"0.0.0.0":       "private_or_local",
		"127.0.0.1":     "private_or_local",
		"169.254.1.1":   "private_or_local",
		"10.1.2.3":      "private_or_local",
		"192.168.1.1":   "private_or_local",
		"100.64.0.1":    "private_or_local",
		"192.0.2.1":     "private_or_local",
		"198.18.0.1":    "private_or_local",
		"::":            "private_or_local",
		"::1":           "private_or_local",
		"fe80::1":       "private_or_local",
		"fd00::1":       "private_or_local",
		"2001:db8::1":   "private_or_local",
		"93.184.216.34": "public",
		"2606:4700::1":  "public",
	}
	for raw, want := range tests {
		if got := ipNetworkScope(net.ParseIP(raw)); got != want {
			t.Errorf("scope(%s) = %q, want %q", raw, got, want)
		}
	}
}

func TestCheckClassifiesProxyConnectFailure(t *testing.T) {
	t.Parallel()
	check := New()
	check.TransportFactory = func(*model.State) stdhttp.RoundTripper {
		return roundTripFunc(func(*stdhttp.Request) (*stdhttp.Response, error) {
			return nil, errors.New("proxyconnect tcp: connection refused")
		})
	}
	state := testHTTPState("https://example.com/start")
	state.SetProxy(model.ProxyInfo{
		Selected: true,
		Selection: model.ProxySelection{
			SourceVariable: "HTTPS_PROXY",
			URL:            "http://proxy.example:8080",
			RequestURL:     "http://proxy.example:8080",
			Validity:       model.ProxyValidityValid,
		},
	})

	result := check.Run(context.Background(), state)

	if result.Status != model.StatusFailed || result.ErrorCode != ErrorProxyConnect {
		t.Fatalf("result = %#v", result)
	}
	if got := state.HTTP().Route; got != "proxy" {
		t.Fatalf("route = %q", got)
	}
}

func TestCheckClassifiesRealProxyCONNECTRejectionWithoutDirectFallback(t *testing.T) {
	t.Parallel()
	var connectRequests atomic.Int32
	serverErrors := make(chan error, 1)
	check := New()
	check.DialContext = func(_ context.Context, _, address string) (net.Conn, error) {
		if address != "proxy.example:8080" {
			return nil, fmt.Errorf("unexpected direct fallback dial to %s", address)
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			request, err := stdhttp.ReadRequest(bufio.NewReader(server))
			if err != nil {
				serverErrors <- err
				return
			}
			connectRequests.Add(1)
			if request.Method != stdhttp.MethodConnect {
				serverErrors <- fmt.Errorf("proxy method = %q, want CONNECT", request.Method)
				return
			}
			_, err = io.WriteString(server, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			if err != nil {
				serverErrors <- err
			}
		}()
		return client, nil
	}

	state := testHTTPState("https://origin.invalid/start")
	state.SetProxy(model.ProxyInfo{
		Selected: true,
		Selection: model.ProxySelection{
			SourceVariable: "HTTPS_PROXY",
			URL:            "http://proxy.example:8080",
			RequestURL:     "http://proxy.example:8080",
			Validity:       model.ProxyValidityValid,
		},
	})
	result := check.Run(context.Background(), state)

	if result.Status != model.StatusFailed || result.ErrorCode != ErrorProxyConnect ||
		connectRequests.Load() != 1 {
		t.Fatalf("requests=%d result=%#v HTTP=%#v", connectRequests.Load(), result, state.HTTP())
	}
	if state.HTTP().Route != "proxy" || state.HTTP().Error != "proxy CONNECT failed" {
		t.Fatalf("HTTP result = %#v", state.HTTP())
	}
	select {
	case err := <-serverErrors:
		t.Fatal(err)
	default:
	}
}

func TestActualHTTPSRunsDespitePreflightTLSFailure(t *testing.T) {
	t.Parallel()
	called := false
	check := New()
	check.TransportFactory = func(*model.State) stdhttp.RoundTripper {
		called = true
		return roundTripFunc(func(request *stdhttp.Request) (*stdhttp.Response, error) {
			return successResponse(request), nil
		})
	}
	state := testHTTPState("https://example.com/start")
	state.SetTLS(model.TLSResult{ErrorCode: "TLS_CERTIFICATE_EXPIRED"})

	result := check.Run(context.Background(), state)

	if !called || result.Status != model.StatusPassed {
		t.Fatalf("called=%t result=%#v", called, result)
	}
}

func TestRedirectDialUsesPolicyApprovedIPWithoutSecondResolution(t *testing.T) {
	t.Parallel()
	check := New()
	var rebindLookups atomic.Int32
	check.Resolver = resolverFunc(func(_ context.Context, _, host string) ([]net.IP, error) {
		if host == "rebind.example" && rebindLookups.Add(1) > 1 {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	})
	dialed := make(chan string, 2)
	serverErrors := make(chan error, 2)
	check.DialContext = func(_ context.Context, _, address string) (net.Conn, error) {
		client, server := net.Pipe()
		dialed <- address
		go func() {
			defer server.Close()
			request, err := stdhttp.ReadRequest(bufio.NewReader(server))
			if err != nil {
				serverErrors <- err
				return
			}
			_ = request.Body.Close()
			response := "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
			if request.URL.Path == "/start" {
				response = "HTTP/1.1 302 Found\r\nLocation: http://rebind.example/final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
			}
			if _, err := io.WriteString(server, response); err != nil {
				serverErrors <- err
			}
		}()
		return client, nil
	}
	state := testHTTPState("http://origin.example/start")

	result := check.Run(context.Background(), state)

	if result.Status != model.StatusPassed {
		t.Fatalf("result=%#v HTTP=%#v", result, state.HTTP())
	}
	addresses := []string{<-dialed, <-dialed}
	if addresses[0] != "origin.example:80" || addresses[1] != "93.184.216.34:80" {
		t.Fatalf("dial addresses = %#v", addresses)
	}
	if rebindLookups.Load() != 1 {
		t.Fatalf("redirect lookups = %d, want exactly one policy lookup", rebindLookups.Load())
	}
	select {
	case err := <-serverErrors:
		t.Fatal(err)
	default:
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

func testHTTPState(rawURL string) *model.State {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	port := uint16(443)
	if parsed.Scheme == "http" {
		port = 80
	}
	options := model.DefaultDiagnoseOptions(rawURL)
	state := model.NewState(model.Target{
		Kind:       model.TargetHTTP,
		Scheme:     parsed.Scheme,
		Host:       parsed.Hostname(),
		Port:       port,
		UseTLS:     parsed.Scheme == "https",
		RequestURL: rawURL,
	}, options)
	setNoProxyConfigured(state)
	return state
}

func setNoProxyConfigured(state *model.State) {
	state.SetProxy(model.ProxyInfo{Selection: model.ProxySelection{
		Validity: model.ProxyValidityNotConfigured,
	}})
}

func applyProxyEnvironment(
	t *testing.T,
	state *model.State,
	values map[string]string,
) {
	t.Helper()
	result := (&environmentcheck.Check{LookupEnv: func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}}).Run(context.Background(), state)
	if result.Status == model.StatusFailed {
		t.Fatalf("initial proxy selection failed: %#v", result)
	}
}

func redirectCheck(location string) *Check {
	check := New()
	check.Resolver = publicResolver()
	check.TransportFactory = func(*model.State) stdhttp.RoundTripper {
		return roundTripFunc(func(request *stdhttp.Request) (*stdhttp.Response, error) {
			if request.URL.Path == "/start" {
				return redirectResponse(request, location), nil
			}
			return successResponse(request), nil
		})
	}
	return check
}

func publicResolver() Resolver {
	return resolverFunc(func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	})
}

func redirectResponse(request *stdhttp.Request, location string) *stdhttp.Response {
	return &stdhttp.Response{
		StatusCode: stdhttp.StatusFound,
		Status:     "302 Found",
		Proto:      "HTTP/1.1",
		Header:     stdhttp.Header{"Location": {location}},
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    request,
	}
}

func successResponse(request *stdhttp.Request) *stdhttp.Response {
	return &stdhttp.Response{
		StatusCode: stdhttp.StatusNoContent,
		Status:     "204 No Content",
		Proto:      "HTTP/1.1",
		Header:     make(stdhttp.Header),
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    request,
	}
}
