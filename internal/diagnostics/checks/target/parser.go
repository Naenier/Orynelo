// Package target parses user-supplied network targets into a canonical,
// privacy-safe domain representation.
package target

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/redaction"
	"golang.org/x/net/idna"
)

const (
	ErrorEmptyTarget       = "TARGET_EMPTY"
	ErrorInvalidTarget     = "TARGET_INVALID"
	ErrorUnsupportedScheme = "TARGET_UNSUPPORTED_SCHEME"
	ErrorMissingHost       = "TARGET_MISSING_HOST"
	ErrorInvalidPort       = "TARGET_INVALID_PORT"
)

// ParseError is a stable, user-input error.
type ParseError struct {
	Code    string
	Message string
	Err     error
}

func (e *ParseError) Error() string {
	if e.Err == nil {
		return e.Message
	}
	return e.Message + ": " + e.Err.Error()
}

func (e *ParseError) Unwrap() error { return e.Err }

// Parse accepts URLs, host:port endpoints, IPv4, bracketed IPv6 endpoints,
// and bare DNS names. A bare host safely defaults to HTTPS on port 443.
func Parse(raw string) (model.Target, error) {
	input := strings.TrimSpace(raw)
	if input == "" {
		return model.Target{}, &ParseError{Code: ErrorEmptyTarget, Message: "target is empty"}
	}
	for _, r := range input {
		if unicode.IsControl(r) {
			return model.Target{}, &ParseError{Code: ErrorInvalidTarget, Message: "target contains control characters"}
		}
	}
	if strings.Contains(input, "://") {
		return parseURL(input)
	}
	return parseEndpoint(input)
}

func parseURL(input string) (model.Target, error) {
	return parseURLWithOriginal(input, input)
}

func parseURLWithOriginal(input, originalInput string) (model.Target, error) {
	u, err := url.Parse(input)
	if err != nil {
		// url.Error may include the complete input, including credentials or
		// query secrets, so it is deliberately not retained.
		return model.Target{}, &ParseError{Code: ErrorInvalidTarget, Message: "invalid URL"}
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return model.Target{}, &ParseError{
			Code:    ErrorUnsupportedScheme,
			Message: fmt.Sprintf("unsupported URL scheme %q; only http and https are supported", scheme),
		}
	}
	if u.Hostname() == "" {
		return model.Target{}, &ParseError{Code: ErrorMissingHost, Message: "URL host is empty"}
	}
	host, display, err := normalizeHost(u.Hostname())
	if err != nil {
		return model.Target{}, err
	}
	port, err := parsePort(u.Port(), defaultPort(scheme))
	if err != nil {
		return model.Target{}, err
	}

	// Requests deliberately omit URL userinfo. Diagnostics should not replay
	// embedded credentials, and reports must never contain them.
	u.User = nil
	u.Scheme = scheme
	u.Host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	u.Fragment = ""
	requestURL := u.String()

	safe := *u
	normalized := redaction.RedactParsedURL(&safe).String()
	original := sanitizedOriginal(originalInput)

	return model.Target{
		Original:    original,
		Normalized:  normalized,
		Scheme:      scheme,
		Host:        host,
		DisplayHost: display,
		Port:        port,
		Path:        u.EscapedPath(),
		Kind:        model.TargetHTTP,
		UseTLS:      scheme == "https",
		RequestURL:  requestURL,
	}, nil
}

func parseEndpoint(input string) (model.Target, error) {
	// A slash or query without a scheme is interpreted as an HTTPS URL.
	if strings.ContainsAny(input, "/?#") {
		return parseURLWithOriginal("https://"+input, input)
	}
	if strings.HasPrefix(input, "[") != strings.HasSuffix(input, "]") &&
		!hasBracketedPort(input) {
		return model.Target{}, &ParseError{Code: ErrorInvalidTarget, Message: "invalid bracketed IPv6 target"}
	}

	host := input
	portText := ""
	explicitPort := false

	if parsedIP := net.ParseIP(strings.Trim(input, "[]")); parsedIP != nil && !hasBracketedPort(input) {
		host = parsedIP.String()
	} else if h, p, err := net.SplitHostPort(input); err == nil {
		host, portText, explicitPort = h, p, true
	} else if strings.HasPrefix(input, "[") {
		return model.Target{}, &ParseError{Code: ErrorInvalidTarget, Message: "invalid bracketed IPv6 target", Err: err}
	} else if strings.Count(input, ":") == 1 {
		h, p, ok := strings.Cut(input, ":")
		if !ok || h == "" || p == "" {
			return model.Target{}, &ParseError{Code: ErrorInvalidTarget, Message: "invalid host:port target"}
		}
		host, portText, explicitPort = h, p, true
	}

	asciiHost, display, err := normalizeHost(host)
	if err != nil {
		return model.Target{}, err
	}
	port, err := parsePort(portText, 443)
	if err != nil {
		return model.Target{}, err
	}

	if explicitPort {
		normalized := net.JoinHostPort(asciiHost, strconv.Itoa(int(port)))
		return model.Target{
			Original:    input,
			Normalized:  normalized,
			Host:        asciiHost,
			DisplayHost: display,
			Port:        port,
			Kind:        model.TargetTCP,
		}, nil
	}

	u := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(asciiHost, strconv.Itoa(int(port))),
	}
	return model.Target{
		Original:    input,
		Normalized:  u.String(),
		Scheme:      "https",
		Host:        asciiHost,
		DisplayHost: display,
		Port:        port,
		Kind:        model.TargetHTTP,
		UseTLS:      true,
		RequestURL:  u.String(),
	}, nil
}

func normalizeHost(host string) (ascii, display string, err error) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return "", "", &ParseError{Code: ErrorMissingHost, Message: "target host is empty"}
	}
	if strings.ContainsAny(host, " \t\r\n/\\") {
		return "", "", &ParseError{Code: ErrorInvalidTarget, Message: "target host contains invalid characters"}
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), ip.String(), nil
	}
	ascii, err = idna.Lookup.ToASCII(host)
	if err != nil {
		return "", "", &ParseError{Code: ErrorInvalidTarget, Message: "invalid internationalized hostname", Err: err}
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > 253 {
		return "", "", &ParseError{Code: ErrorInvalidTarget, Message: "hostname is too long"}
	}
	return ascii, host, nil
}

func parsePort(port string, fallback uint16) (uint16, error) {
	if port == "" {
		return fallback, nil
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return 0, &ParseError{Code: ErrorInvalidPort, Message: fmt.Sprintf("invalid port %q", port), Err: err}
	}
	return uint16(n), nil
}

func defaultPort(scheme string) uint16 {
	if scheme == "http" {
		return 80
	}
	return 443
}

func hasBracketedPort(input string) bool {
	close := strings.LastIndexByte(input, ']')
	return close >= 0 && len(input) > close+1 && input[close+1] == ':'
}

func sanitizedOriginal(input string) string {
	parseInput := input
	schemeAdded := !strings.Contains(input, "://") && strings.ContainsAny(input, "/?#")
	if schemeAdded {
		parseInput = "https://" + input
	}
	u, err := url.Parse(parseInput)
	if err != nil {
		return "[INVALID TARGET]"
	}
	u.User = nil
	u.Fragment = ""
	safe := redaction.RedactParsedURL(u).String()
	if schemeAdded {
		return strings.TrimPrefix(safe, "https://")
	}
	return safe
}

// ErrorCode extracts a stable parser error code.
func ErrorCode(err error) string {
	var parseErr *ParseError
	if errors.As(err, &parseErr) {
		return parseErr.Code
	}
	return ErrorInvalidTarget
}
