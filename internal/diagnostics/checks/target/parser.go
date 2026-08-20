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

	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/redaction"
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

// Unwrap returns the underlying target parsing error.
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
	switch scheme {
	case "http", "https", "tcp", "tls":
	default:
		return model.Target{}, &ParseError{
			Code:    ErrorUnsupportedScheme,
			Message: fmt.Sprintf("unsupported URL scheme %q; supported schemes are tcp, tls, http, and https", scheme),
		}
	}
	if u.Hostname() == "" {
		return model.Target{}, &ParseError{Code: ErrorMissingHost, Message: "URL host is empty"}
	}
	host, display, zone, err := normalizeHost(u.Hostname())
	if err != nil {
		return model.Target{}, err
	}
	if scheme == "tcp" || scheme == "tls" {
		return parseTransportURL(u, originalInput, scheme, host, display, zone)
	}
	port, err := parsePort(u.Port(), defaultPort(scheme))
	if err != nil {
		return model.Target{}, err
	}

	redactedURL := redaction.RedactParsedURL(u)
	privacyRedacted := u.User != nil || redactedURL.RawQuery != u.RawQuery

	// Requests deliberately omit URL userinfo. Diagnostics should not replay
	// embedded credentials, and reports must never contain them.
	u.User = nil
	u.Scheme = scheme
	u.Host = net.JoinHostPort(scopedHost(host, zone), strconv.Itoa(int(port)))
	u.Fragment = ""
	requestURL := u.String()

	safe := *u
	normalized := redaction.RedactParsedURL(&safe).String()
	original := sanitizedOriginal(originalInput)

	return model.Target{
		Original:        original,
		Normalized:      normalized,
		Scheme:          scheme,
		Host:            host,
		DisplayHost:     display,
		Port:            port,
		Path:            u.EscapedPath(),
		Kind:            model.TargetHTTP,
		UseTLS:          scheme == "https",
		Mode:            httpTargetMode(scheme),
		Zone:            zone,
		PrivacyRedacted: privacyRedacted,
		RequestURL:      requestURL,
	}, nil
}

func parseTransportURL(
	u *url.URL,
	originalInput string,
	scheme string,
	host string,
	display string,
	zone string,
) (model.Target, error) {
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return model.Target{}, &ParseError{
			Code:    ErrorInvalidTarget,
			Message: fmt.Sprintf("%s target must contain only a host and port", scheme),
		}
	}
	if u.Port() == "" {
		return model.Target{}, &ParseError{
			Code:    ErrorInvalidPort,
			Message: fmt.Sprintf("%s target requires an explicit port", scheme),
		}
	}
	port, err := parsePort(u.Port(), 0)
	if err != nil {
		return model.Target{}, err
	}
	u.Scheme = scheme
	u.Host = net.JoinHostPort(scopedHost(host, zone), strconv.Itoa(int(port)))
	u.User = nil
	u.Fragment = ""
	u.RawQuery = ""
	normalized := u.String()
	mode := model.TargetModeTCP
	if scheme == "tls" {
		mode = model.TargetModeTLS
	}
	return model.Target{
		Original:    sanitizedOriginal(originalInput),
		Normalized:  normalized,
		Scheme:      scheme,
		Host:        host,
		DisplayHost: display,
		Port:        port,
		Kind:        model.TargetTCP,
		UseTLS:      scheme == "tls",
		Mode:        mode,
		Zone:        zone,
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

	asciiHost, display, zone, err := normalizeHost(host)
	if err != nil {
		return model.Target{}, err
	}
	port, err := parsePort(portText, 443)
	if err != nil {
		return model.Target{}, err
	}

	if explicitPort {
		normalized := net.JoinHostPort(scopedHost(asciiHost, zone), strconv.Itoa(int(port)))
		return model.Target{
			Original:    input,
			Normalized:  normalized,
			Host:        asciiHost,
			DisplayHost: display,
			Port:        port,
			Kind:        model.TargetTCP,
			Mode:        model.TargetModeTCP,
			Zone:        zone,
		}, nil
	}

	u := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(scopedHost(asciiHost, zone), strconv.Itoa(int(port))),
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
		Mode:        model.TargetModeHTTPS,
		Zone:        zone,
		RequestURL:  u.String(),
	}, nil
}

func normalizeHost(host string) (ascii, display, zone string, err error) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return "", "", "", &ParseError{Code: ErrorMissingHost, Message: "target host is empty"}
	}
	if strings.ContainsAny(host, " \t\r\n/\\") {
		return "", "", "", &ParseError{Code: ErrorInvalidTarget, Message: "target host contains invalid characters"}
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), ip.String(), "", nil
	}
	if address, candidateZone, ok := splitIPv6Zone(host); ok {
		return address.String(), address.String(), candidateZone, nil
	}
	ascii, err = idna.Lookup.ToASCII(host)
	if err != nil {
		return "", "", "", &ParseError{Code: ErrorInvalidTarget, Message: "invalid internationalized hostname", Err: err}
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > 253 {
		return "", "", "", &ParseError{Code: ErrorInvalidTarget, Message: "hostname is too long"}
	}
	return ascii, host, "", nil
}

func splitIPv6Zone(host string) (net.IP, string, bool) {
	addressText, zone, ok := strings.Cut(host, "%")
	if !ok || addressText == "" || !validZone(zone) {
		return nil, "", false
	}
	address := net.ParseIP(addressText)
	if address == nil || address.To4() != nil || !address.IsLinkLocalUnicast() {
		return nil, "", false
	}
	return address, zone, true
}

func validZone(zone string) bool {
	if zone == "" || len(zone) > 64 {
		return false
	}
	for _, r := range zone {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func scopedHost(host, zone string) string {
	if zone == "" {
		return host
	}
	return host + "%" + zone
}

func httpTargetMode(scheme string) model.TargetMode {
	if scheme == "http" {
		return model.TargetModeHTTP
	}
	return model.TargetModeHTTPS
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
