// Package privacy defines the single typed projection used whenever diagnostic
// data leaves the running process through persistence, reports, events, or the
// clipboard.
package privacy

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/redaction"
)

// Mode controls how much identifying context is retained in a projection.
type Mode string

const (
	// ModeStandard removes credentials and secret-like values while preserving
	// the diagnostic target and other non-secret context.
	ModeStandard Mode = "standard"
	// ModeStrict additionally removes URL paths and query values, internal
	// hosts/addresses, and recognizable local filesystem paths.
	ModeStrict Mode = "strict"
)

var (
	urlPattern              = regexp.MustCompile(`(?i)\b(?:https?|socks(?:4a?|5h?)?|ftp)://[^\s"'<>]+`)
	internalHostnamePattern = regexp.MustCompile(
		`(?i)\b(?:localhost|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:local|internal|localhost|lan|home|corp))\b`,
	)
	ipv4Pattern      = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	ipv6Pattern      = regexp.MustCompile(`(?i)(?:\[[0-9a-f:.%]+\]|(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.%]*)`)
	localPathPattern = regexp.MustCompile(
		`(?i)(^|[\s"'(=\[])(?:[a-z]:[\\/][^\s"'<>]+|/[^\s"'<>]+|\\\\[^\\\s]+\\[^\s"'<>]+)`,
	)
	lookupHostPattern = regexp.MustCompile(
		`(?i)\b(lookup\s+)([a-z0-9][a-z0-9-]{0,62})(\s+on\s+|:)`,
	)
	endpointHostPattern = regexp.MustCompile(
		`(?i)\b((?:dial\s+(?:tcp|udp)|connect(?:ing)?\s+to|host|hostname|proxy)\s+)([a-z0-9][a-z0-9-]{0,62})(:)`,
	)
	sharedAddressPrefix = netip.MustParsePrefix("100.64.0.0/10")
)

// ParseMode validates a user-facing anonymization mode.
func ParseMode(value string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(value))) {
	case "", ModeStandard:
		return ModeStandard, nil
	case ModeStrict:
		return ModeStrict, nil
	default:
		return "", fmt.Errorf("anonymization mode must be standard or strict, got %q", value)
	}
}

// Projection is an immutable typed privacy policy.
type Projection struct {
	mode Mode
}

// New returns a projection for a validated mode.
func New(mode Mode) (Projection, error) {
	parsed, err := ParseMode(string(mode))
	if err != nil {
		return Projection{}, err
	}
	return Projection{mode: parsed}, nil
}

// Standard returns the default credential-redacting projection.
func Standard() Projection {
	return Projection{mode: ModeStandard}
}

// Strict returns the opt-in high-anonymity projection.
func Strict() Projection {
	return Projection{mode: ModeStrict}
}

// Mode reports the projection mode.
func (p Projection) Mode() Mode {
	if p.mode == ModeStrict {
		return ModeStrict
	}
	return ModeStandard
}

// Diagnosis returns a deep-enough privacy-safe copy for serialization or
// display. The caller's value is never mutated.
func (p Projection) Diagnosis(input model.Diagnosis) model.Diagnosis {
	result := input
	result.Target = p.Target(input.Target)
	result.Options = p.Options(input.Options)
	result.StartedAt = utc(input.StartedAt)
	result.FinishedAt = utc(input.FinishedAt)
	result.Summary = p.summary(input.Summary)
	result.Checks = make([]model.CheckResult, len(input.Checks))
	for index := range input.Checks {
		result.Checks[index] = p.CheckResult(input.Checks[index])
	}
	return result
}

// Target returns a privacy-safe target without the request-capable URL.
func (p Projection) Target(input model.Target) model.Target {
	result := input
	result.Original = p.url(input.Original)
	result.Normalized = p.url(input.Normalized)
	result.PrivacyRedacted = input.PrivacyRedacted || result.Original != input.Original ||
		result.Normalized != input.Normalized
	result.RequestURL = ""
	result.Host = p.host(input.Host)
	result.DisplayHost = p.host(input.DisplayHost)
	result.Path = p.value("path", input.Path)
	return result
}

// Options returns a projection of all currently persisted request options.
func (p Projection) Options(input model.DiagnoseOptions) model.DiagnoseOptions {
	result := input
	result.Target = p.url(input.Target)
	result.UserAgent = p.value("userAgent", input.UserAgent)
	return result
}

// CheckResult returns a privacy-safe result with independent slices and maps.
func (p Projection) CheckResult(input model.CheckResult) model.CheckResult {
	result := input
	result.Name = p.value("checkName", input.Name)
	result.Summary = p.value("summary", input.Summary)
	result.StartedAt = utc(input.StartedAt)
	result.FinishedAt = utc(input.FinishedAt)
	result.Evidence = make([]model.Evidence, len(input.Evidence))
	for index, evidence := range input.Evidence {
		evidence.Message = p.value("message", evidence.Message)
		evidence.Details = p.details(evidence.Details)
		result.Evidence[index] = evidence
	}
	result.Recommendations = p.recommendations(input.Recommendations)
	return result
}

// Event returns a privacy-safe event for external consumers. Result is copied
// so projecting an event cannot mutate engine state.
func (p Projection) Event(input model.CheckEvent) model.CheckEvent {
	result := input
	result.CheckName = p.value("checkName", input.CheckName)
	result.At = utc(input.At)
	if input.Result != nil {
		projected := p.CheckResult(*input.Result)
		result.Result = &projected
	}
	return result
}

// Profile returns the exact value suitable for local persistence and for the
// save-preview shown to users.
func (p Projection) Profile(input model.Profile) model.Profile {
	result := input
	result.Name = strings.TrimSpace(p.value("profileName", input.Name))
	result.Target = p.url(strings.TrimSpace(input.Target))
	result.Method = strings.ToUpper(strings.TrimSpace(input.Method))
	result.EnableTLS = result.Mode == model.DiagnosticModeTLS
	result.CreatedAt = utc(input.CreatedAt)
	result.UpdatedAt = utc(input.UpdatedAt)
	return result
}

// HistoryEntry projects the compact history view returned by persistence.
func (p Projection) HistoryEntry(input model.HistoryEntry) model.HistoryEntry {
	result := input
	result.Target = p.url(input.Target)
	result.Date = utc(input.Date)
	return result
}

// Text projects unstructured clipboard text through the same policy.
func (p Projection) Text(input string) string {
	return p.value("clipboard", input)
}

func (p Projection) summary(input model.Summary) model.Summary {
	result := input
	result.Title = p.value("title", input.Title)
	result.Description = p.value("description", input.Description)
	result.EvidenceRefs = append([]string(nil), input.EvidenceRefs...)
	result.Recommendations = p.recommendations(input.Recommendations)
	return result
}

func (p Projection) recommendations(input []model.Recommendation) []model.Recommendation {
	if input == nil {
		return nil
	}
	result := append([]model.Recommendation(nil), input...)
	for index := range result {
		result[index].Message = p.value("recommendation", result[index].Message)
	}
	return result
}

func (p Projection) details(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		if redaction.IsSensitiveStructuredKey(key) {
			result[key] = redaction.Replacement
			continue
		}
		result[key] = p.value(key, value)
	}
	return result
}

func (p Projection) url(input string) string {
	redacted, schemeLess := redactURLLikeTarget(input)
	if p.Mode() != ModeStrict || strings.TrimSpace(redacted) == "" {
		return redacted
	}
	parseInput := redacted
	if schemeLess {
		parseInput = "//" + redacted
	}
	parsed, err := url.Parse(parseInput)
	if err != nil || (!schemeLess && parsed.Scheme == "") || (schemeLess && parsed.Host == "") {
		return p.value("target", redacted)
	}
	if isInternalHost(parsed.Hostname()) {
		host := "redacted.invalid"
		if port := parsed.Port(); port != "" {
			host = net.JoinHostPort(host, port)
		}
		parsed.Host = host
	}
	if parsed.Path != "" && parsed.Path != "/" {
		parsed.Path = "/" + redaction.Replacement
		parsed.RawPath = ""
	}
	parsed.RawQuery = redactEveryQueryValue(parsed.RawQuery)
	if parsed.Fragment != "" {
		parsed.Fragment = redaction.Replacement
	}
	result := parsed.String()
	if schemeLess {
		result = strings.TrimPrefix(result, "//")
	}
	return result
}

func redactURLLikeTarget(input string) (string, bool) {
	schemeLess := !strings.Contains(input, "://")
	if schemeLess {
		// Target parsing treats an authority followed by a path/query as HTTPS
		// even without a scheme. Parse it the same way here so
		// user:password@host cannot be mistaken for an opaque custom scheme.
		parsed, err := url.Parse("//" + input)
		if err == nil && parsed.Host != "" {
			return strings.TrimPrefix(redaction.RedactParsedURL(parsed).String(), "//"), true
		}
		// RedactProxyURL also applies a conservative authority-userinfo
		// fallback when malformed escaping prevents URL parsing.
		return redaction.RedactProxyURL(input), true
	}
	return redaction.RedactURL(input), schemeLess
}

func redactEveryQueryValue(query string) string {
	if query == "" {
		return ""
	}
	parts := strings.FieldsFunc(query, func(r rune) bool { return r == '&' || r == ';' })
	for index, part := range parts {
		name, _, _ := strings.Cut(part, "=")
		parts[index] = name + "=" + redaction.Replacement
	}
	return strings.Join(parts, "&")
}

func (p Projection) host(input string) string {
	redacted := redaction.RedactText(input)
	if p.Mode() == ModeStrict && isInternalHost(strings.Trim(redacted, "[]")) {
		return redaction.Replacement
	}
	return redacted
}

func (p Projection) value(key, input string) string {
	result := redaction.RedactText(input)
	if p.Mode() != ModeStrict {
		return result
	}
	if strictIdentityKey(key) && strings.TrimSpace(result) != "" {
		return redaction.Replacement
	}
	result = urlPattern.ReplaceAllStringFunc(result, func(match string) string {
		value, suffix := splitTrailingPunctuation(match)
		return p.url(value) + suffix
	})
	result = localPathPattern.ReplaceAllString(result, "$1"+redaction.Replacement)
	result = lookupHostPattern.ReplaceAllString(result, "$1"+redaction.Replacement+"$3")
	result = endpointHostPattern.ReplaceAllString(result, "$1"+redaction.Replacement+"$3")
	result = ipv4Pattern.ReplaceAllStringFunc(result, func(candidate string) string {
		if isInternalHost(candidate) {
			return redaction.Replacement
		}
		return candidate
	})
	result = ipv6Pattern.ReplaceAllStringFunc(result, func(candidate string) string {
		trimmed := strings.Trim(candidate, "[](),;.")
		if zone := strings.LastIndexByte(trimmed, '%'); zone >= 0 {
			trimmed = trimmed[:zone]
		}
		if isInternalHost(trimmed) {
			return redaction.Replacement
		}
		return candidate
	})
	result = internalHostnamePattern.ReplaceAllString(result, redaction.Replacement)
	if networkKey(key) {
		trimmed := strings.TrimSpace(strings.Trim(result, "[]"))
		if isInternalHost(trimmed) {
			return redaction.Replacement
		}
	}
	if pathKey(key) && filepath.IsAbs(strings.TrimSpace(result)) {
		return redaction.Replacement
	}
	return result
}

func networkKey(key string) bool {
	normalized := strings.ToLower(key)
	return strings.Contains(normalized, "host") || strings.Contains(normalized, "address") ||
		strings.Contains(normalized, "remoteip") || strings.Contains(normalized, "localip") ||
		strings.Contains(normalized, "sans") || normalized == "sni" ||
		normalized == "ip" || normalized == "proxy"
}

func strictIdentityKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "sni", "dnssans", "ipsans", "subject", "issuer", "verificationerror":
		return true
	default:
		return false
	}
}

func pathKey(key string) bool {
	normalized := strings.ToLower(key)
	return strings.Contains(normalized, "path") || strings.Contains(normalized, "file") ||
		strings.Contains(normalized, "directory")
}

func isInternalHost(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		return address.IsPrivate() || address.IsLoopback() ||
			address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() ||
			address.IsInterfaceLocalMulticast() || address.IsMulticast() ||
			address.IsUnspecified() || sharedAddressPrefix.Contains(address)
	}
	if host == "localhost" || !strings.Contains(host, ".") {
		return true
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".lan", ".home", ".corp"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func splitTrailingPunctuation(value string) (string, string) {
	end := len(value)
	for end > 0 {
		switch value[end-1] {
		case '.', ',', '!', ')', ']', '}':
			end--
		default:
			return value[:end], value[end:]
		}
	}
	return value, ""
}

func utc(value time.Time) time.Time {
	if value.IsZero() {
		return value
	}
	return value.UTC()
}
