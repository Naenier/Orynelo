// Package redaction removes credentials and other sensitive values before
// diagnostic data is logged, displayed, or persisted.
package redaction

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Replacement is the stable marker used for every removed value.
const Replacement = "[REDACTED]"

var (
	sensitiveQueryNames = map[string]struct{}{
		"token":             {},
		"accesstoken":       {},
		"refreshtoken":      {},
		"idtoken":           {},
		"sessiontoken":      {},
		"apikey":            {},
		"key":               {},
		"secret":            {},
		"clientsecret":      {},
		"secretkey":         {},
		"privatekey":        {},
		"password":          {},
		"passwd":            {},
		"signature":         {},
		"sig":               {},
		"auth":              {},
		"credential":        {},
		"credentials":       {},
		"code":              {},
		"authorizationcode": {},
		"authcode":          {},
		"oauthcode":         {},
		"codeverifier":      {},
		"jwt":               {},
		"session":           {},
		"sessionid":         {},
		"jsessionid":        {},
		"phpsessid":         {},
		"sid":               {},
		"assertion":         {},
		"samlassertion":     {},
		"ticket":            {},
	}
	sensitiveHeaderNames = map[string]struct{}{
		"authorization":      {},
		"proxyauthorization": {},
		"cookie":             {},
		"setcookie":          {},
		"xapikey":            {},
		"xauthtoken":         {},
		"xaccesstoken":       {},
	}
	urlPattern    = regexp.MustCompile(`(?i)\b(?:https?|socks(?:4a?|5h?)?|ftp)://[^\s"'<>]+`)
	headerPattern = regexp.MustCompile(
		`(?im)\b(authorization|proxy-authorization|cookie|set-cookie)\s*[:=][^\r\n]*`,
	)
	queryAssignmentPattern = regexp.MustCompile(
		`(?i)(^|[?&;\s])([a-z0-9_.\-\[\]]+)=([^&;\s#]+)`,
	)
)

// IsSensitiveQueryKey reports whether a query parameter name is expected to
// carry a credential or secret.
func IsSensitiveQueryKey(name string) bool {
	normalized := normalizeName(name)
	if _, ok := sensitiveQueryNames[normalized]; ok {
		return true
	}
	for _, suffix := range []string{
		"token",
		"secret",
		"password",
		"passwd",
		"credential",
		"credentials",
		"signature",
		"apikey",
	} {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}

// IsSensitiveHeader reports whether a complete header value must be removed.
func IsSensitiveHeader(name string) bool {
	normalized := normalizeName(name)
	if _, ok := sensitiveHeaderNames[normalized]; ok {
		return true
	}
	if !strings.HasPrefix(normalized, "x") {
		return false
	}
	extension := strings.TrimPrefix(normalized, "x")
	return IsSensitiveQueryKey(extension) ||
		strings.HasPrefix(extension, "secret") ||
		strings.HasPrefix(extension, "credential")
}

func normalizeName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	return strings.Map(func(r rune) rune {
		switch r {
		case '-', '_', '.', '[', ']', ' ', '\t':
			return -1
		default:
			return r
		}
	}, name)
}

// RedactURL removes all userinfo and sensitive query values from a URL. If the
// input is malformed, a conservative best-effort redaction is still applied.
func RedactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return redactMalformedURL(raw)
	}
	return RedactParsedURL(parsed).String()
}

// RedactProxyURL is an explicit alias for call sites handling proxy settings.
func RedactProxyURL(raw string) string {
	result := RedactURL(raw)
	if !strings.Contains(result, "://") {
		result = removeAuthorityUserinfo(result)
	}
	return result
}

// RedactParsedURL returns a copy; it never mutates the caller's URL.
func RedactParsedURL(input *url.URL) *url.URL {
	if input == nil {
		return nil
	}
	result := *input
	result.User = nil
	result.RawQuery = redactRawQuery(input.RawQuery)
	if isNetworkScheme(result.Scheme) && result.Opaque != "" {
		result.Opaque = removeAuthorityUserinfo(result.Opaque)
	}
	if strings.Contains(result.Fragment, "=") {
		result.Fragment = redactQueryLikeText(result.Fragment)
	}
	return &result
}

func isNetworkScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "http", "https", "ftp", "socks", "socks4", "socks4a", "socks5", "socks5h":
		return true
	default:
		return false
	}
}

// RedactQuery returns a deep copy of query values.
func RedactQuery(input url.Values) url.Values {
	if input == nil {
		return nil
	}
	result := make(url.Values, len(input))
	for name, values := range input {
		if IsSensitiveQueryKey(name) {
			result[name] = []string{Replacement}
			continue
		}
		result[name] = append([]string(nil), values...)
	}
	return result
}

func redactRawQuery(query string) string {
	if query == "" {
		return ""
	}
	var result strings.Builder
	start := 0
	for index := 0; index <= len(query); index++ {
		if index < len(query) && query[index] != '&' && query[index] != ';' {
			continue
		}
		result.WriteString(redactQueryPart(query[start:index]))
		if index < len(query) {
			result.WriteByte(query[index])
		}
		start = index + 1
	}
	return result.String()
}

func redactQueryPart(part string) string {
	name, _, found := strings.Cut(part, "=")
	decodedName, err := url.QueryUnescape(name)
	if err != nil {
		decodedName = name
	}
	if !IsSensitiveQueryKey(decodedName) {
		return part
	}
	if !found {
		return name + "=" + Replacement
	}
	return name + "=" + Replacement
}

func redactMalformedURL(raw string) string {
	result := removeLooseUserinfo(raw)
	queryStart := strings.IndexByte(result, '?')
	if queryStart < 0 {
		return redactQueryLikeText(result)
	}
	fragmentStart := strings.IndexByte(result[queryStart+1:], '#')
	if fragmentStart < 0 {
		return result[:queryStart+1] + redactRawQuery(result[queryStart+1:])
	}
	fragmentStart += queryStart + 1
	return result[:queryStart+1] +
		redactRawQuery(result[queryStart+1:fragmentStart]) +
		result[fragmentStart:]
}

func removeLooseUserinfo(raw string) string {
	scheme := strings.Index(raw, "://")
	if scheme < 0 {
		return raw
	}
	authorityStart := scheme + 3
	authorityEnd := len(raw)
	if relativeEnd := strings.IndexAny(raw[authorityStart:], "/?#"); relativeEnd >= 0 {
		authorityEnd = authorityStart + relativeEnd
	}
	at := strings.LastIndex(raw[authorityStart:authorityEnd], "@")
	if at < 0 {
		return raw
	}
	at += authorityStart
	return raw[:authorityStart] + raw[at+1:]
}

func removeAuthorityUserinfo(raw string) string {
	authorityEnd := len(raw)
	if end := strings.IndexAny(raw, "/?#"); end >= 0 {
		authorityEnd = end
	}
	at := strings.LastIndex(raw[:authorityEnd], "@")
	if at < 0 {
		return raw
	}
	return raw[at+1:]
}

// RedactHeaders returns a deep copy of HTTP headers. Credential-bearing
// headers are replaced completely; URLs embedded in other headers are scrubbed
// as well.
func RedactHeaders(input http.Header) http.Header {
	if input == nil {
		return nil
	}
	result := make(http.Header, len(input))
	for name, values := range input {
		if IsSensitiveHeader(name) {
			result[name] = []string{Replacement}
			continue
		}
		result[name] = make([]string, len(values))
		for index, value := range values {
			result[name][index] = RedactText(value)
		}
	}
	return result
}

// RedactMap returns a copy of string fields suitable for structured technical
// details.
func RedactMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	result := make(map[string]string, len(input))
	for name, value := range input {
		if IsSensitiveHeader(name) || IsSensitiveQueryKey(name) {
			result[name] = Replacement
		} else {
			result[name] = RedactText(value)
		}
	}
	return result
}

// RedactText scrubs common header, URL, proxy, and query representations from
// otherwise unstructured text.
func RedactText(input string) string {
	result := headerPattern.ReplaceAllString(input, "$1: "+Replacement)
	result = urlPattern.ReplaceAllStringFunc(result, func(match string) string {
		urlText, suffix := splitTrailingPunctuation(match)
		return RedactURL(urlText) + suffix
	})
	return redactQueryLikeText(result)
}

func redactQueryLikeText(input string) string {
	return queryAssignmentPattern.ReplaceAllStringFunc(input, func(match string) string {
		parts := queryAssignmentPattern.FindStringSubmatch(match)
		if len(parts) != 4 || !IsSensitiveQueryKey(parts[2]) {
			return match
		}
		return parts[1] + parts[2] + "=" + Replacement
	})
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

// Handler is a slog.Handler decorator that applies redaction to messages and
// structured attributes before forwarding records.
type Handler struct {
	next slog.Handler
}

// NewHandler wraps a slog handler with mandatory redaction.
func NewHandler(next slog.Handler) *Handler {
	if next == nil {
		next = slog.DiscardHandler
	}
	return &Handler{next: next}
}

// Enabled implements slog.Handler.
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

// Handle implements slog.Handler.
func (h *Handler) Handle(ctx context.Context, record slog.Record) error {
	scrubbed := slog.NewRecord(record.Time, record.Level, RedactText(record.Message), record.PC)
	record.Attrs(func(attr slog.Attr) bool {
		scrubbed.AddAttrs(redactAttr(attr))
		return true
	})
	return h.next.Handle(ctx, scrubbed)
}

// WithAttrs implements slog.Handler.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	scrubbed := make([]slog.Attr, len(attrs))
	for index, attr := range attrs {
		scrubbed[index] = redactAttr(attr)
	}
	return &Handler{next: h.next.WithAttrs(scrubbed)}
}

// WithGroup implements slog.Handler.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{next: h.next.WithGroup(name)}
}

func redactAttr(attr slog.Attr) slog.Attr {
	attr.Value = attr.Value.Resolve()
	if IsSensitiveHeader(attr.Key) || IsSensitiveQueryKey(attr.Key) {
		return slog.String(attr.Key, Replacement)
	}

	switch attr.Value.Kind() {
	case slog.KindString:
		return slog.String(attr.Key, RedactText(attr.Value.String()))
	case slog.KindGroup:
		group := attr.Value.Group()
		scrubbed := make([]slog.Attr, len(group))
		for index, child := range group {
			scrubbed[index] = redactAttr(child)
		}
		return slog.Group(attr.Key, attrsToAny(scrubbed)...)
	case slog.KindAny:
		return redactAnyAttr(attr)
	default:
		return attr
	}
}

func attrsToAny(attrs []slog.Attr) []any {
	result := make([]any, len(attrs))
	for index := range attrs {
		result[index] = attrs[index]
	}
	return result
}

func redactAnyAttr(attr slog.Attr) slog.Attr {
	switch value := attr.Value.Any().(type) {
	case http.Header:
		return slog.Any(attr.Key, RedactHeaders(value))
	case url.Values:
		return slog.Any(attr.Key, RedactQuery(value))
	case *url.URL:
		return slog.Any(attr.Key, RedactParsedURL(value))
	case url.URL:
		return slog.Any(attr.Key, RedactParsedURL(&value))
	case map[string]string:
		return slog.Any(attr.Key, RedactMap(value))
	case map[string]any:
		return slog.Any(attr.Key, redactAnyMap(value, 0))
	case []string:
		scrubbed := make([]string, len(value))
		for index := range value {
			scrubbed[index] = RedactText(value[index])
		}
		return slog.Any(attr.Key, scrubbed)
	case []any:
		scrubbed := make([]any, len(value))
		for index := range value {
			scrubbed[index] = redactAnyValue("", value[index], 0)
		}
		return slog.Any(attr.Key, scrubbed)
	case error:
		return slog.String(attr.Key, RedactText(value.Error()))
	case fmt.Stringer:
		return slog.String(attr.Key, RedactText(value.String()))
	default:
		return attr
	}
}

func redactAnyMap(input map[string]any, depth int) map[string]any {
	if depth >= 8 {
		return map[string]any{"value": Replacement}
	}
	result := make(map[string]any, len(input))
	for key, value := range input {
		result[key] = redactAnyValue(key, value, depth+1)
	}
	return result
}

func redactAnyValue(key string, input any, depth int) any {
	if IsSensitiveHeader(key) || IsSensitiveQueryKey(key) {
		return Replacement
	}
	if depth >= 8 {
		return Replacement
	}
	switch value := input.(type) {
	case string:
		return RedactText(value)
	case error:
		return RedactText(value.Error())
	case http.Header:
		return RedactHeaders(value)
	case url.Values:
		return RedactQuery(value)
	case *url.URL:
		return RedactParsedURL(value)
	case url.URL:
		return RedactParsedURL(&value)
	case map[string]string:
		return RedactMap(value)
	case map[string]any:
		return redactAnyMap(value, depth+1)
	case []string:
		result := make([]string, len(value))
		for index := range value {
			result[index] = RedactText(value[index])
		}
		return result
	case []any:
		result := make([]any, len(value))
		for index := range value {
			result[index] = redactAnyValue("", value[index], depth+1)
		}
		return result
	default:
		return input
	}
}
