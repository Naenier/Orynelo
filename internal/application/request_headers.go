package application

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/net/http/httpguts"
)

const (
	maxTransientHeaders     = 16
	maxTransientHeaderBytes = 8 << 10
)

var forbiddenTransientHeaders = map[string]struct{}{
	"connection":          {},
	"content-length":      {},
	"host":                {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"proxy-connection":    {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

// ParseTransientHeaders parses one-time Name: value lines. Values are
// returned only in runtime memory; callers must never log or persist the map.
func ParseTransientHeaders(lines []string) (map[string]string, []string, error) {
	if len(lines) > maxTransientHeaders {
		return nil, nil, fmt.Errorf("at most %d one-time request headers are allowed", maxTransientHeaders)
	}
	headers := make(map[string]string, len(lines))
	total := 0
	for index, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.ContainsAny(line, "\r\n") {
			return nil, nil, fmt.Errorf("one-time request header %d contains a line break", index+1)
		}
		name, value, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if !ok || !httpguts.ValidHeaderFieldName(name) {
			return nil, nil, fmt.Errorf("one-time request header %d has an invalid name", index+1)
		}
		canonical := strings.ToLower(name)
		if _, forbidden := forbiddenTransientHeaders[canonical]; forbidden {
			return nil, nil, fmt.Errorf("one-time request header %q is controlled by Orynelo", name)
		}
		if !httpguts.ValidHeaderFieldValue(value) {
			return nil, nil, fmt.Errorf("one-time request header %q has an invalid value", name)
		}
		total += len(name) + len(value)
		if total > maxTransientHeaderBytes {
			return nil, nil, fmt.Errorf("one-time request headers exceed the %d byte limit", maxTransientHeaderBytes)
		}
		if _, duplicate := headers[canonical]; duplicate {
			return nil, nil, fmt.Errorf("one-time request header %q is duplicated", name)
		}
		headers[canonical] = value
	}
	if len(headers) == 0 {
		return nil, nil, nil
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	return headers, names, nil
}

func validateTransientHeaders(headers map[string]string) (map[string]string, []string, error) {
	if len(headers) == 0 {
		return nil, nil, nil
	}
	lines := make([]string, 0, len(headers))
	for name, value := range headers {
		lines = append(lines, name+": "+value)
	}
	sort.Strings(lines)
	return ParseTransientHeaders(lines)
}
