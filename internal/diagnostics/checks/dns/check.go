// Package dns performs address-family-aware name resolution behind an
// injectable resolver interface.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

const (
	ErrorLookupFailed     = "DNS_LOOKUP_FAILED"
	ErrorNoRecords        = "DNS_NO_RECORDS"
	ErrorIPFamilyMismatch = "DNS_IP_LITERAL_FAMILY_MISMATCH"
	ErrorCancelled        = "DNS_CANCELLED"
)

// Resolver is implemented by net.Resolver and test doubles.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// Check resolves A and AAAA records with a system resolver by default.
type Check struct {
	Resolver Resolver
	Now      func() time.Time
}

// New constructs a DNS check.
func New(resolver Resolver) *Check {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &Check{Resolver: resolver, Now: time.Now}
}

// ID returns the stable diagnostic identifier.
func (*Check) ID() string   { return "dns" }
// Name returns the human-readable check name.
func (*Check) Name() string { return "DNS resolution" }

type lookupResult struct {
	family    string
	addresses []net.IP
	err       error
	duration  time.Duration
}

// Run resolves the target's A and AAAA records.
func (c *Check) Run(ctx context.Context, state *model.State) model.CheckResult {
	host := state.Target.Host
	if ip := net.ParseIP(host); ip != nil {
		result := model.DNSResult{}
		if ip.To4() != nil {
			if state.Options.IPVersion == model.IPVersion6 {
				return ipFamilyMismatchResult(
					c,
					ip,
					state.Options.IPVersion,
					"The target is IPv4 but IPv6-only mode was requested.",
				)
			}
			result.IPv4 = []net.IP{canonicalIP(ip)}
		} else {
			if state.Options.IPVersion == model.IPVersion4 {
				return ipFamilyMismatchResult(
					c,
					ip,
					state.Options.IPVersion,
					"The target is IPv6 but IPv4-only mode was requested.",
				)
			}
			result.IPv6 = []net.IP{canonicalIP(ip)}
		}
		state.SetDNS(result)
		return model.CheckResult{
			ID:      c.ID(),
			Name:    c.Name(),
			Status:  model.StatusPassed,
			Summary: "The target is an IP literal; DNS lookup is not required.",
			Evidence: []model.Evidence{{
				ID:      "dns.literal",
				Code:    "DNS_IP_LITERAL",
				Message: "The target contains a canonical IP address.",
				Details: map[string]string{"address": ip.String()},
			}},
		}
	}

	families := requestedFamilies(state.Options.IPVersion)
	results := make(chan lookupResult, len(families))
	for _, family := range families {
		family := family
		go func() {
			started := c.now()
			addresses, err := c.Resolver.LookupIP(ctx, family, host)
			results <- lookupResult{
				family:    family,
				addresses: addresses,
				err:       err,
				duration:  c.now().Sub(started),
			}
		}()
	}

	byFamily := make(map[string]lookupResult, len(families))
	for range families {
		result := <-results
		byFamily[result.family] = result
	}

	dnsResult := model.DNSResult{}
	var evidence []model.Evidence
	for _, family := range families {
		result := byFamily[family]
		addresses, duplicates := normalize(result.addresses, family)
		if family == "ip4" {
			dnsResult.IPv4 = addresses
			dnsResult.ADuration = result.duration
			if result.err != nil {
				dnsResult.AError = result.err.Error()
			}
		} else {
			dnsResult.IPv6 = addresses
			dnsResult.AAAADuration = result.duration
			if result.err != nil {
				dnsResult.AAAAError = result.err.Error()
			}
		}
		recordType := map[string]string{"ip4": "A", "ip6": "AAAA"}[family]
		details := map[string]string{
			"recordType": recordType,
			"addresses":  joinIPs(addresses),
			"duration":   result.duration.String(),
		}
		if duplicates > 0 {
			details["duplicatesRemoved"] = fmt.Sprintf("%d", duplicates)
		}
		if result.err != nil {
			details["error"] = result.err.Error()
		}
		evidence = append(evidence, model.Evidence{
			ID:      "dns." + strings.ToLower(recordType),
			Code:    "DNS_" + recordType + "_RESULT",
			Message: fmt.Sprintf("%s lookup returned %d unique address(es).", recordType, len(addresses)),
			Details: details,
		})
	}
	state.SetDNS(dnsResult)

	if ctx.Err() != nil {
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusCancelled,
			Summary:   "DNS resolution was cancelled.",
			Evidence:  evidence,
			ErrorCode: ErrorCancelled,
		}
	}

	has4, has6 := len(dnsResult.IPv4) > 0, len(dnsResult.IPv6) > 0
	requiredFound := (state.Options.IPVersion == model.IPVersionAuto && (has4 || has6)) ||
		(state.Options.IPVersion == model.IPVersion4 && has4) ||
		(state.Options.IPVersion == model.IPVersion6 && has6)
	if !requiredFound {
		code := ErrorNoRecords
		summary := "DNS returned no usable addresses for the requested IP mode."
		if dnsResult.AError != "" || dnsResult.AAAAError != "" {
			code = ErrorLookupFailed
			summary = "DNS resolution failed for the requested IP mode."
		}
		return model.CheckResult{
			ID:        c.ID(),
			Name:      c.Name(),
			Status:    model.StatusFailed,
			Summary:   summary,
			Evidence:  evidence,
			ErrorCode: code,
			Recommendations: []model.Recommendation{{
				ID:       "dns.verify_name",
				Priority: "high",
				Message:  "Verify the hostname, resolver configuration, and expected DNS records.",
			}},
		}
	}

	summary := fmt.Sprintf("Resolved %d IPv4 and %d IPv6 address(es).", len(dnsResult.IPv4), len(dnsResult.IPv6))
	return model.CheckResult{
		ID:       c.ID(),
		Name:     c.Name(),
		Status:   model.StatusPassed,
		Summary:  summary,
		Evidence: evidence,
	}
}

func noRecordsResult(c *Check, summary string) model.CheckResult {
	return model.CheckResult{
		ID:        c.ID(),
		Name:      c.Name(),
		Status:    model.StatusFailed,
		Summary:   summary,
		ErrorCode: ErrorNoRecords,
	}
}

func ipFamilyMismatchResult(
	c *Check,
	literal net.IP,
	requested model.IPVersion,
	summary string,
) model.CheckResult {
	return model.CheckResult{
		ID:        c.ID(),
		Name:      c.Name(),
		Status:    model.StatusFailed,
		Summary:   summary,
		ErrorCode: ErrorIPFamilyMismatch,
		Evidence: []model.Evidence{{
			ID:      "dns.literal_family_mismatch",
			Code:    ErrorIPFamilyMismatch,
			Message: "The literal address family does not match the requested IP mode.",
			Details: map[string]string{
				"address":       literal.String(),
				"addressFamily": literalFamily(literal),
				"requestedMode": string(requested),
			},
		}},
		Recommendations: []model.Recommendation{{
			ID:       "dns.select_literal_family",
			Priority: "high",
			Message:  "Select an IP family that matches the literal target address.",
		}},
	}
}

func literalFamily(ip net.IP) string {
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

func requestedFamilies(version model.IPVersion) []string {
	switch version {
	case model.IPVersion4:
		return []string{"ip4"}
	case model.IPVersion6:
		return []string{"ip6"}
	default:
		return []string{"ip4", "ip6"}
	}
}

func normalize(addresses []net.IP, family string) ([]net.IP, int) {
	seen := make(map[string]struct{})
	var out []net.IP
	duplicates := 0
	for _, address := range addresses {
		address = canonicalIP(address)
		if address == nil || (family == "ip4" && address.To4() == nil) ||
			(family == "ip6" && address.To4() != nil) {
			continue
		}
		key := address.String()
		if _, ok := seen[key]; ok {
			duplicates++
			continue
		}
		seen[key] = struct{}{}
		out = append(out, address)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return bytesCompare(out[i], out[j]) < 0
	})
	return out, duplicates
}

func canonicalIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return append(net.IP(nil), v4...)
	}
	if v6 := ip.To16(); v6 != nil {
		return append(net.IP(nil), v6...)
	}
	return nil
}

func bytesCompare(left, right net.IP) int {
	for i := 0; i < len(left) && i < len(right); i++ {
		if left[i] < right[i] {
			return -1
		}
		if left[i] > right[i] {
			return 1
		}
	}
	return len(left) - len(right)
}

func joinIPs(addresses []net.IP) string {
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, address.String())
	}
	return strings.Join(values, ", ")
}

func (c *Check) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// IsLookupFailure helps tests and callers classify wrapped resolver failures.
func IsLookupFailure(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}
