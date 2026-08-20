// Package dns performs address-family-aware name resolution behind injectable
// system and detailed resolver interfaces.
package dns

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

const (
	ErrorLookupFailed     = "DNS_LOOKUP_FAILED"
	ErrorNoRecords        = "DNS_NO_RECORDS"
	ErrorNXDOMAIN         = "DNS_NXDOMAIN"
	ErrorNoData           = "DNS_NODATA"
	ErrorSERVFAIL         = "DNS_SERVFAIL"
	ErrorTimeout          = "DNS_TIMEOUT"
	ErrorNotFoundUnknown  = "DNS_NOT_FOUND_UNKNOWN"
	ErrorPartialFailure   = "DNS_PARTIAL_FAILURE"
	ErrorDetailsFailed    = "DNS_DETAILS_FAILED"
	ErrorFamilyMismatch   = "DNS_FAMILY_MISMATCH"
	ErrorIPFamilyMismatch = "DNS_IP_LITERAL_FAMILY_MISMATCH"
	ErrorCancelled        = "DNS_CANCELLED"
)

const (
	directPathID = "path-direct"
	originHopID  = "hop-origin"
)

// Resolver is implemented by net.Resolver and deterministic test doubles.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// Check resolves A and AAAA records with the system resolver by default.
// DetailedResolver is consulted only when CollectDNSDetails is enabled.
type Check struct {
	Resolver         Resolver
	DetailedResolver DetailedResolver
	ResolverInfo     func() resolverInfo
	Now              func() time.Time
}

// New constructs a DNS check.
func New(resolver Resolver) *Check {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &Check{
		Resolver:     resolver,
		ResolverInfo: systemResolverInfo,
		Now:          time.Now,
	}
}

// ID returns the stable diagnostic identifier.
func (*Check) ID() string { return "dns" }

// Name returns the human-readable check name.
func (*Check) Name() string { return "DNS resolution" }

type lookupResult struct {
	family    string
	addresses []net.IP
	err       error
	duration  time.Duration
}

// Run resolves both address families so a requested-family absence can be
// distinguished from a hostname that exists only in the other family.
func (c *Check) Run(ctx context.Context, state *model.State) model.CheckResult {
	host := state.Target.Host
	if ip := net.ParseIP(host); ip != nil {
		return c.literalResult(state, ip)
	}

	lookups := c.lookupFamilies(ctx, host)
	info := resolverInfo{source: "system resolver"}
	if c.ResolverInfo != nil {
		info = c.ResolverInfo()
	}
	dnsResult := model.DNSResult{
		ResolverSource: info.source,
		SearchDomains:  append([]string(nil), info.searchDomains...),
	}

	families := make([]model.DNSFamilyResult, 0, 2)
	duplicates := make(map[string]int, 2)
	for _, family := range []string{"ip4", "ip6"} {
		lookup := lookups[family]
		addresses, removed := normalize(lookup.addresses, family)
		duplicates[family] = removed
		families = append(
			families,
			classifyFamilyLookup(family, addresses, lookup.err, lookup.duration),
		)
	}

	var detailResult DetailedResult
	var detailErr error
	if state.Options.CollectDNSDetails {
		resolver := detailedResolverFor(c)
		if resolver == nil {
			detailErr = errors.New("detailed resolver is unavailable on this platform")
		} else {
			detailResult, detailErr = lookupDetails(ctx, resolver, host)
			families = mergeDetailedFamilies(families, detailResult.Families)
			if detailResult.ResolverSource != "" {
				dnsResult.ResolverSource = detailResult.ResolverSource
			}
			if detailResult.SearchDomains != nil {
				dnsResult.SearchDomains = normalizedDomains(detailResult.SearchDomains)
			}
			dnsResult.CNAMEs = normalizeCNAMEs(detailResult.CNAMEs, 16)
			if detailResult.TTL > 0 {
				dnsResult.TTL = detailResult.TTL
			}
		}
	}

	applyResolvedFamilyMismatch(families, state.Options.IPVersion)
	dnsResult.Families = families
	populateLegacyDNSResult(&dnsResult)
	state.SetDNS(dnsResult)
	c.recordDNSPath(state, dnsResult)

	evidence := familyEvidence(
		families,
		duplicates,
		detailResult.ResponseCodes,
		state.Options.IPVersion,
		state.Options.AddressLimit,
	)
	evidence = append(
		evidence,
		resolverEvidence(dnsResult, state.Options.CollectDNSDetails, detailErr),
	)
	selection := SelectAddresses(dnsResult, state.Options)
	if selection.Skipped > 0 {
		evidence = append(evidence, skippedByLimitEvidence(selection, state.Options))
	}

	if ctx.Err() != nil {
		return model.CheckResult{
			ID:          c.ID(),
			Name:        c.Name(),
			Status:      model.StatusCancelled,
			Summary:     "DNS resolution was cancelled.",
			NetworkRefs: familyNetworkRefs(families),
			Evidence:    evidence,
			ErrorCode:   ErrorCancelled,
		}
	}
	status, code, summary := evaluateFamilyResults(
		families,
		state.Options.IPVersion,
		detailErr,
	)
	result := model.CheckResult{
		ID:          c.ID(),
		Name:        c.Name(),
		Status:      status,
		Summary:     summary,
		NetworkRefs: familyNetworkRefs(families),
		Evidence:    evidence,
		ErrorCode:   code,
	}
	switch status {
	case model.StatusFailed:
		result.Recommendations = []model.Recommendation{{
			ID:       recommendationID(code),
			Priority: "high",
			Message:  recommendation(code),
		}}
	case model.StatusWarning:
		result.Recommendations = []model.Recommendation{{
			ID:       "dns.investigate_partial",
			Priority: "medium",
			Message:  "Inspect the affected address family and resolver evidence before assigning a host-wide cause.",
		}}
	}
	return result
}

func lookupDetails(
	ctx context.Context,
	resolver DetailedResolver,
	host string,
) (result DetailedResult, err error) {
	defer func() {
		if recover() != nil {
			result = DetailedResult{}
			err = errors.New("detailed resolver adapter failed internally")
		}
	}()
	return resolver.LookupDetails(ctx, host)
}

func (c *Check) lookupFamilies(ctx context.Context, host string) map[string]lookupResult {
	const familyCount = 2
	results := make(chan lookupResult, familyCount)
	for _, family := range []string{"ip4", "ip6"} {
		family := family
		go func() {
			results <- c.lookupFamily(ctx, family, host)
		}()
	}
	byFamily := make(map[string]lookupResult, familyCount)
	for range familyCount {
		result := <-results
		byFamily[result.family] = result
	}
	return byFamily
}

func (c *Check) lookupFamily(
	ctx context.Context,
	family string,
	host string,
) (result lookupResult) {
	started := c.now()
	result.family = family
	defer func() {
		result.duration = c.now().Sub(started)
		if recover() != nil {
			result.addresses = nil
			result.err = errors.New("resolver adapter failed internally")
		}
	}()
	if c.Resolver == nil {
		result.err = errors.New("resolver adapter is unavailable")
		return result
	}
	result.addresses, result.err = c.Resolver.LookupIP(ctx, family, host)
	return result
}

func classifyFamilyLookup(
	family string,
	addresses []net.IP,
	err error,
	duration time.Duration,
) model.DNSFamilyResult {
	record := recordType(family)
	result := model.DNSFamilyResult{
		NetworkRef: networkRef(dnsAttemptID(record)),
		Family:     displayFamily(family),
		RecordType: record,
		Addresses:  cloneIPs(addresses),
		Duration:   duration,
	}
	if len(addresses) > 0 {
		result.Status = model.DNSFamilyStatusSuccess
		if err != nil {
			result.ErrorCode = ErrorPartialFailure
			result.Error = boundedErrorText(err)
		}
		return result
	}
	if err == nil {
		result.Status = model.DNSFamilyStatusNoData
		result.ErrorCode = ErrorNoData
		return result
	}
	result.Error = boundedErrorText(err)
	result.Status, result.ErrorCode = classifyResolverError(err)
	return result
}

func classifyResolverError(err error) (model.DNSFamilyStatus, string) {
	switch {
	case errors.Is(err, context.Canceled):
		return model.DNSFamilyStatusCancelled, ErrorCancelled
	case errors.Is(err, context.DeadlineExceeded):
		return model.DNSFamilyStatusTimeout, ErrorTimeout
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsTimeout:
			return model.DNSFamilyStatusTimeout, ErrorTimeout
		case dnsErr.IsNotFound:
			// net.Resolver maps both NXDOMAIN and successful empty answers to
			// IsNotFound. Only structured detailed evidence can refine it.
			return model.DNSFamilyStatusNotFoundUnknown, ErrorNotFoundUnknown
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return model.DNSFamilyStatusTimeout, ErrorTimeout
	}
	return model.DNSFamilyStatusError, ErrorLookupFailed
}

func normalize(addresses []net.IP, family string) ([]net.IP, int) {
	seen := make(map[string]struct{})
	var result []net.IP
	duplicates := 0
	for _, address := range addresses {
		address = canonicalIP(address)
		if address == nil || (family == "ip4" && address.To4() == nil) ||
			(family == "ip6" && address.To4() != nil) {
			continue
		}
		key := address.String()
		if _, duplicate := seen[key]; duplicate {
			duplicates++
			continue
		}
		seen[key] = struct{}{}
		result = append(result, address)
	}
	sort.SliceStable(result, func(left, right int) bool {
		return bytesCompare(result[left], result[right]) < 0
	})
	return result, duplicates
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
	for index := 0; index < len(left) && index < len(right); index++ {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
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
