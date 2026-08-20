package dns

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

// DetailedResult carries optional wire-level or platform resolver enrichment.
// Families may refine an ambiguous system lookup classification, while
// addresses from the system Resolver remain authoritative for connection
// selection.
type DetailedResult struct {
	Families       []model.DNSFamilyResult
	ResponseCodes  map[string]string
	CNAMEs         []string
	TTL            time.Duration
	ResolverSource string
	SearchDomains  []string
}

// DetailedResolver optionally supplies response codes, CNAMEs, TTLs, and
// resolver provenance that net.Resolver does not expose portably.
type DetailedResolver interface {
	LookupDetails(ctx context.Context, host string) (DetailedResult, error)
}

type cnameResolver interface {
	LookupCNAME(context.Context, string) (string, error)
}

// systemDetailedResolver is an honest best-effort adapter: the platform API
// can expose a canonical name, but not authoritative TTL or DNS response code.
type systemDetailedResolver struct {
	resolver cnameResolver
}

func (resolver systemDetailedResolver) LookupDetails(
	ctx context.Context,
	host string,
) (DetailedResult, error) {
	info := systemResolverInfo()
	result := DetailedResult{
		ResolverSource: info.source,
		SearchDomains:  append([]string(nil), info.searchDomains...),
	}
	canonical, err := resolver.resolver.LookupCNAME(ctx, host)
	if err != nil {
		return result, err
	}
	canonical = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(canonical)), ".")
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if canonical != "" && canonical != host {
		result.CNAMEs = []string{canonical}
	}
	return result, nil
}

func detailedResolverFor(check *Check) DetailedResolver {
	if check.DetailedResolver != nil {
		return check.DetailedResolver
	}
	if resolver, ok := check.Resolver.(*net.Resolver); ok && resolver == net.DefaultResolver {
		if wire, err := newSystemWireDetailedResolver(); err == nil {
			return wire
		}
	}
	if resolver, ok := check.Resolver.(cnameResolver); ok {
		return systemDetailedResolver{resolver: resolver}
	}
	return nil
}
