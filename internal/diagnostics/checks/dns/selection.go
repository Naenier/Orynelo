package dns

import (
	"net"
	"net/netip"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

// AddressSelection is the bounded, deterministic backend set consumed by
// route, TCP, and TLS checks. Total counts usable addresses before the bound.
type AddressSelection struct {
	Addresses []net.IP
	Total     int
	Skipped   int
}

// SelectAddresses applies the effective IP-family and address-limit policy to
// canonical DNS output. An explicit connect IP replaces resolver candidates
// without changing the logical target identity used by TLS and HTTP.
func SelectAddresses(result model.DNSResult, options model.DiagnoseOptions) AddressSelection {
	if connectIP := optionConnectIP(options.ConnectIP); connectIP != nil {
		if matchesRequestedFamily(connectIP, options.IPVersion) {
			return AddressSelection{Addresses: []net.IP{connectIP}, Total: 1}
		}
		return AddressSelection{}
	}

	var candidates []net.IP
	switch options.IPVersion {
	case model.IPVersion4:
		candidates = appendCanonicalUnique(candidates, result.IPv4...)
	case model.IPVersion6:
		candidates = appendCanonicalUnique(candidates, result.IPv6...)
	default:
		// Preserve the established A-before-AAAA evidence order. The TCP check
		// owns connection racing and records which candidate was selected.
		candidates = appendCanonicalUnique(candidates, result.IPv4...)
		candidates = appendCanonicalUnique(candidates, result.IPv6...)
	}

	selection := AddressSelection{Total: len(candidates)}
	limit := options.AddressLimit
	if limit <= 0 {
		limit = model.DefaultDiagnoseOptions("").AddressLimit
	}
	if options.ProbeMode == model.ProbeModeClientEffective && limit > 2 {
		limit = 2
	}
	if len(candidates) > limit {
		selection.Skipped = len(candidates) - limit
		candidates = candidates[:limit]
	}
	selection.Addresses = cloneIPs(candidates)
	return selection
}

func optionConnectIP(value string) net.IP {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return nil
	}
	return canonicalIP(net.IP(address.Unmap().AsSlice()))
}

func appendCanonicalUnique(destination []net.IP, values ...net.IP) []net.IP {
	seen := make(map[string]struct{}, len(destination)+len(values))
	for _, value := range destination {
		seen[value.String()] = struct{}{}
	}
	for _, value := range values {
		value = canonicalIP(value)
		if value == nil {
			continue
		}
		key := value.String()
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		destination = append(destination, value)
	}
	return destination
}

func matchesRequestedFamily(address net.IP, version model.IPVersion) bool {
	switch version {
	case model.IPVersion4:
		return address.To4() != nil
	case model.IPVersion6:
		return address.To4() == nil && address.To16() != nil
	default:
		return address.To16() != nil
	}
}

func cloneIPs(values []net.IP) []net.IP {
	result := make([]net.IP, len(values))
	for index, value := range values {
		result[index] = append(net.IP(nil), value...)
	}
	return result
}
