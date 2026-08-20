package dns

import (
	"bufio"
	"io"
	"net/netip"
	"os"
	"strings"
)

const resolverConfigurationPath = "/etc/resolv.conf"

const maximumResolverServers = 3

type resolverConfiguration struct {
	servers       []string
	searchDomains []string
}

// resolverInfo describes only configuration that can be observed without
// claiming which server a platform resolver ultimately contacted.
type resolverInfo struct {
	source        string
	searchDomains []string
}

func systemResolverInfo() resolverInfo {
	info := resolverInfo{source: "system resolver"}
	configuration, err := readResolverConfiguration(resolverConfigurationPath)
	if err != nil {
		return info
	}
	info.source = "system resolver configuration: " + resolverConfigurationPath
	info.searchDomains = configuration.searchDomains
	return info
}

func parseResolverSearchDomains(reader io.Reader) ([]string, bool) {
	configuration, ok := parseResolverConfiguration(reader)
	return configuration.searchDomains, ok
}

func readResolverConfiguration(path string) (resolverConfiguration, error) {
	file, err := os.Open(path)
	if err != nil {
		return resolverConfiguration{}, err
	}
	defer file.Close()
	configuration, ok := parseResolverConfiguration(io.LimitReader(file, 64<<10))
	if !ok {
		return resolverConfiguration{}, io.ErrUnexpectedEOF
	}
	return configuration, nil
}

func parseResolverConfiguration(reader io.Reader) (resolverConfiguration, bool) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024), 64<<10)
	var domain []string
	var search []string
	var servers []string
	seenServers := make(map[string]struct{})
	for scanner.Scan() {
		line := scanner.Text()
		if index := strings.IndexAny(line, "#;"); index >= 0 {
			line = line[:index]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "domain":
			domain = normalizedDomains(fields[1:2])
		case "search":
			search = normalizedDomains(fields[1:])
		case "nameserver":
			if len(servers) == maximumResolverServers {
				continue
			}
			address, err := netip.ParseAddr(strings.Trim(fields[1], "[]"))
			if err != nil {
				continue
			}
			value := address.String()
			if _, duplicate := seenServers[value]; duplicate {
				continue
			}
			seenServers[value] = struct{}{}
			servers = append(servers, value)
		}
	}
	if scanner.Err() != nil {
		return resolverConfiguration{}, false
	}
	if len(search) > 0 {
		domain = search
	}
	return resolverConfiguration{
		servers:       servers,
		searchDomains: domain,
	}, true
}

func normalizedDomains(values []string) []string {
	const maximumSearchDomains = 16
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
		if value == "" || len(value) > 253 || containsControl(value) {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
		if len(result) == maximumSearchDomains {
			break
		}
	}
	return result
}
