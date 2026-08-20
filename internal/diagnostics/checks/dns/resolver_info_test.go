package dns

import (
	"strings"
	"testing"
)

func TestParseResolverSearchDomains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "search overrides domain",
			content: "domain fallback.example\nsearch Corp.Example. svc.example corp.example # comment\n",
			want:    "corp.example,svc.example",
		},
		{
			name:    "domain fallback",
			content: "domain branch.example.\n",
			want:    "branch.example",
		},
		{
			name:    "no search configuration",
			content: "nameserver 192.0.2.53\n",
			want:    "",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseResolverSearchDomains(strings.NewReader(test.content))
			if !ok {
				t.Fatal("parseResolverSearchDomains() reported an unexpected read failure")
			}
			if strings.Join(got, ",") != test.want {
				t.Fatalf("search domains = %q, want %q", strings.Join(got, ","), test.want)
			}
		})
	}
}

func TestParseResolverConfigurationBoundsAndValidatesNameservers(t *testing.T) {
	t.Parallel()

	configuration, ok := parseResolverConfiguration(strings.NewReader(`
nameserver 192.0.2.53
nameserver invalid.example
nameserver 2001:db8::53
nameserver 192.0.2.53
nameserver 198.51.100.53
nameserver 203.0.113.53
search One.Example. two.example one.example
`))
	if !ok {
		t.Fatal("parseResolverConfiguration() reported a read failure")
	}
	if got := strings.Join(configuration.servers, ","); got != "192.0.2.53,2001:db8::53,198.51.100.53" {
		t.Fatalf("nameservers = %q", got)
	}
	if got := strings.Join(configuration.searchDomains, ","); got != "one.example,two.example" {
		t.Fatalf("search domains = %q", got)
	}
}
