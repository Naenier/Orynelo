package dns

import (
	"net"
	"testing"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

func TestSelectAddressesAppliesFamilyLimitAndConnectOverride(t *testing.T) {
	t.Parallel()

	result := model.DNSResult{
		IPv4: []net.IP{
			net.ParseIP("192.0.2.1"),
			net.ParseIP("192.0.2.2"),
		},
		IPv6: []net.IP{net.ParseIP("2001:db8::1")},
	}
	options := model.DefaultDiagnoseOptions("example.test")
	options.AddressLimit = 2
	options.ProbeMode = model.ProbeModeAddressMatrix
	selection := SelectAddresses(result, options)
	if joinIPs(selection.Addresses) != "192.0.2.1, 192.0.2.2" ||
		selection.Total != 3 || selection.Skipped != 1 {
		t.Fatalf("selection = %#v", selection)
	}

	options.ProbeMode = model.ProbeModeClientEffective
	options.AddressLimit = 4
	selection = SelectAddresses(result, options)
	if len(selection.Addresses) != 2 || selection.Skipped != 1 {
		t.Fatalf("client-effective selection = %#v", selection)
	}

	options.IPVersion = model.IPVersion6
	selection = SelectAddresses(result, options)
	if joinIPs(selection.Addresses) != "2001:db8::1" || selection.Skipped != 0 {
		t.Fatalf("IPv6 selection = %#v", selection)
	}

	options.ConnectIP = "192.0.2.99"
	options.IPVersion = model.IPVersionAuto
	selection = SelectAddresses(result, options)
	if joinIPs(selection.Addresses) != "192.0.2.99" || selection.Total != 1 {
		t.Fatalf("connect-IP selection = %#v", selection)
	}

	options.ConnectIP = "fe80::1%eth0"
	options.IPVersion = model.IPVersion6
	selection = SelectAddresses(result, options)
	if joinIPs(selection.Addresses) != "fe80::1" || selection.Total != 1 {
		t.Fatalf("zoned connect-IP selection = %#v", selection)
	}
}
