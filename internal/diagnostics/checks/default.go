// Package checks assembles the production diagnostic plan.
package checks

import (
	"github.com/Naenier/orynelo/internal/diagnostics/checks/dns"
	"github.com/Naenier/orynelo/internal/diagnostics/checks/environment"
	httpcheck "github.com/Naenier/orynelo/internal/diagnostics/checks/http"
	"github.com/Naenier/orynelo/internal/diagnostics/checks/route"
	"github.com/Naenier/orynelo/internal/diagnostics/checks/target"
	"github.com/Naenier/orynelo/internal/diagnostics/checks/tcp"
	tlscheck "github.com/Naenier/orynelo/internal/diagnostics/checks/tls"
	"github.com/Naenier/orynelo/internal/diagnostics/engine"
)

// Default returns the ordered production plan. Each inner slice is one
// concurrency stage.
func Default() engine.Plan {
	return engine.Plan{
		{target.Check{}},
		{environment.New()},
		{dns.New(nil)},
		{route.New(nil)},
		{tcp.New(nil)},
		{tlscheck.New(nil)},
		{httpcheck.New()},
	}
}
