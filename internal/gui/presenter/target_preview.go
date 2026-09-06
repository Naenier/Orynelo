package presenter

import (
	"fmt"
	"strings"

	targetcheck "github.com/Naenier/orynelo/internal/diagnostics/checks/target"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/privacy"
)

// DiagnoseContext identifies which protocol-specific controls are applicable
// to the effective target selected in the Diagnose form.
type DiagnoseContext string

const (
	DiagnoseContextUnknown DiagnoseContext = "unknown"
	DiagnoseContextTCP     DiagnoseContext = "tcp"
	DiagnoseContextTLS     DiagnoseContext = "tls"
	DiagnoseContextHTTP    DiagnoseContext = "http"
	DiagnoseContextHTTPS   DiagnoseContext = "https"
)

// TargetContext parses the effective target with the same rules used by the
// diagnostic runner and returns the protocol context used to shape the form.
// Invalid and incomplete targets deliberately return Unknown so editing never
// flashes an unrelated set of advanced controls.
func TargetContext(raw, modeValue string) DiagnoseContext {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DiagnoseContextUnknown
	}
	parsed, err := targetcheck.Parse(raw)
	if err != nil {
		return DiagnoseContextUnknown
	}
	switch model.DiagnosticMode(strings.ToLower(strings.TrimSpace(modeValue))) {
	case model.DiagnosticModeTCP:
		return DiagnoseContextTCP
	case model.DiagnosticModeTLS:
		return DiagnoseContextTLS
	}
	switch parsed.Mode {
	case model.TargetModeTCP:
		return DiagnoseContextTCP
	case model.TargetModeTLS:
		return DiagnoseContextTLS
	case model.TargetModeHTTP:
		return DiagnoseContextHTTP
	case model.TargetModeHTTPS:
		return DiagnoseContextHTTPS
	default:
		return DiagnoseContextUnknown
	}
}

// TargetPreview returns the same privacy-safe effective target interpretation
// shown before a GUI run. It performs parsing only and never starts I/O.
func TargetPreview(raw, modeValue string) (string, error) {
	parsed, err := targetcheck.Parse(raw)
	if err != nil {
		return "", err
	}
	mode := model.DiagnosticMode(strings.ToLower(strings.TrimSpace(modeValue)))
	if mode != model.DiagnosticModeAuto {
		wanted := model.TargetModeTCP
		if mode == model.DiagnosticModeTLS {
			wanted = model.TargetModeTLS
		}
		if strings.Contains(raw, "://") && parsed.Mode != wanted {
			return "", fmt.Errorf("explicit %s target conflicts with %s mode", parsed.Mode, mode)
		}
		if !strings.Contains(raw, "://") && strings.ContainsAny(raw, "/?#") {
			return "", fmt.Errorf("explicit %s mode does not accept URL paths, queries, or fragments", mode)
		}
		parsed, err = targetcheck.Parse(string(wanted) + "://" + parsed.Address())
		if err != nil {
			return "", err
		}
	}
	return privacy.Standard().Target(parsed).Normalized, nil
}
