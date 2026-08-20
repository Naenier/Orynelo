package presenter

import (
	"fmt"
	"strings"

	targetcheck "github.com/Naenier/orynelo/internal/diagnostics/checks/target"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/privacy"
)

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
