package target

import (
	"context"
	"fmt"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

// Check confirms the canonical target passed into the pipeline.
type Check struct{}

func (Check) ID() string   { return "target" }
func (Check) Name() string { return "Target validation" }

func (Check) Run(_ context.Context, state *model.State) model.CheckResult {
	t := state.Target
	if t.Host == "" || t.Port == 0 {
		return model.CheckResult{
			ID:        "target",
			Name:      "Target validation",
			Status:    model.StatusFailed,
			Summary:   "The target is missing a host or port.",
			ErrorCode: ErrorInvalidTarget,
		}
	}
	return model.CheckResult{
		ID:      "target",
		Name:    "Target validation",
		Status:  model.StatusPassed,
		Summary: fmt.Sprintf("Parsed %s target %s.", t.Kind, t.Normalized),
		Evidence: []model.Evidence{{
			ID:      "target.normalized",
			Code:    "TARGET_NORMALIZED",
			Message: "The target was parsed and normalized.",
			Details: map[string]string{
				"host":       t.Host,
				"port":       fmt.Sprintf("%d", t.Port),
				"normalized": t.Normalized,
			},
		}},
	}
}
