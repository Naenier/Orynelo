package storage

import (
	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/privacy"
)

func sanitizeDiagnosis(input model.Diagnosis) model.Diagnosis {
	return privacy.Standard().Diagnosis(input)
}

func sanitizeProfile(input model.Profile) model.Profile {
	return privacy.Standard().Profile(input)
}
