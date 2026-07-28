package storage

import (
	"strings"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/redaction"
)

func sanitizeDiagnosis(input model.Diagnosis) model.Diagnosis {
	result := input
	result.Target.Original = redaction.RedactURL(input.Target.Original)
	result.Target.Normalized = redaction.RedactURL(input.Target.Normalized)
	result.Target.RequestURL = ""
	result.Options.Target = redaction.RedactURL(input.Options.Target)
	result.Summary.Title = redaction.RedactText(input.Summary.Title)
	result.Summary.Description = redaction.RedactText(input.Summary.Description)
	result.Summary.EvidenceRefs = append([]string(nil), input.Summary.EvidenceRefs...)
	result.Summary.Recommendations = sanitizeRecommendations(input.Summary.Recommendations)

	result.Checks = make([]model.CheckResult, len(input.Checks))
	for checkIndex, check := range input.Checks {
		check.Summary = redaction.RedactText(check.Summary)
		check.Evidence = make([]model.Evidence, len(input.Checks[checkIndex].Evidence))
		for evidenceIndex, evidence := range input.Checks[checkIndex].Evidence {
			evidence.Message = redaction.RedactText(evidence.Message)
			evidence.Details = redaction.RedactMap(evidence.Details)
			check.Evidence[evidenceIndex] = evidence
		}
		check.Recommendations = sanitizeRecommendations(input.Checks[checkIndex].Recommendations)
		result.Checks[checkIndex] = check
	}
	return result
}

func sanitizeRecommendations(input []model.Recommendation) []model.Recommendation {
	result := make([]model.Recommendation, len(input))
	for index, recommendation := range input {
		recommendation.Message = redaction.RedactText(recommendation.Message)
		result[index] = recommendation
	}
	return result
}

func sanitizeProfile(input model.Profile) model.Profile {
	result := input
	result.Name = strings.TrimSpace(redaction.RedactText(input.Name))
	result.Target = redaction.RedactURL(strings.TrimSpace(input.Target))
	result.Method = strings.ToUpper(strings.TrimSpace(input.Method))
	result.EnableTLS = result.Mode == model.DiagnosticModeTLS
	return result
}
