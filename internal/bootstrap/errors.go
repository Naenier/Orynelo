package bootstrap

import (
	"github.com/Naenier/orynelo/internal/application"
)

// bootstrapBoundaryError assigns operation-specific categories to otherwise
// untyped infrastructure failures. Existing application errors and canonical
// lifecycle/permission classifications remain unchanged.
func bootstrapBoundaryError(
	err error,
	category application.ErrorCategory,
	code application.ErrorCode,
	messageID application.MessageID,
) error {
	if err == nil {
		return nil
	}
	if _, ok := application.AsError(err); ok {
		return err
	}
	classified := application.ClassifyError(err)
	if classified.Category() != application.ErrorCategoryInternal {
		return classified
	}
	return application.WrapError(err, category, code, messageID, nil)
}
