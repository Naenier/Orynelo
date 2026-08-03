package application

import (
	"context"
	"errors"
	"os"
)

// operationError preserves already-typed failures and promotes lifecycle and
// permission failures to their canonical categories before applying an
// operation-specific boundary.
func operationError(
	err error,
	category ErrorCategory,
	code ErrorCode,
	messageID MessageID,
	arguments map[string]string,
) error {
	if err == nil {
		return nil
	}
	if _, ok := AsError(err); ok {
		return err
	}
	if errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, os.ErrPermission) {
		return ClassifyError(err)
	}
	return WrapError(err, category, code, messageID, arguments)
}
