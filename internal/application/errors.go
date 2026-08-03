package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/Naenier/opsdoctor/internal/redaction"
)

// ErrorCategory describes the recovery boundary for an application error.
// Values are part of the CLI/GUI contract and must remain stable.
type ErrorCategory string

const (
	ErrorCategoryValidation    ErrorCategory = "validation"
	ErrorCategoryConfiguration ErrorCategory = "configuration"
	ErrorCategoryStorage       ErrorCategory = "storage"
	ErrorCategoryPermission    ErrorCategory = "permission"
	ErrorCategoryCancelled     ErrorCategory = "cancelled"
	ErrorCategoryNetworkPolicy ErrorCategory = "network-policy"
	ErrorCategoryInternal      ErrorCategory = "internal"
)

// Valid reports whether the category is part of the application error
// contract.
func (category ErrorCategory) Valid() bool {
	switch category {
	case ErrorCategoryValidation,
		ErrorCategoryConfiguration,
		ErrorCategoryStorage,
		ErrorCategoryPermission,
		ErrorCategoryCancelled,
		ErrorCategoryNetworkPolicy,
		ErrorCategoryInternal:
		return true
	default:
		return false
	}
}

// ErrorCode is a stable, machine-readable application failure identifier.
// Once emitted by a released version, a code must not be repurposed.
type ErrorCode string

// MessageID identifies localizable user-facing copy. The identifier, rather
// than rendered text, crosses the application boundary.
type MessageID string

const (
	ErrorCodeValidationFailed    ErrorCode = "APP_VALIDATION_FAILED"
	ErrorCodeConfigurationFailed ErrorCode = "APP_CONFIGURATION_FAILED"
	ErrorCodeStorageFailed       ErrorCode = "APP_STORAGE_FAILED"
	ErrorCodePermissionDenied    ErrorCode = "APP_PERMISSION_DENIED"
	ErrorCodeOperationCancelled  ErrorCode = "APP_OPERATION_CANCELLED"
	ErrorCodeOperationTimedOut   ErrorCode = "APP_OPERATION_TIMED_OUT"
	ErrorCodeNetworkPolicy       ErrorCode = "APP_NETWORK_POLICY_BLOCKED"
	ErrorCodeInternal            ErrorCode = "APP_INTERNAL_ERROR"

	MessageIDValidationFailed    MessageID = "error.validation"
	MessageIDConfigurationFailed MessageID = "error.configuration"
	MessageIDStorageFailed       MessageID = "error.storage"
	MessageIDPermissionDenied    MessageID = "error.permission"
	MessageIDOperationCancelled  MessageID = "error.cancelled"
	MessageIDOperationTimedOut   MessageID = "error.timed_out"
	MessageIDNetworkPolicy       MessageID = "error.network_policy"
	MessageIDInternal            MessageID = "error.internal"
)

// Error is the application boundary's typed failure. Its cause is deliberately
// private and excluded from Error, View, and JSON output. It remains available
// to logging and diagnostics through errors.Unwrap, errors.Is, and errors.As.
type Error struct {
	category  ErrorCategory
	code      ErrorCode
	messageID MessageID
	arguments map[string]string
	cause     error
}

// ErrorView is the complete user-facing and JSON-safe representation of an
// application error. Arguments are already privacy-redacted.
type ErrorView struct {
	Category  ErrorCategory     `json:"category"`
	Code      ErrorCode         `json:"code"`
	MessageID MessageID         `json:"messageId"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

// NewError creates an application error without an infrastructure cause.
func NewError(
	category ErrorCategory,
	code ErrorCode,
	messageID MessageID,
	arguments map[string]string,
) *Error {
	return makeError(nil, category, code, messageID, arguments)
}

// WrapError adds a typed application boundary around cause. A nil cause
// remains nil, matching the behavior expected from error-wrapping helpers.
func WrapError(
	cause error,
	category ErrorCategory,
	code ErrorCode,
	messageID MessageID,
	arguments map[string]string,
) error {
	if cause == nil {
		return nil
	}
	return makeError(cause, category, code, messageID, arguments)
}

func makeError(
	cause error,
	category ErrorCategory,
	code ErrorCode,
	messageID MessageID,
	arguments map[string]string,
) *Error {
	if !category.Valid() {
		category = ErrorCategoryInternal
		code = ErrorCodeInternal
		messageID = MessageIDInternal
	}
	defaultCode, defaultMessageID := defaultsForCategory(category)
	if !validErrorCode(code) {
		code = defaultCode
	}
	if !validMessageID(messageID) {
		messageID = defaultMessageID
	}
	return &Error{
		category:  category,
		code:      code,
		messageID: messageID,
		arguments: safeArguments(arguments),
		cause:     cause,
	}
}

// Error returns stable technical identifiers only. In particular, it never
// includes the wrapped cause or localized arguments, so an accidental display
// of err.Error() cannot disclose infrastructure details or credentials.
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s (%s)", e.code, e.messageID)
}

// Unwrap exposes the original failure to errors.Is/errors.As and logging code.
// User-facing code should use View instead.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Category returns the stable recovery category.
func (e *Error) Category() ErrorCategory {
	if e == nil {
		return ""
	}
	return e.category
}

// Code returns the stable machine-readable code.
func (e *Error) Code() ErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

// MessageID returns the localization key for user-facing copy.
func (e *Error) MessageID() MessageID {
	if e == nil {
		return ""
	}
	return e.messageID
}

// Arguments returns an independent copy of the privacy-safe localization
// arguments.
func (e *Error) Arguments() map[string]string {
	if e == nil {
		return nil
	}
	return cloneArguments(e.arguments)
}

// View returns an independent JSON-safe view with no wrapped cause.
func (e *Error) View() ErrorView {
	if e == nil {
		return ErrorView{}
	}
	return ErrorView{
		Category:  e.category,
		Code:      e.code,
		MessageID: e.messageID,
		Arguments: cloneArguments(e.arguments),
	}
}

// MarshalJSON makes direct serialization of Error as safe as serializing its
// View. The wrapped cause is never encoded.
func (e *Error) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.View())
}

// AsError finds a typed application error anywhere in err's unwrap chain.
func AsError(err error) (*Error, bool) {
	var applicationError *Error
	if !errors.As(err, &applicationError) || applicationError == nil {
		return nil, false
	}
	return applicationError, true
}

// ClassifyError returns a typed representation for any error. Existing
// application errors are preserved. Cancellation, deadline, and permission
// failures get stable classifications; unknown errors are internal failures.
func ClassifyError(err error) *Error {
	if err == nil {
		return nil
	}
	if applicationError, ok := AsError(err); ok {
		return applicationError
	}
	switch {
	case errors.Is(err, context.Canceled):
		return makeError(
			err,
			ErrorCategoryCancelled,
			ErrorCodeOperationCancelled,
			MessageIDOperationCancelled,
			nil,
		)
	case errors.Is(err, context.DeadlineExceeded):
		return makeError(
			err,
			ErrorCategoryCancelled,
			ErrorCodeOperationTimedOut,
			MessageIDOperationTimedOut,
			nil,
		)
	case errors.Is(err, os.ErrPermission):
		return makeError(
			err,
			ErrorCategoryPermission,
			ErrorCodePermissionDenied,
			MessageIDPermissionDenied,
			nil,
		)
	default:
		return makeError(
			err,
			ErrorCategoryInternal,
			ErrorCodeInternal,
			MessageIDInternal,
			nil,
		)
	}
}

// ToErrorView classifies err and returns its cause-free JSON/user view.
func ToErrorView(err error) *ErrorView {
	applicationError := ClassifyError(err)
	if applicationError == nil {
		return nil
	}
	view := applicationError.View()
	return &view
}

// IsErrorCategory reports the classified recovery category of err.
func IsErrorCategory(err error, category ErrorCategory) bool {
	applicationError := ClassifyError(err)
	return applicationError != nil && category.Valid() && applicationError.category == category
}

// IsErrorCode reports whether err contains the given stable application code.
// Untyped cancellation, deadline, permission, and internal errors are first
// classified using ClassifyError.
func IsErrorCode(err error, code ErrorCode) bool {
	applicationError := ClassifyError(err)
	return applicationError != nil && applicationError.code == code
}

func defaultsForCategory(category ErrorCategory) (ErrorCode, MessageID) {
	switch category {
	case ErrorCategoryValidation:
		return ErrorCodeValidationFailed, MessageIDValidationFailed
	case ErrorCategoryConfiguration:
		return ErrorCodeConfigurationFailed, MessageIDConfigurationFailed
	case ErrorCategoryStorage:
		return ErrorCodeStorageFailed, MessageIDStorageFailed
	case ErrorCategoryPermission:
		return ErrorCodePermissionDenied, MessageIDPermissionDenied
	case ErrorCategoryCancelled:
		return ErrorCodeOperationCancelled, MessageIDOperationCancelled
	case ErrorCategoryNetworkPolicy:
		return ErrorCodeNetworkPolicy, MessageIDNetworkPolicy
	default:
		return ErrorCodeInternal, MessageIDInternal
	}
}

func validErrorCode(code ErrorCode) bool {
	value := string(code)
	if value == "" || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for _, char := range value {
		if (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '_' || char == '.' {
			continue
		}
		return false
	}
	return true
}

func validMessageID(messageID MessageID) bool {
	value := string(messageID)
	if value == "" || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') || char == '_' || char == '-' || char == '.' {
			continue
		}
		return false
	}
	return true
}

func safeArguments(arguments map[string]string) map[string]string {
	if len(arguments) == 0 {
		return nil
	}
	return redaction.RedactMap(arguments)
}

func cloneArguments(arguments map[string]string) map[string]string {
	if len(arguments) == 0 {
		return nil
	}
	result := make(map[string]string, len(arguments))
	for name, value := range arguments {
		result[name] = value
	}
	return result
}
