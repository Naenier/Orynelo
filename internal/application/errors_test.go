package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Naenier/orynelo/internal/redaction"
)

func TestErrorCategoriesAreStableAndValid(t *testing.T) {
	t.Parallel()

	want := []ErrorCategory{
		"validation",
		"configuration",
		"storage",
		"permission",
		"cancelled",
		"network-policy",
		"internal",
	}
	got := []ErrorCategory{
		ErrorCategoryValidation,
		ErrorCategoryConfiguration,
		ErrorCategoryStorage,
		ErrorCategoryPermission,
		ErrorCategoryCancelled,
		ErrorCategoryNetworkPolicy,
		ErrorCategoryInternal,
	}
	for index := range want {
		if got[index] != want[index] || !got[index].Valid() {
			t.Fatalf("category %d = %q, want valid %q", index, got[index], want[index])
		}
	}
	if ErrorCategory("other").Valid() {
		t.Fatal("unknown category is valid")
	}
}

func TestNewErrorUsesStableDefaultsAndDefensiveArguments(t *testing.T) {
	t.Parallel()

	input := map[string]string{
		"field":         "target",
		"request.url":   "https://user:password@example.test/?access_token=secret&view=full",
		"client_secret": "argument-secret",
	}
	applicationError := NewError(ErrorCategoryValidation, "", "", input)
	input["field"] = "mutated"
	input["late"] = "not-copied"

	if applicationError.Category() != ErrorCategoryValidation ||
		applicationError.Code() != ErrorCodeValidationFailed ||
		applicationError.MessageID() != MessageIDValidationFailed {
		t.Fatalf("unexpected descriptors: %#v", applicationError.View())
	}
	arguments := applicationError.Arguments()
	if arguments["field"] != "target" || arguments["late"] != "" {
		t.Fatalf("arguments were not defensively copied: %#v", arguments)
	}
	if arguments["client_secret"] != redaction.Replacement {
		t.Fatalf("sensitive keyed argument = %q", arguments["client_secret"])
	}
	for _, secret := range []string{"user", "password", "secret"} {
		if strings.Contains(arguments["request.url"], secret) {
			t.Fatalf("URL argument leaked %q: %q", secret, arguments["request.url"])
		}
	}
	arguments["field"] = "view-mutated"
	if applicationError.Arguments()["field"] != "target" {
		t.Fatal("returned arguments mutated the application error")
	}
}

func TestErrorStringAndJSONNeverExposeCause(t *testing.T) {
	t.Parallel()

	const causeSecret = "database-password-from-cause"
	wrapped := WrapError(
		errors.New(causeSecret),
		ErrorCategoryStorage,
		"HISTORY_WRITE_FAILED",
		"error.history_write",
		map[string]string{
			"profile": "daily",
			"token":   "argument-token-secret",
		},
	)
	applicationError, ok := AsError(wrapped)
	if !ok {
		t.Fatal("WrapError did not return an application error")
	}

	if rendered := applicationError.Error(); rendered != "HISTORY_WRITE_FAILED (error.history_write)" {
		t.Fatalf("Error() = %q", rendered)
	}
	encoded, err := json.Marshal(applicationError)
	if err != nil {
		t.Fatal(err)
	}
	jsonText := string(encoded)
	for _, secret := range []string{causeSecret, "argument-token-secret"} {
		if strings.Contains(jsonText, secret) {
			t.Fatalf("JSON exposed %q: %s", secret, jsonText)
		}
	}
	for _, field := range []string{
		`"category":"storage"`,
		`"code":"HISTORY_WRITE_FAILED"`,
		`"messageId":"error.history_write"`,
		`"token":"[REDACTED]"`,
	} {
		if !strings.Contains(jsonText, field) {
			t.Fatalf("JSON %s does not contain %s", jsonText, field)
		}
	}
	if strings.Contains(jsonText, "cause") {
		t.Fatalf("JSON contains a cause field: %s", jsonText)
	}
}

type testCause struct {
	marker string
}

func (e *testCause) Error() string { return e.marker }

func TestWrapErrorPreservesErrorsIsAndAs(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("storage sentinel")
	cause := &testCause{marker: "typed cause"}
	joined := errors.Join(sentinel, cause)
	wrapped := WrapError(
		joined,
		ErrorCategoryStorage,
		"PROFILE_LOAD_FAILED",
		"error.profile_load",
		nil,
	)
	outer := fmt.Errorf("operation boundary: %w", wrapped)

	if !errors.Is(outer, sentinel) {
		t.Fatal("errors.Is did not reach wrapped cause")
	}
	var gotCause *testCause
	if !errors.As(outer, &gotCause) || gotCause != cause {
		t.Fatal("errors.As did not reach typed cause")
	}
	var gotApplicationError *Error
	if !errors.As(outer, &gotApplicationError) || gotApplicationError.Code() != "PROFILE_LOAD_FAILED" {
		t.Fatal("errors.As did not find application error")
	}
	if applicationError, ok := AsError(outer); !ok || applicationError != gotApplicationError {
		t.Fatal("AsError did not preserve the application error")
	}
	if WrapError(nil, ErrorCategoryInternal, "", "", nil) != nil {
		t.Fatal("WrapError(nil) returned a non-nil error")
	}
}

func TestClassifyError(t *testing.T) {
	t.Parallel()

	typed := NewError(
		ErrorCategoryNetworkPolicy,
		"REDIRECT_BLOCKED",
		"error.redirect_blocked",
		nil,
	)
	tests := []struct {
		name       string
		err        error
		category   ErrorCategory
		code       ErrorCode
		messageID  MessageID
		preserved  *Error
		isOriginal error
	}{
		{
			name:       "existing application error",
			err:        fmt.Errorf("outer: %w", typed),
			category:   ErrorCategoryNetworkPolicy,
			code:       "REDIRECT_BLOCKED",
			messageID:  "error.redirect_blocked",
			preserved:  typed,
			isOriginal: typed,
		},
		{
			name:       "cancelled",
			err:        fmt.Errorf("stop: %w", context.Canceled),
			category:   ErrorCategoryCancelled,
			code:       ErrorCodeOperationCancelled,
			messageID:  MessageIDOperationCancelled,
			isOriginal: context.Canceled,
		},
		{
			name:       "deadline",
			err:        fmt.Errorf("stop: %w", context.DeadlineExceeded),
			category:   ErrorCategoryCancelled,
			code:       ErrorCodeOperationTimedOut,
			messageID:  MessageIDOperationTimedOut,
			isOriginal: context.DeadlineExceeded,
		},
		{
			name: "permission",
			err: &os.PathError{
				Op:   "open",
				Path: "/private/history.db",
				Err:  os.ErrPermission,
			},
			category:   ErrorCategoryPermission,
			code:       ErrorCodePermissionDenied,
			messageID:  MessageIDPermissionDenied,
			isOriginal: os.ErrPermission,
		},
		{
			name:       "unknown",
			err:        errors.New("implementation detail"),
			category:   ErrorCategoryInternal,
			code:       ErrorCodeInternal,
			messageID:  MessageIDInternal,
			isOriginal: nil,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := ClassifyError(test.err)
			if got == nil || got.Category() != test.category ||
				got.Code() != test.code || got.MessageID() != test.messageID {
				t.Fatalf("ClassifyError() = %#v", got)
			}
			if test.preserved != nil && got != test.preserved {
				t.Fatal("existing application error was copied or replaced")
			}
			if test.isOriginal != nil && !errors.Is(got, test.isOriginal) {
				t.Fatalf("classified error no longer wraps %v", test.isOriginal)
			}
			if !IsErrorCategory(test.err, test.category) || !IsErrorCode(test.err, test.code) {
				t.Fatal("classification helpers disagree with ClassifyError")
			}
		})
	}
	if ClassifyError(nil) != nil || ToErrorView(nil) != nil {
		t.Fatal("nil error was classified")
	}
}

func TestToErrorViewIsIndependentAndCauseFree(t *testing.T) {
	t.Parallel()

	err := WrapError(
		errors.New("private storage detail"),
		ErrorCategoryStorage,
		"HISTORY_READ_FAILED",
		"error.history_read",
		map[string]string{"action": "retry"},
	)
	first := ToErrorView(err)
	second := ToErrorView(err)
	if first == nil || second == nil || first == second {
		t.Fatal("ToErrorView did not return independent views")
	}
	first.Arguments["action"] = "mutated"
	if second.Arguments["action"] != "retry" {
		t.Fatal("views share mutable arguments")
	}
	encoded, marshalErr := json.Marshal(struct {
		Error *ErrorView `json:"error"`
	}{Error: second})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(string(encoded), "private storage detail") {
		t.Fatalf("view exposed cause: %s", encoded)
	}
}

func TestInvalidDescriptorsFailClosedToInternal(t *testing.T) {
	t.Parallel()

	invalidCategory := NewError(
		"secret category",
		"SECRET_CODE",
		"error.secret",
		nil,
	)
	if invalidCategory.Category() != ErrorCategoryInternal ||
		invalidCategory.Code() != ErrorCodeInternal ||
		invalidCategory.MessageID() != MessageIDInternal {
		t.Fatalf("invalid category did not fail closed: %#v", invalidCategory.View())
	}

	invalidIdentifiers := NewError(
		ErrorCategoryConfiguration,
		"configuration failed: password=secret",
		"Configuration failed for secret",
		nil,
	)
	if invalidIdentifiers.Code() != ErrorCodeConfigurationFailed ||
		invalidIdentifiers.MessageID() != MessageIDConfigurationFailed {
		t.Fatalf("invalid identifiers did not use defaults: %#v", invalidIdentifiers.View())
	}
}
