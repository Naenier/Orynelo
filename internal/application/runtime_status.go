package application

// RecoveryAction identifies a safe response to an unavailable optional
// runtime adapter. Values are stable so interfaces can map them to localized
// controls without inspecting technical causes.
type RecoveryAction string

const (
	RecoveryRetry         RecoveryAction = "retry"
	RecoveryRunNoHistory  RecoveryAction = "run-no-history"
	RecoveryRunEphemeral  RecoveryAction = "run-ephemeral"
	RecoveryOpenReadOnly  RecoveryAction = "open-read-only"
	RecoveryUseQuarantine RecoveryAction = "use-quarantine"
)

// StartupWarning describes an optional adapter that could not be activated.
// It deliberately contains no wrapped error or local path.
type StartupWarning struct {
	Category ErrorCategory    `json:"category"`
	Code     ErrorCode        `json:"code"`
	Message  MessageID        `json:"messageId"`
	Actions  []RecoveryAction `json:"actions,omitempty"`
}

func cloneStartupWarnings(values []StartupWarning) []StartupWarning {
	cloned := make([]StartupWarning, len(values))
	for index, value := range values {
		cloned[index] = value
		cloned[index].Actions = append([]RecoveryAction(nil), value.Actions...)
	}
	return cloned
}
