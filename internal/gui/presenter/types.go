// Package presenter contains GUI-only view models. Diagnostic and persistence
// domain types are converted here instead of being coupled to Fyne widgets.
package presenter

import "time"

// DiagnoseInput is the set of controls exposed by the Diagnose screen.
type DiagnoseInput struct {
	Target                 string
	Mode                   string
	IPVersion              string
	Timeout                time.Duration
	CheckTimeout           time.Duration
	Method                 string
	NoProxy                bool
	Insecure               bool
	AllowInsecureRedirects bool
	AllowPrivateRedirects  bool
	MaxRedirects           int
	Verbosity              string
	ProbeMode              string
	AddressLimit           int
	AddressMatrixBudget    time.Duration
	ExpectedStatusMin      int
	ExpectedStatusMax      int
	ExpectedStatusSet      bool
	LatencyThreshold       time.Duration
	ConnectIP              string
	ServerName             string
	HTTPHost               string
	CustomCABundlePath     string
	RequestHeaders         map[string]string
	CollectDNSDetails      bool
	InspectBody            bool
}

// CheckView is a display-ready diagnostic step.
type CheckView struct {
	ID                  string
	Name                string
	Status              string
	Summary             string
	StartedAt           time.Time
	FinishedAt          time.Time
	Duration            time.Duration
	Evidence            []string
	Recommendations     []string
	EvidenceGroups      []EvidenceGroupView
	RecommendationItems []RecommendationView
	Technical           string
	RawStructured       string
}

// DiagnosisView is a display-ready completed diagnostic run.
type DiagnosisView struct {
	ID                     string
	Target                 string
	SummaryTitle           string
	SummaryDetail          string
	SummaryRecommendations []string
	Recommendations        []RecommendationView
	Paths                  []PathView
	PrimaryPath            string
	BreakPoint             string
	StartedAt              time.Time
	FinishedAt             time.Time
	Version                string
	OverallStatus          string
	Checks                 []CheckView
	Timing                 []TimingView
}

// RecommendationView preserves priority and source links for one action.
type RecommendationView struct {
	ID          string
	Priority    string
	Message     string
	CheckID     string
	EvidenceIDs []string
}

// EvidenceGroupView groups facts by their concrete path, hop, and attempt.
type EvidenceGroupView struct {
	PathID    string
	HopID     string
	AttemptID string
	Items     []EvidenceItemView
}

// EvidenceItemView is a structured, display-safe observation.
type EvidenceItemView struct {
	ID      string
	Code    string
	Message string
	Values  []EvidenceValueView
}

// EvidenceValueView keeps both a bounded display form and the complete value.
type EvidenceValueView struct {
	Key       string
	Display   string
	Full      string
	Kind      string
	Redacted  bool
	Collapsed bool
}

// PathView describes an observed client, redirect, proxy, or comparison path.
type PathView struct {
	ID       string
	Role     string
	Kind     string
	Sequence int
	Label    string
	Hops     []HopView
}

// HopView describes one endpoint and its attributable attempts.
type HopView struct {
	ID       string
	Label    string
	Reused   bool
	Attempts []AttemptView
}

// AttemptView describes one independently timed network operation.
type AttemptView struct {
	ID         string
	Kind       string
	State      string
	StartedAt  time.Time
	FinishedAt time.Time
	Duration   time.Duration
	Reused     bool
}

// TimingView is one labeled timing measurement.
type TimingView struct {
	Name       string
	Duration   time.Duration
	Measured   bool
	IsTotal    bool
	StartedAt  time.Time
	FinishedAt time.Time
	AttemptID  string
	Reused     bool
}

// HistoryView is one row in the history table.
type HistoryView struct {
	ID        string
	Date      time.Time
	Target    string
	Status    string
	Duration  time.Duration
	Version   string
	Diagnosis *DiagnosisView
}

// ProfileView is one saved diagnostic profile.
type ProfileView struct {
	ID           int64
	Name         string
	Target       string
	Mode         string
	IPVersion    string
	Timeout      time.Duration
	CheckTimeout time.Duration
	NoProxy      bool
	MaxRedirects int
	Method       string
	// Unsafe opt-ins and Verbosity are transient Diagnose-screen controls.
	// Stored profiles receive safe defaults; history reruns can restore them.
	Insecure               bool
	AllowInsecureRedirects bool
	AllowPrivateRedirects  bool
	Verbosity              string
}
