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
}

// CheckView is a display-ready diagnostic step.
type CheckView struct {
	ID              string
	Name            string
	Status          string
	Summary         string
	StartedAt       time.Time
	FinishedAt      time.Time
	Duration        time.Duration
	Evidence        []string
	Recommendations []string
	Technical       string
	RawStructured   string
}

// DiagnosisView is a display-ready completed diagnostic run.
type DiagnosisView struct {
	ID                     string
	Target                 string
	SummaryTitle           string
	SummaryDetail          string
	SummaryRecommendations []string
	OverallStatus          string
	Checks                 []CheckView
	Timing                 []TimingView
}

// TimingView is one labeled timing measurement.
type TimingView struct {
	Name     string
	Duration time.Duration
	Measured bool
	IsTotal  bool
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
