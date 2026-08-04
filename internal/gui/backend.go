// Package gui coordinates the Fyne desktop interface around application-layer
// services without leaking toolkit types into the backend.
package gui

import (
	"context"

	"github.com/Naenier/orynelo/internal/application"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/privacy"
)

// Backend is the application-layer contract used by the desktop interface.
// It intentionally contains no Fyne types.
type Backend interface {
	// DiagnoseRequest resolves and runs one diagnosis while streaming safe events.
	DiagnoseRequest(
		context.Context,
		application.DiagnoseRequest,
		model.EventSink,
	) (model.Diagnosis, error)

	// Configuration returns the active settings snapshot.
	Configuration() application.Config
	// SaveConfiguration validates, persists, and activates settings.
	SaveConfiguration(application.Config) error
	// LogDirectory returns the platform directory containing application logs.
	LogDirectory() string

	// ListHistory returns compact stored diagnosis rows matching the filters.
	ListHistory(context.Context, string, model.Status) ([]model.HistoryEntry, error)
	// GetDiagnosis returns one complete stored diagnosis.
	GetDiagnosis(context.Context, string) (model.Diagnosis, error)
	// DeleteDiagnosis removes one stored diagnosis.
	DeleteDiagnosis(context.Context, string) error
	// ClearHistory removes all stored diagnoses.
	ClearHistory(context.Context) error

	// ListProfiles returns reusable diagnostic profiles.
	ListProfiles(context.Context) ([]model.Profile, error)
	// SaveProfile creates or updates a reusable diagnostic profile.
	SaveProfile(context.Context, model.Profile) (model.Profile, error)
	// DeleteProfile removes one reusable profile.
	DeleteProfile(context.Context, int64) error

	// RenderReport creates a privacy-projected report in the requested format.
	RenderReport(string, model.Diagnosis, privacy.Mode) ([]byte, error)
}
