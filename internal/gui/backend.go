package gui

import (
	"context"

	"github.com/Naenier/opsdoctor/internal/application"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

// Backend is the application-layer contract used by the desktop interface.
// It intentionally contains no Fyne types.
type Backend interface {
	Diagnose(context.Context, model.DiagnoseOptions, model.EventSink) (model.Diagnosis, error)

	Configuration() application.Config
	SaveConfiguration(application.Config) error
	LogDirectory() string

	ListHistory(context.Context, string, model.Status) ([]model.HistoryEntry, error)
	GetDiagnosis(context.Context, string) (model.Diagnosis, error)
	DeleteDiagnosis(context.Context, string) error
	ClearHistory(context.Context) error

	ListProfiles(context.Context) ([]model.Profile, error)
	SaveProfile(context.Context, model.Profile) (model.Profile, error)
	DeleteProfile(context.Context, int64) error

	RenderReport(string, model.Diagnosis) ([]byte, error)
}
