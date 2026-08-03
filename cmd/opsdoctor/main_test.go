package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Naenier/opsdoctor/internal/application"
	"github.com/Naenier/opsdoctor/internal/bootstrap"
	"github.com/Naenier/opsdoctor/internal/buildinfo"
	"github.com/Naenier/opsdoctor/internal/config"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

type recordingRunner struct {
	options model.DiagnoseOptions
}

func (runner *recordingRunner) Diagnose(
	_ context.Context,
	options model.DiagnoseOptions,
	_ model.EventSink,
) (model.Diagnosis, error) {
	runner.options = options
	return model.Diagnosis{Summary: model.Summary{Status: model.StatusPassed}}, nil
}

func TestLazyApplicationDelegatesDiagnoseRequestToApplicationResolver(t *testing.T) {
	t.Parallel()

	config := application.DefaultConfig()
	config.Diagnostics.DefaultTimeout = 41 * time.Second
	runner := &recordingRunner{}
	service, err := application.New(application.Dependencies{
		Runner: runner,
		Config: config,
	})
	if err != nil {
		t.Fatal(err)
	}
	lazy := &lazyApplication{
		info: buildinfo.Info{Version: "test"},
		openRuntime: func(buildinfo.Info) (*bootstrap.Runtime, error) {
			return &bootstrap.Runtime{Service: service}, nil
		},
	}
	target := "host.test"
	checkTimeout := 3 * time.Second
	_, err = lazy.DiagnoseRequest(
		context.Background(),
		application.DiagnoseRequest{Overrides: application.DiagnoseOverrides{
			Target:       &target,
			CheckTimeout: &checkTimeout,
		}},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if runner.options.Target != target ||
		runner.options.Timeout != 41*time.Second ||
		runner.options.CheckTimeout != checkTimeout {
		t.Fatalf("effective options = %+v", runner.options)
	}
}

func TestLazyApplicationTypesRuntimeInitializationErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		openErr  error
		category application.ErrorCategory
		code     application.ErrorCode
	}{
		{
			name:     "invalid configuration",
			openErr:  &config.InvalidError{Err: errors.New("invalid configuration detail")},
			category: application.ErrorCategoryConfiguration,
			code:     "APP_CONFIGURATION_INVALID",
		},
		{
			name:     "unknown infrastructure failure",
			openErr:  errors.New("database implementation detail"),
			category: application.ErrorCategoryInternal,
			code:     "APP_RUNTIME_INITIALIZATION_FAILED",
		},
		{
			name: "typed bootstrap storage failure",
			openErr: application.WrapError(
				errors.New("database implementation detail"),
				application.ErrorCategoryStorage,
				"APP_STORAGE_INITIALIZATION_FAILED",
				"error.storage_initialization_failed",
				nil,
			),
			category: application.ErrorCategoryStorage,
			code:     "APP_STORAGE_INITIALIZATION_FAILED",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			lazy := &lazyApplication{
				openRuntime: func(buildinfo.Info) (*bootstrap.Runtime, error) {
					return nil, test.openErr
				},
			}
			target := "host.test"
			_, err := lazy.DiagnoseRequest(
				context.Background(),
				application.DiagnoseRequest{
					Overrides: application.DiagnoseOverrides{Target: &target},
				},
				nil,
			)
			applicationError, ok := application.AsError(err)
			if !ok || applicationError.Category() != test.category ||
				applicationError.Code() != test.code {
				t.Fatalf("runtime error = %#v", err)
			}
			if !errors.Is(err, test.openErr) {
				t.Fatal("runtime error lost its wrapped cause")
			}
		})
	}
}
