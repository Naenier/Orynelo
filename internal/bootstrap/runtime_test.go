package bootstrap

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Naenier/opsdoctor/internal/application"
	"github.com/Naenier/opsdoctor/internal/buildinfo"
	"github.com/Naenier/opsdoctor/internal/config"
	"github.com/Naenier/opsdoctor/internal/platform"
)

type runtimeTestConfigStore struct {
	config application.Config
	err    error
}

type runtimeTestRunner struct {
	application.DiagnosticRunner
}

type runtimeClosePersistence struct {
	application.Persistence
	closeErr error
}

func (p *runtimeClosePersistence) Close() error { return p.closeErr }

func (store *runtimeTestConfigStore) Load() (application.Config, error) {
	return store.config, store.err
}

func (*runtimeTestConfigStore) Save(application.Config) error { return nil }

func successfulRuntimeOpeners() runtimeOpeners {
	paths := platform.Paths{
		ConfigDir:    "/config",
		DataDir:      "/data",
		StateDir:     "/state",
		ConfigFile:   "/config/config.yaml",
		DatabaseFile: "/data/opsdoctor.db",
		LogFile:      "/state/opsdoctor.log",
	}
	return runtimeOpeners{
		resolvePaths: func() (platform.Paths, error) { return paths, nil },
		ensurePaths:  func(platform.Paths) error { return nil },
		newConfigStore: func(string) runtimeConfigStore {
			return &runtimeTestConfigStore{config: application.DefaultConfig()}
		},
		openLogging: func(string, string) (*Logging, error) { return &Logging{}, nil },
		openStorage: func(string) (application.Persistence, error) { return nil, nil },
		newService: func(application.Dependencies) (*application.Service, error) {
			return &application.Service{}, nil
		},
	}
}

func TestOpenRuntimeTypesCompositionFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		configure func(*runtimeOpeners, error)
		category  application.ErrorCategory
		code      application.ErrorCode
	}{
		{
			name: "path resolution",
			configure: func(openers *runtimeOpeners, cause error) {
				openers.resolvePaths = func() (platform.Paths, error) {
					return platform.Paths{}, cause
				}
			},
			category: application.ErrorCategoryConfiguration,
			code:     "APP_PATHS_RESOLVE_FAILED",
		},
		{
			name: "path preparation",
			configure: func(openers *runtimeOpeners, cause error) {
				openers.ensurePaths = func(platform.Paths) error { return cause }
			},
			category: application.ErrorCategoryStorage,
			code:     "APP_PATHS_PREPARE_FAILED",
		},
		{
			name: "path permission",
			configure: func(openers *runtimeOpeners, _ error) {
				openers.ensurePaths = func(platform.Paths) error {
					return os.ErrPermission
				}
			},
			category: application.ErrorCategoryPermission,
			code:     application.ErrorCodePermissionDenied,
		},
		{
			name: "invalid configuration",
			configure: func(openers *runtimeOpeners, cause error) {
				openers.newConfigStore = func(string) runtimeConfigStore {
					return &runtimeTestConfigStore{
						err: &config.InvalidError{Err: cause},
					}
				}
			},
			category: application.ErrorCategoryConfiguration,
			code:     "APP_CONFIGURATION_INVALID",
		},
		{
			name: "configuration load",
			configure: func(openers *runtimeOpeners, cause error) {
				openers.newConfigStore = func(string) runtimeConfigStore {
					return &runtimeTestConfigStore{err: cause}
				}
			},
			category: application.ErrorCategoryStorage,
			code:     "APP_CONFIGURATION_LOAD_FAILED",
		},
		{
			name: "logging initialization",
			configure: func(openers *runtimeOpeners, cause error) {
				openers.openLogging = func(string, string) (*Logging, error) {
					return nil, cause
				}
			},
			category: application.ErrorCategoryStorage,
			code:     "APP_LOGGING_INITIALIZATION_FAILED",
		},
		{
			name: "storage initialization",
			configure: func(openers *runtimeOpeners, cause error) {
				openers.openStorage = func(string) (application.Persistence, error) {
					return nil, cause
				}
			},
			category: application.ErrorCategoryStorage,
			code:     "APP_STORAGE_INITIALIZATION_FAILED",
		},
		{
			name: "service initialization",
			configure: func(openers *runtimeOpeners, cause error) {
				openers.newService = func(application.Dependencies) (*application.Service, error) {
					return nil, cause
				}
			},
			category: application.ErrorCategoryInternal,
			code:     "APP_SERVICE_INITIALIZATION_FAILED",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cause := errors.New("private composition detail")
			openers := successfulRuntimeOpeners()
			test.configure(&openers, cause)
			_, err := openRuntime(buildinfo.Info{Version: "test"}, openers)
			applicationError, ok := application.AsError(err)
			if !ok || applicationError.Category() != test.category ||
				applicationError.Code() != test.code {
				t.Fatalf("openRuntime() error = %#v", err)
			}
			if test.name != "path permission" && !errors.Is(err, cause) {
				t.Fatal("typed boundary lost its infrastructure cause")
			}
			if test.name == "path permission" && !errors.Is(err, os.ErrPermission) {
				t.Fatal("permission boundary lost os.ErrPermission")
			}
		})
	}
}

func TestRuntimeCloseErrorWrapsAggregateInPrivacySafeApplicationError(t *testing.T) {
	t.Parallel()

	const serviceSecret = "/private/database/path"
	serviceCause := errors.New(serviceSecret)
	service, err := application.New(application.Dependencies{
		Runner:      &runtimeTestRunner{},
		Persistence: &runtimeClosePersistence{closeErr: serviceCause},
		Config:      application.DefaultConfig(),
	})
	if err != nil {
		t.Fatalf("application.New() error = %v", err)
	}
	logFile, err := os.CreateTemp(t.TempDir(), "private-log-path-")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	logPath := logFile.Name()
	if err := logFile.Close(); err != nil {
		t.Fatalf("initial log close error = %v", err)
	}

	err = (&Runtime{Service: service, Logging: &Logging{file: logFile}}).Close()
	topLevel, ok := err.(*application.Error)
	if !ok {
		t.Fatalf("Runtime.Close() returned non-typed top-level error: %T", err)
	}
	if topLevel.Code() != "APP_RUNTIME_CLOSE_FAILED" ||
		topLevel.Category() != application.ErrorCategoryStorage {
		t.Fatalf("runtime close error = %#v", topLevel.View())
	}
	if !errors.Is(err, serviceCause) || !errors.Is(err, os.ErrClosed) {
		t.Fatal("runtime close boundary lost an aggregate cause")
	}
	serialized, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("Marshal() error = %v", marshalErr)
	}
	for _, output := range []string{err.Error(), string(serialized)} {
		if strings.Contains(output, serviceSecret) || strings.Contains(output, logPath) {
			t.Fatalf("runtime close error exposed a private cause: %q", output)
		}
	}
}

func TestOpenRuntimePreservesTypedServiceError(t *testing.T) {
	t.Parallel()

	typed := application.NewError(
		application.ErrorCategoryConfiguration,
		"APP_SERVICE_CONFIG_TEST",
		"error.service_config_test",
		nil,
	)
	openers := successfulRuntimeOpeners()
	openers.newService = func(application.Dependencies) (*application.Service, error) {
		return nil, typed
	}
	_, err := openRuntime(buildinfo.Info{Version: "test"}, openers)
	applicationError, ok := application.AsError(err)
	if !ok || applicationError != typed || !errors.Is(err, typed) {
		t.Fatalf("typed service error was replaced: %#v", err)
	}
}

func TestOpenRuntimeSuccessRetainsResolvedPaths(t *testing.T) {
	t.Parallel()

	openers := successfulRuntimeOpeners()
	want, err := openers.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := openRuntime(buildinfo.Info{Version: "test"}, openers)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Paths != want || runtime.Service == nil || runtime.Logging == nil {
		t.Fatalf("runtime = %#v", runtime)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
