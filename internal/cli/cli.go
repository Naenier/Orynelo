// Package cli implements the Cobra interface over the shared application
// service.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Naenier/orynelo/internal/application"
	"github.com/Naenier/orynelo/internal/buildinfo"
	"github.com/Naenier/orynelo/internal/diagnostics/model"
	"github.com/Naenier/orynelo/internal/privacy"
	"github.com/Naenier/orynelo/internal/report"
	"github.com/Naenier/orynelo/internal/secureio"
)

const (
	ExitOK       = 0
	ExitFailure  = 1
	ExitInput    = 2
	ExitInternal = 3
	ExitCancel   = 130
)

// Application is the CLI-facing application contract.
type Application interface {
	DiagnoseRequest(context.Context, application.DiagnoseRequest, model.EventSink) (model.Diagnosis, error)
	RenderReport(string, model.Diagnosis, privacy.Mode) ([]byte, error)
}

// Options configures a root command without process-global output state.
type Options struct {
	Application Application
	Build       buildinfo.Info
	Stdout      io.Writer
	Stderr      io.Writer
	SetLogLevel func(string) error
}

// ExitError carries a stable process code without forcing a duplicate message.
type ExitError struct {
	Code       int
	Err        error
	JSONOutput bool
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit status %d", e.Code)
	}
	return e.Err.Error()
}

// Unwrap returns the underlying application error.
func (e *ExitError) Unwrap() error { return e.Err }

// NewRoot builds the complete orynelo command tree.
func NewRoot(options Options) *cobra.Command {
	if options.Stdout == nil {
		options.Stdout = io.Discard
	}
	if options.Stderr == nil {
		options.Stderr = io.Discard
	}
	root := &cobra.Command{
		Use:           "orynelo",
		Short:         "Evidence-based network reachability diagnostics",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return nil
			}
			return &ExitError{Code: ExitInput, Err: fmt.Errorf("unknown command %q", args[0])}
		},
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	root.SetOut(options.Stdout)
	root.SetErr(options.Stderr)
	root.SetFlagErrorFunc(func(command *cobra.Command, err error) error {
		return &ExitError{
			Code: ExitInput,
			Err: typedBoundaryError(
				err,
				application.ErrorCategoryValidation,
				"APP_CLI_FLAGS_INVALID",
				"error.cli_flags_invalid",
				nil,
			),
			JSONOutput: diagnoseJSONOutput(command),
		}
	})
	root.CompletionOptions.DisableDefaultCmd = true
	root.AddCommand(
		newDiagnose(options),
		newVersion(options.Build),
		newCompletion(root),
	)
	return root
}

// Execute runs a root command and maps errors to the documented exit codes.
func Execute(ctx context.Context, root *cobra.Command, stderr io.Writer) int {
	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}
	var exit *ExitError
	if errors.As(err, &exit) {
		if exit.Err != nil && stderr != nil {
			writeCLIError(stderr, exit.Err, exit.JSONOutput)
		}
		return exit.Code
	}
	applicationError := application.ClassifyError(err)
	code := exitCodeForApplicationError(applicationError)
	if stderr != nil {
		writeCLIError(stderr, applicationError, false)
	}
	return code
}

type diagnoseFlags struct {
	timeout                string
	checkTimeout           string
	ipVersion              string
	format                 string
	anonymize              string
	output                 string
	noProxy                bool
	insecure               bool
	allowInsecureRedirects bool
	allowPrivateRedirects  bool
	maxRedirects           string
	method                 string
	logLevel               string
	verbose                bool
}

func newDiagnose(options Options) *cobra.Command {
	flags := diagnoseFlags{}
	command := &cobra.Command{
		Use:   "diagnose <target>",
		Short: "Run an ordered diagnostic pipeline for a network target",
		Args: func(command *cobra.Command, args []string) error {
			if len(args) != 1 {
				return diagnoseExitError(command, application.NewError(
					application.ErrorCategoryValidation,
					"APP_CLI_TARGET_REQUIRED",
					"error.cli_target_required",
					map[string]string{"field": "target"},
				))
			}
			return nil
		},
		RunE: func(command *cobra.Command, args []string) error {
			if options.Application == nil {
				return diagnoseExitError(command, application.NewError(
					application.ErrorCategoryInternal,
					"APP_APPLICATION_UNAVAILABLE",
					"error.application_unavailable",
					nil,
				))
			}
			if command.Flags().Changed("log-level") {
				if !validLogLevel(flags.logLevel) {
					return diagnoseExitError(command, application.NewError(
						application.ErrorCategoryValidation,
						"APP_LOG_LEVEL_INVALID",
						"error.log_level_invalid",
						map[string]string{"field": "log-level"},
					))
				}
				if options.SetLogLevel != nil {
					if err := options.SetLogLevel(flags.logLevel); err != nil {
						return diagnoseExitError(command, typedBoundaryError(
							err,
							application.ErrorCategoryInternal,
							"APP_LOG_LEVEL_APPLY_FAILED",
							"error.log_level_apply_failed",
							nil,
						))
					}
				}
			}
			parsedFormat, err := report.ParseFormat(flags.format)
			if err != nil {
				return diagnoseExitError(command, typedBoundaryError(
					err,
					application.ErrorCategoryValidation,
					"APP_REPORT_FORMAT_INVALID",
					"error.report_format_invalid",
					map[string]string{"field": "format"},
				))
			}
			anonymization, err := privacy.ParseMode(flags.anonymize)
			if err != nil {
				return diagnoseExitError(command, typedBoundaryError(
					err,
					application.ErrorCategoryValidation,
					"APP_PRIVACY_MODE_INVALID",
					"error.privacy_mode_invalid",
					map[string]string{"field": "anonymize"},
				))
			}
			format := string(parsedFormat)
			overrides, err := diagnoseOverrides(command, args[0], flags)
			if err != nil {
				return diagnoseExitError(command, err)
			}

			var sink model.EventSink
			if flags.verbose && format != "json" {
				sink = verboseSink(options.Stderr)
			}
			diagnosis, err := options.Application.DiagnoseRequest(
				command.Context(),
				application.DiagnoseRequest{
					Overrides: overrides,
				},
				sink,
			)
			if err != nil {
				return diagnoseExitError(command, err)
			}
			content, err := options.Application.RenderReport(format, diagnosis, anonymization)
			if err != nil {
				return diagnoseExitError(command, typedBoundaryError(
					err,
					application.ErrorCategoryInternal,
					"APP_REPORT_RENDER_FAILED",
					"error.report_render_failed",
					nil,
				))
			}
			if err := writeOutput(options.Stdout, flags.output, content); err != nil {
				return diagnoseExitError(command, typedBoundaryError(
					err,
					application.ErrorCategoryStorage,
					"APP_REPORT_WRITE_FAILED",
					"error.report_write_failed",
					nil,
				))
			}
			if flags.output != "" && flags.output != "-" {
				destination, err := filepath.Abs(filepath.Clean(flags.output))
				if err != nil {
					return diagnoseExitError(command, typedBoundaryError(
						fmt.Errorf("resolve report output path: %w", err),
						application.ErrorCategoryStorage,
						"APP_REPORT_DESTINATION_INVALID",
						"error.report_destination_invalid",
						nil,
					))
				}
				message := fmt.Sprintf("Report saved atomically to %s\n", destination)
				written, err := io.WriteString(options.Stderr, message)
				if err != nil {
					return diagnoseExitError(command, typedBoundaryError(
						fmt.Errorf("write report destination: %w", err),
						application.ErrorCategoryInternal,
						"APP_CLI_OUTPUT_FAILED",
						"error.cli_output_failed",
						nil,
					))
				}
				if written != len(message) {
					return diagnoseExitError(command, typedBoundaryError(
						fmt.Errorf("write report destination: %w", io.ErrShortWrite),
						application.ErrorCategoryInternal,
						"APP_CLI_OUTPUT_FAILED",
						"error.cli_output_failed",
						nil,
					))
				}
			}
			if errors.Is(command.Context().Err(), context.Canceled) ||
				diagnosis.Summary.Status == model.StatusCancelled {
				return &ExitError{Code: ExitCancel, JSONOutput: diagnoseJSONOutput(command)}
			}
			if diagnosis.Summary.Status == model.StatusFailed {
				return &ExitError{Code: ExitFailure, JSONOutput: diagnoseJSONOutput(command)}
			}
			return nil
		},
	}
	command.Flags().StringVar(&flags.timeout, "timeout", (15 * time.Second).String(), "Global diagnostic timeout")
	command.Flags().StringVar(&flags.checkTimeout, "check-timeout", (5 * time.Second).String(), "Timeout for an individual check")
	command.Flags().StringVar(&flags.ipVersion, "ip-version", "auto", "Address family: auto, 4, or 6")
	command.Flags().StringVar(&flags.format, "format", "text", "Report format: text, json, markdown, or md")
	command.Flags().StringVar(
		&flags.anonymize,
		"anonymize",
		string(privacy.ModeStandard),
		"Export anonymization: standard or strict",
	)
	command.Flags().StringVarP(&flags.output, "output", "o", "", "Write the report to a private file instead of stdout")
	command.Flags().BoolVar(&flags.noProxy, "no-proxy", false, "Disable proxy use for this diagnosis")
	command.Flags().BoolVar(&flags.insecure, "insecure", false, "Disable TLS verification (unsafe; reported as a warning)")
	command.Flags().BoolVar(
		&flags.allowInsecureRedirects,
		"allow-insecure-redirects",
		false,
		"Allow HTTPS-to-HTTP redirects (unsafe; explicit opt-in)",
	)
	command.Flags().BoolVar(
		&flags.allowPrivateRedirects,
		"allow-private-redirects",
		false,
		"Allow redirects from public hosts to private or local networks (unsafe; explicit opt-in)",
	)
	command.Flags().StringVar(&flags.maxRedirects, "max-redirects", "10", "Maximum HTTP redirects")
	command.Flags().StringVar(&flags.method, "method", "GET", "Safe HTTP method: GET, HEAD, or OPTIONS")
	command.Flags().StringVar(&flags.logLevel, "log-level", "info", "Log level: debug, info, warn, or error")
	command.Flags().BoolVarP(&flags.verbose, "verbose", "v", false, "Write progress events to stderr")
	return command
}

func validLogLevel(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug", "info", "warn", "error":
		return true
	default:
		return false
	}
}

func diagnoseOverrides(
	command *cobra.Command,
	targetValue string,
	flags diagnoseFlags,
) (application.DiagnoseOverrides, error) {
	target := targetValue
	overrides := application.DiagnoseOverrides{Target: &target}

	if command.Flags().Changed("timeout") {
		value, err := time.ParseDuration(flags.timeout)
		if err != nil {
			return application.DiagnoseOverrides{}, invalidCLIFlagValue(err, "timeout")
		}
		overrides.Timeout = &value
	}
	if command.Flags().Changed("check-timeout") {
		value, err := time.ParseDuration(flags.checkTimeout)
		if err != nil {
			return application.DiagnoseOverrides{}, invalidCLIFlagValue(err, "check-timeout")
		}
		overrides.CheckTimeout = &value
	}
	if command.Flags().Changed("ip-version") {
		value := model.IPVersion(flags.ipVersion)
		overrides.IPVersion = &value
	}
	if command.Flags().Changed("no-proxy") {
		value := flags.noProxy
		overrides.NoProxy = &value
	}
	if command.Flags().Changed("insecure") {
		value := flags.insecure
		overrides.Insecure = &value
	}
	if command.Flags().Changed("allow-insecure-redirects") {
		value := flags.allowInsecureRedirects
		overrides.AllowInsecureRedirects = &value
	}
	if command.Flags().Changed("allow-private-redirects") {
		value := flags.allowPrivateRedirects
		overrides.AllowPrivateRedirects = &value
	}
	if command.Flags().Changed("max-redirects") {
		value, err := strconv.Atoi(flags.maxRedirects)
		if err != nil {
			return application.DiagnoseOverrides{}, invalidCLIFlagValue(err, "max-redirects")
		}
		overrides.MaxRedirects = &value
	}
	if command.Flags().Changed("method") {
		value := flags.method
		overrides.Method = &value
	}
	if command.Flags().Changed("verbose") {
		value := model.ReportVerbosityNormal
		if flags.verbose {
			value = model.ReportVerbosityVerbose
		}
		overrides.ReportVerbosity = &value
	}
	return overrides, nil
}

func invalidCLIFlagValue(err error, field string) error {
	return typedBoundaryError(
		err,
		application.ErrorCategoryValidation,
		"APP_CLI_FLAGS_INVALID",
		"error.cli_flags_invalid",
		map[string]string{"field": field},
	)
}

func diagnoseExitError(command *cobra.Command, err error) *ExitError {
	applicationError := application.ClassifyError(err)
	return &ExitError{
		Code:       exitCodeForApplicationError(applicationError),
		Err:        applicationError,
		JSONOutput: diagnoseJSONOutput(command),
	}
}

func diagnoseJSONOutput(command *cobra.Command) bool {
	if command == nil || command.Name() != "diagnose" {
		return false
	}
	format := command.Flags().Lookup("format")
	return format != nil && strings.EqualFold(strings.TrimSpace(format.Value.String()), "json")
}

func typedBoundaryError(
	err error,
	category application.ErrorCategory,
	code application.ErrorCode,
	messageID application.MessageID,
	arguments map[string]string,
) error {
	if err == nil {
		return nil
	}
	if _, ok := application.AsError(err); ok {
		return err
	}
	classified := application.ClassifyError(err)
	if classified.Category() != application.ErrorCategoryInternal {
		return classified
	}
	return application.WrapError(err, category, code, messageID, arguments)
}

func exitCodeForApplicationError(err *application.Error) int {
	if err == nil {
		return ExitInternal
	}
	if err.Code() == application.ErrorCodeOperationTimedOut {
		return ExitFailure
	}
	switch err.Category() {
	case application.ErrorCategoryValidation,
		application.ErrorCategoryConfiguration:
		return ExitInput
	case application.ErrorCategoryNetworkPolicy:
		return ExitFailure
	case application.ErrorCategoryCancelled:
		return ExitCancel
	default:
		return ExitInternal
	}
}

type errorEnvelope struct {
	Error application.ErrorView `json:"error"`
}

func writeCLIError(writer io.Writer, err error, jsonOutput bool) {
	applicationError, typed := application.AsError(err)
	if !typed && !jsonOutput {
		_, _ = fmt.Fprintln(writer, "Error:", err)
		return
	}
	if applicationError == nil {
		applicationError = application.ClassifyError(err)
	}
	if jsonOutput {
		_ = json.NewEncoder(writer).Encode(errorEnvelope{Error: applicationError.View()})
		return
	}
	_, _ = fmt.Fprintf(
		writer,
		"Error [%s]: %s\n",
		applicationError.Code(),
		applicationErrorGuidance(applicationError),
	)
}

func applicationErrorGuidance(err *application.Error) string {
	if err == nil {
		return "Internal application error. Retry; if it persists, inspect the application logs."
	}
	switch err.Code() {
	case application.ErrorCodeOperationTimedOut:
		return "Operation timed out. Retry, or increase the configured timeout."
	case "APP_REPORT_WRITE_FAILED":
		return "Report write failed. Check the destination path, permissions, and available disk space, then retry."
	case "APP_REPORT_DESTINATION_INVALID":
		return "Report destination is invalid. Choose a valid output path and try again."
	}
	switch err.Category() {
	case application.ErrorCategoryValidation:
		return "Invalid input. Correct the requested value and try again."
	case application.ErrorCategoryConfiguration:
		return "Configuration error. Correct the settings and try again."
	case application.ErrorCategoryStorage:
		return "Storage operation failed. Retry, or continue without history when available."
	case application.ErrorCategoryPermission:
		return "Permission denied. Check access to the configured files and directories."
	case application.ErrorCategoryCancelled:
		return "Operation cancelled."
	case application.ErrorCategoryNetworkPolicy:
		return "Network policy blocked the operation. Review the policy settings before retrying."
	default:
		return "Internal application error. Retry; if it persists, inspect the application logs."
	}
}

func verboseSink(writer io.Writer) model.EventSink {
	return func(event model.CheckEvent) {
		switch event.Type {
		case model.EventCheckStarted:
			_, _ = fmt.Fprintf(writer, "RUNNING  %s\n", event.CheckName)
		case model.EventCheckCompleted:
			_, _ = fmt.Fprintf(writer, "%-8s %s\n", strings.ToUpper(string(event.Status)), event.CheckName)
		}
	}
}

func writeOutput(stdout io.Writer, path string, content []byte) error {
	if path == "" || path == "-" {
		written, err := stdout.Write(content)
		if err != nil {
			return fmt.Errorf("write report to stdout: %w", err)
		}
		if written != len(content) {
			return fmt.Errorf("write report to stdout: %w", io.ErrShortWrite)
		}
		return nil
	}

	if err := secureio.WriteFile(path, content); err != nil {
		return fmt.Errorf("write report output: %w", err)
	}
	return nil
}

func newVersion(info buildinfo.Info) *cobra.Command {
	jsonOutput := false
	command := &cobra.Command{
		Use:   "version",
		Short: "Print application build information",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 0 {
				return &ExitError{Code: ExitInput, Err: errors.New("version does not accept positional arguments")}
			}
			return nil
		},
		RunE: func(command *cobra.Command, _ []string) error {
			if jsonOutput {
				encoder := json.NewEncoder(command.OutOrStdout())
				encoder.SetIndent("", "  ")
				if err := encoder.Encode(info); err != nil {
					return &ExitError{Code: ExitInternal, Err: fmt.Errorf("encode version: %w", err)}
				}
				return nil
			}
			_, err := fmt.Fprintf(
				command.OutOrStdout(),
				"Orynelo %s\ncommit: %s\nbuilt: %s\ndirty: %t\ngo: %s\nplatform: %s/%s\n",
				info.Version,
				info.Commit,
				info.BuildDate,
				info.Dirty,
				info.GoVersion,
				info.OS,
				info.Arch,
			)
			if err != nil {
				return &ExitError{Code: ExitInternal, Err: fmt.Errorf("write version: %w", err)}
			}
			return nil
		},
	}
	command.Flags().BoolVar(&jsonOutput, "json", false, "Print build information as JSON")
	return command
}

func newCompletion(root *cobra.Command) *cobra.Command {
	command := &cobra.Command{
		Use:   "completion [bash|zsh|fish]",
		Short: "Generate a shell completion script",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return &ExitError{Code: ExitInput, Err: errors.New("completion requires one shell: bash, zsh, or fish")}
			}
			return nil
		},
		ValidArgs:             []string{"bash", "zsh", "fish"},
		DisableFlagsInUseLine: true,
		RunE: func(command *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				if err := root.GenBashCompletion(command.OutOrStdout()); err != nil {
					return &ExitError{Code: ExitInternal, Err: err}
				}
				return nil
			case "zsh":
				if err := root.GenZshCompletion(command.OutOrStdout()); err != nil {
					return &ExitError{Code: ExitInternal, Err: err}
				}
				return nil
			case "fish":
				if err := root.GenFishCompletion(command.OutOrStdout(), true); err != nil {
					return &ExitError{Code: ExitInternal, Err: err}
				}
				return nil
			default:
				return &ExitError{
					Code: ExitInput,
					Err:  fmt.Errorf("unsupported shell %q; use bash, zsh, or fish", args[0]),
				}
			}
		},
	}
	return command
}
