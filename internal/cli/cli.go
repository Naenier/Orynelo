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
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Naenier/opsdoctor/internal/application"
	"github.com/Naenier/opsdoctor/internal/buildinfo"
	"github.com/Naenier/opsdoctor/internal/diagnostics"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/privacy"
	"github.com/Naenier/opsdoctor/internal/report"
	"github.com/Naenier/opsdoctor/internal/secureio"
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
	Diagnose(context.Context, model.DiagnoseOptions, model.EventSink) (model.Diagnosis, error)
	RenderReport(string, model.Diagnosis, privacy.Mode) ([]byte, error)
}

// Options configures a root command without process-global output state.
type Options struct {
	Application Application
	Build       buildinfo.Info
	Stdout      io.Writer
	Stderr      io.Writer
	SetLogLevel func(string) error
	LoadConfig  func() (application.Config, error)
	// IsConfigInvalid distinguishes user-correctable configuration errors
	// without coupling this presentation adapter to the YAML implementation.
	IsConfigInvalid func(error) bool
}

// ExitError carries a stable process code without forcing a duplicate message.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit status %d", e.Code)
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error { return e.Err }

// NewRoot builds the complete opsdoctor command tree.
func NewRoot(options Options) *cobra.Command {
	if options.Stdout == nil {
		options.Stdout = io.Discard
	}
	if options.Stderr == nil {
		options.Stderr = io.Discard
	}
	root := &cobra.Command{
		Use:           "opsdoctor",
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
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return &ExitError{Code: ExitInput, Err: err}
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
			_, _ = fmt.Fprintln(stderr, "Error:", exit.Err)
		}
		return exit.Code
	}
	if errors.Is(err, context.Canceled) {
		return ExitCancel
	}
	if diagnostics.IsInputError(err) {
		if stderr != nil {
			_, _ = fmt.Fprintln(stderr, "Error:", err)
		}
		return ExitInput
	}
	if stderr != nil {
		_, _ = fmt.Fprintln(stderr, "Error:", err)
	}
	return ExitInternal
}

type diagnoseFlags struct {
	timeout                time.Duration
	checkTimeout           time.Duration
	ipVersion              string
	format                 string
	anonymize              string
	output                 string
	noProxy                bool
	insecure               bool
	allowInsecureRedirects bool
	allowPrivateRedirects  bool
	maxRedirects           int
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
				return &ExitError{Code: ExitInput, Err: errors.New("diagnose requires exactly one target")}
			}
			return nil
		},
		RunE: func(command *cobra.Command, args []string) error {
			if options.Application == nil {
				return &ExitError{Code: ExitInternal, Err: errors.New("diagnostic application is unavailable")}
			}
			if command.Flags().Changed("log-level") {
				if !validLogLevel(flags.logLevel) {
					return &ExitError{
						Code: ExitInput,
						Err:  fmt.Errorf("log level must be debug, info, warn, or error, got %q", flags.logLevel),
					}
				}
				if options.SetLogLevel != nil {
					if err := options.SetLogLevel(flags.logLevel); err != nil {
						if options.IsConfigInvalid != nil && options.IsConfigInvalid(err) {
							return &ExitError{Code: ExitInput, Err: err}
						}
						return &ExitError{Code: ExitInternal, Err: err}
					}
				}
			}
			if options.LoadConfig != nil {
				cfg, err := options.LoadConfig()
				if err != nil {
					if options.IsConfigInvalid != nil && options.IsConfigInvalid(err) {
						return &ExitError{Code: ExitInput, Err: err}
					}
					return &ExitError{Code: ExitInternal, Err: err}
				}
				if !command.Flags().Changed("timeout") {
					flags.timeout = cfg.Diagnostics.DefaultTimeout
				}
				if !command.Flags().Changed("check-timeout") {
					flags.checkTimeout = cfg.Diagnostics.CheckTimeout
				}
				if !command.Flags().Changed("ip-version") {
					flags.ipVersion = cfg.Diagnostics.PreferredIPVersion
				}
				if !command.Flags().Changed("max-redirects") {
					flags.maxRedirects = cfg.Diagnostics.MaxRedirects
				}
				if !command.Flags().Changed("no-proxy") && !cfg.Network.UseSystemProxy {
					flags.noProxy = true
				}
			}
			parsedFormat, err := report.ParseFormat(flags.format)
			if err != nil {
				return &ExitError{Code: ExitInput, Err: err}
			}
			anonymization, err := privacy.ParseMode(flags.anonymize)
			if err != nil {
				return &ExitError{Code: ExitInput, Err: err}
			}
			format := string(parsedFormat)
			ipVersion, err := parseIPVersion(flags.ipVersion)
			if err != nil {
				return &ExitError{Code: ExitInput, Err: err}
			}
			method := strings.ToUpper(strings.TrimSpace(flags.method))
			switch method {
			case "GET", "HEAD", "OPTIONS":
			default:
				return &ExitError{
					Code: ExitInput,
					Err:  fmt.Errorf("method %q is not a safe diagnostic HTTP method", method),
				}
			}
			if flags.timeout <= 0 || flags.timeout > 24*time.Hour || flags.checkTimeout <= 0 {
				return &ExitError{
					Code: ExitInput,
					Err:  errors.New("global timeout must be greater than zero and at most 24h"),
				}
			}
			if flags.checkTimeout > flags.timeout {
				return &ExitError{Code: ExitInput, Err: errors.New("check timeout must not exceed global timeout")}
			}
			if flags.maxRedirects < 0 || flags.maxRedirects > 50 {
				return &ExitError{Code: ExitInput, Err: errors.New("maximum redirects must be between 0 and 50")}
			}

			diagnoseOptions := model.DefaultDiagnoseOptions(args[0])
			diagnoseOptions.Timeout = flags.timeout
			diagnoseOptions.CheckTimeout = flags.checkTimeout
			diagnoseOptions.IPVersion = ipVersion
			diagnoseOptions.NoProxy = flags.noProxy
			diagnoseOptions.Insecure = flags.insecure
			diagnoseOptions.AllowInsecureRedirects = flags.allowInsecureRedirects
			diagnoseOptions.AllowPrivateRedirects = flags.allowPrivateRedirects
			diagnoseOptions.MaxRedirects = flags.maxRedirects
			diagnoseOptions.Method = method
			if flags.verbose {
				diagnoseOptions.ReportVerbosity = model.ReportVerbosityVerbose
			}

			var sink model.EventSink
			if flags.verbose {
				sink = verboseSink(options.Stderr)
			}
			diagnosis, err := options.Application.Diagnose(command.Context(), diagnoseOptions, sink)
			if err != nil {
				if diagnostics.IsInputError(err) {
					return &ExitError{Code: ExitInput, Err: err}
				}
				if errors.Is(err, context.Canceled) || errors.Is(command.Context().Err(), context.Canceled) {
					return &ExitError{Code: ExitCancel}
				}
				return &ExitError{Code: ExitInternal, Err: err}
			}
			content, err := options.Application.RenderReport(format, diagnosis, anonymization)
			if err != nil {
				return &ExitError{Code: ExitInternal, Err: err}
			}
			if err := writeOutput(options.Stdout, flags.output, content); err != nil {
				return &ExitError{Code: ExitInternal, Err: err}
			}
			if flags.output != "" && flags.output != "-" {
				destination, err := filepath.Abs(filepath.Clean(flags.output))
				if err != nil {
					return &ExitError{Code: ExitInternal, Err: fmt.Errorf("resolve report output path: %w", err)}
				}
				message := fmt.Sprintf("Report saved atomically to %s\n", destination)
				written, err := io.WriteString(options.Stderr, message)
				if err != nil {
					return &ExitError{Code: ExitInternal, Err: fmt.Errorf("write report destination: %w", err)}
				}
				if written != len(message) {
					return &ExitError{Code: ExitInternal, Err: fmt.Errorf("write report destination: %w", io.ErrShortWrite)}
				}
			}
			if errors.Is(command.Context().Err(), context.Canceled) ||
				diagnosis.Summary.Status == model.StatusCancelled {
				return &ExitError{Code: ExitCancel}
			}
			if diagnosis.Summary.Status == model.StatusFailed {
				return &ExitError{Code: ExitFailure}
			}
			return nil
		},
	}
	command.Flags().DurationVar(&flags.timeout, "timeout", 15*time.Second, "Global diagnostic timeout")
	command.Flags().DurationVar(&flags.checkTimeout, "check-timeout", 5*time.Second, "Timeout for an individual check")
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
	command.Flags().IntVar(&flags.maxRedirects, "max-redirects", 10, "Maximum HTTP redirects")
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

func parseIPVersion(value string) (model.IPVersion, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "auto":
		return model.IPVersionAuto, nil
	case "4", "ipv4":
		return model.IPVersion4, nil
	case "6", "ipv6":
		return model.IPVersion6, nil
	default:
		return "", fmt.Errorf("IP version must be auto, 4, or 6, got %q", value)
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
				"OpsDoctor %s\ncommit: %s\nbuilt: %s\ndirty: %t\ngo: %s\nplatform: %s/%s\n",
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
