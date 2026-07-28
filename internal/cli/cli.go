// Package cli implements the Cobra interface over the shared application
// service.
package cli

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Naenier/opsdoctor/internal/application"
	"github.com/Naenier/opsdoctor/internal/buildinfo"
	"github.com/Naenier/opsdoctor/internal/diagnostics"
	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
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
	RenderReport(string, model.Diagnosis) ([]byte, error)
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
	timeout      time.Duration
	checkTimeout time.Duration
	ipVersion    string
	format       string
	output       string
	noProxy      bool
	insecure     bool
	maxRedirects int
	method       string
	logLevel     string
	verbose      bool
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
			format := strings.ToLower(strings.TrimSpace(flags.format))
			switch format {
			case "text", "json", "markdown":
			default:
				return &ExitError{
					Code: ExitInput,
					Err:  fmt.Errorf("format must be text, json, or markdown, got %q", flags.format),
				}
			}
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
			if flags.timeout <= 0 || flags.checkTimeout <= 0 {
				return &ExitError{Code: ExitInput, Err: errors.New("timeouts must be greater than zero")}
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
			content, err := options.Application.RenderReport(format, diagnosis)
			if err != nil {
				return &ExitError{Code: ExitInternal, Err: err}
			}
			if err := writeOutput(options.Stdout, flags.output, content); err != nil {
				return &ExitError{Code: ExitInternal, Err: err}
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
	command.Flags().StringVar(&flags.format, "format", "text", "Report format: text, json, or markdown")
	command.Flags().StringVarP(&flags.output, "output", "o", "", "Write the report to a private file instead of stdout")
	command.Flags().BoolVar(&flags.noProxy, "no-proxy", false, "Disable proxy use for this diagnosis")
	command.Flags().BoolVar(&flags.insecure, "insecure", false, "Disable TLS verification (unsafe; reported as a warning)")
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

	clean := filepath.Clean(path)
	root, err := os.OpenRoot(filepath.Dir(clean))
	if err != nil {
		return fmt.Errorf("open report output directory for %q: %w", path, err)
	}
	defer root.Close()

	name := filepath.Base(clean)
	if err := validateReportDestination(root, name, path); err != nil {
		return err
	}
	file, temporaryName, err := createReportTemporary(root)
	if err != nil {
		return fmt.Errorf("create temporary report output for %q: %w", path, err)
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = root.Remove(temporaryName)
		}
	}()

	written, writeErr := file.Write(content)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write report output %q: %w", path, writeErr)
	}
	if written != len(content) {
		return fmt.Errorf("write report output %q: %w", path, io.ErrShortWrite)
	}
	if syncErr != nil {
		return fmt.Errorf("sync report output %q: %w", path, syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close report output %q: %w", path, closeErr)
	}
	if err := validateReportDestination(root, name, path); err != nil {
		return err
	}
	if err := root.Rename(temporaryName, name); err != nil {
		return fmt.Errorf("replace report output %q: %w", path, err)
	}
	committed = true
	return nil
}

func validateReportDestination(root *os.Root, name, displayPath string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect report output %q: %w", displayPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("report output %q is a symbolic link", displayPath)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("report output %q is not a regular file", displayPath)
	}
	return nil
}

func createReportTemporary(root *os.Root) (*os.File, string, error) {
	var suffix [16]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return nil, "", err
	}
	name := fmt.Sprintf(".opsdoctor-report-%x", suffix)
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, "", err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = root.Remove(name)
		return nil, "", err
	}
	return file, name, nil
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
