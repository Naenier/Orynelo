// Package localization provides user-interface strings without coupling the
// application to a particular translation framework.
package localization

import "strings"

// Key identifies a user-facing string.
type Key string

const (
	AppName Key = "app.name"

	NavigationDiagnose Key = "navigation.diagnose"
	NavigationHistory  Key = "navigation.history"
	NavigationProfiles Key = "navigation.profiles"
	NavigationSettings Key = "navigation.settings"
	NavigationAbout    Key = "navigation.about"

	CommonTarget           Key = "common.target"
	CommonMode             Key = "common.mode"
	CommonIP               Key = "common.ip"
	CommonTimeout          Key = "common.timeout"
	CommonPerCheckTimeout  Key = "common.per_check_timeout"
	CommonMaximumRedirects Key = "common.maximum_redirects"
	CommonHTTPMethod       Key = "common.http_method"
	CommonDisableProxy     Key = "common.disable_proxy"
	CommonSave             Key = "common.save"
	CommonCancel           Key = "common.cancel"
	CommonRefresh          Key = "common.refresh"
	CommonOpen             Key = "common.open"
	CommonRerun            Key = "common.rerun"
	CommonExport           Key = "common.export"
	CommonRun              Key = "common.run"
	CommonEdit             Key = "common.edit"
	CommonDuplicate        Key = "common.duplicate"
	CommonDelete           Key = "common.delete"
	CommonYes              Key = "common.yes"
	CommonNo               Key = "common.no"
	CommonUnavailable      Key = "common.unavailable"
	CommonListItemFormat   Key = "common.list_item_format"

	OptionAuto     Key = "option.auto"
	OptionTCP      Key = "option.tcp"
	OptionTLS      Key = "option.tls"
	OptionIPv4     Key = "option.ipv4"
	OptionIPv6     Key = "option.ipv6"
	OptionIP4Value Key = "option.ip4_value"
	OptionIP6Value Key = "option.ip6_value"
	OptionGET      Key = "option.get"
	OptionHEAD     Key = "option.head"
	OptionOPTIONS  Key = "option.options"
	OptionNormal   Key = "option.normal"
	OptionVerbose  Key = "option.verbose"
	OptionSystem   Key = "option.system"
	OptionLight    Key = "option.light"
	OptionDark     Key = "option.dark"
	OptionDebug    Key = "option.debug"
	OptionInfo     Key = "option.info"
	OptionWarn     Key = "option.warn"
	OptionError    Key = "option.error"

	StatusPending   Key = "status.pending"
	StatusRunning   Key = "status.running"
	StatusPassed    Key = "status.passed"
	StatusWarning   Key = "status.warning"
	StatusFailed    Key = "status.failed"
	StatusSkipped   Key = "status.skipped"
	StatusCancelled Key = "status.cancelled"

	HeaderReady           Key = "header.ready"
	HeaderDevelopment     Key = "header.development"
	HeaderRunning         Key = "header.running"
	HeaderCancelling      Key = "header.cancelling"
	HeaderCancelled       Key = "header.cancelled"
	HeaderError           Key = "header.error"
	HeaderStatusVersion   Key = "header.status_version"
	HeaderCompletedFormat Key = "header.completed_format"

	DiagnoseTargetPlaceholder         Key = "diagnose.target_placeholder"
	DiagnoseDefaultTimeout            Key = "diagnose.default_timeout"
	DiagnoseDefaultCheckTimeout       Key = "diagnose.default_check_timeout"
	DiagnoseDefaultMaxRedirects       Key = "diagnose.default_max_redirects"
	DiagnoseZeroDuration              Key = "diagnose.zero_duration"
	DiagnoseInsecureTLS               Key = "diagnose.insecure_tls"
	DiagnoseReportVerbosity           Key = "diagnose.report_verbosity"
	DiagnoseRun                       Key = "diagnose.run"
	DiagnoseAdvancedOptions           Key = "diagnose.advanced_options"
	DiagnosePreparing                 Key = "diagnose.preparing"
	DiagnoseReadyTitle                Key = "diagnose.ready_title"
	DiagnoseReadyDetail               Key = "diagnose.ready_detail"
	DiagnoseCheckNotStarted           Key = "diagnose.check_not_started"
	DiagnoseCheck                     Key = "diagnose.check"
	DiagnoseShortResult               Key = "diagnose.short_result"
	DiagnoseSelectStep                Key = "diagnose.select_step"
	DiagnoseNoEvidenceSelected        Key = "diagnose.no_evidence_selected"
	DiagnoseNoRecommendationsSelected Key = "diagnose.no_recommendations_selected"
	DiagnoseCopyStep                  Key = "diagnose.copy_step"
	DiagnoseSummary                   Key = "diagnose.summary"
	DiagnoseEvidence                  Key = "diagnose.evidence"
	DiagnoseRecommendations           Key = "diagnose.recommendations"
	DiagnoseTechnicalDetails          Key = "diagnose.technical_details"
	DiagnoseRawStructuredData         Key = "diagnose.raw_structured_data"
	DiagnoseDiagnosticSteps           Key = "diagnose.diagnostic_steps"
	DiagnoseTimelineSubtitle          Key = "diagnose.timeline_subtitle"
	DiagnoseSelectedStepDetails       Key = "diagnose.selected_step_details"
	DiagnoseRunAgain                  Key = "diagnose.run_again"
	DiagnoseCopySummary               Key = "diagnose.copy_summary"
	DiagnoseExportJSON                Key = "diagnose.export_json"
	DiagnoseExportMarkdown            Key = "diagnose.export_markdown"
	DiagnoseSaveAsProfile             Key = "diagnose.save_as_profile"
	DiagnoseTimingWaterfall           Key = "diagnose.timing_waterfall"
	DiagnoseTimingSubtitle            Key = "diagnose.timing_subtitle"
	DiagnoseInvalidTimeout            Key = "diagnose.invalid_timeout"
	DiagnoseInvalidCheckTimeout       Key = "diagnose.invalid_check_timeout"
	DiagnoseInvalidRedirects          Key = "diagnose.invalid_redirects"
	DiagnoseTargetRequired            Key = "diagnose.target_required"
	DiagnoseRunningTitle              Key = "diagnose.running_title"
	DiagnoseRunningDetail             Key = "diagnose.running_detail"
	DiagnoseCouldNotComplete          Key = "diagnose.could_not_complete"
	DiagnoseCancelledTitle            Key = "diagnose.cancelled_title"
	DiagnoseTimingFormat              Key = "diagnose.timing_format"
	DiagnoseNoEvidenceRecorded        Key = "diagnose.no_evidence_recorded"
	DiagnoseNoRecommendationsRecorded Key = "diagnose.no_recommendations_recorded"
	DiagnoseCheckRunning              Key = "diagnose.check_running"

	TimingDNS              Key = "timing.dns"
	TimingTCP              Key = "timing.tcp"
	TimingTLS              Key = "timing.tls"
	TimingTTFB             Key = "timing.ttfb"
	TimingTotal            Key = "timing.total"
	TimingWaiting          Key = "timing.waiting"
	TimingNoData           Key = "timing.no_data"
	TimingPercentFormat    Key = "timing.percent_format"
	StatusAccessibleFormat Key = "status.accessible_format"

	HistorySearchPlaceholder   Key = "history.search_placeholder"
	HistoryFilterAll           Key = "history.filter_all"
	HistoryFilterPassed        Key = "history.filter_passed"
	HistoryFilterWarning       Key = "history.filter_warning"
	HistoryFilterFailed        Key = "history.filter_failed"
	HistoryFilterCancelled     Key = "history.filter_cancelled"
	HistoryNewestFirst         Key = "history.newest_first"
	HistoryOldestFirst         Key = "history.oldest_first"
	HistoryNoOverallStatus     Key = "history.no_overall_status"
	HistoryCell                Key = "history.cell"
	HistoryOverallStatusFormat Key = "history.overall_status_format"
	HistoryColumnDate          Key = "history.column_date"
	HistoryColumnTarget        Key = "history.column_target"
	HistoryColumnOverallStatus Key = "history.column_overall_status"
	HistoryColumnDuration      Key = "history.column_duration"
	HistoryColumnVersion       Key = "history.column_version"
	HistoryDeleteSelected      Key = "history.delete_selected"
	HistoryClear               Key = "history.clear"
	HistoryLoadErrorPrefix     Key = "history.load_error_prefix"
	HistorySelectFirst         Key = "history.select_first"
	HistoryDeleteTitle         Key = "history.delete_title"
	HistoryDeleteBody          Key = "history.delete_body"
	HistoryDeleteErrorPrefix   Key = "history.delete_error_prefix"
	HistoryClearTitle          Key = "history.clear_title"
	HistoryClearBody           Key = "history.clear_body"

	ProfilesSearchPlaceholder    Key = "profiles.search_placeholder"
	ProfilesProfile              Key = "profiles.profile"
	ProfilesTarget               Key = "profiles.target"
	ProfilesSettings             Key = "profiles.settings"
	ProfilesSummaryFormat        Key = "profiles.summary_format"
	ProfilesCreate               Key = "profiles.create"
	ProfilesDelete               Key = "profiles.delete"
	ProfilesDuplicateErrorPrefix Key = "profiles.duplicate_error_prefix"
	ProfilesLoadErrorPrefix      Key = "profiles.load_error_prefix"
	ProfilesSelectFirst          Key = "profiles.select_first"
	ProfilesCopySuffix           Key = "profiles.copy_suffix"
	ProfilesDeleteTitle          Key = "profiles.delete_title"
	ProfilesDeleteBodyFormat     Key = "profiles.delete_body_format"
	ProfilesDeleteErrorPrefix    Key = "profiles.delete_error_prefix"
	ProfilesCreateTitle          Key = "profiles.create_title"
	ProfilesEditTitle            Key = "profiles.edit_title"
	ProfilesName                 Key = "profiles.name"
	ProfilesIPPreference         Key = "profiles.ip_preference"
	ProfilesProxy                Key = "profiles.proxy"
	ProfilesInvalidTimeout       Key = "profiles.invalid_timeout"
	ProfilesInvalidCheckTimeout  Key = "profiles.invalid_check_timeout"
	ProfilesInvalidRedirects     Key = "profiles.invalid_redirects"
	ProfilesRequiredFields       Key = "profiles.required_fields"
	ProfilesNameTargetRequired   Key = "profiles.name_target_required"
	ProfilesInvalidIPFormat      Key = "profiles.invalid_ip_format"

	SettingsUseSystemProxy        Key = "settings.use_system_proxy"
	SettingsSaveHistory           Key = "settings.save_history"
	SettingsSave                  Key = "settings.save"
	SettingsSaveErrorPrefix       Key = "settings.save_error_prefix"
	SettingsSaved                 Key = "settings.saved"
	SettingsOpenLogDirectory      Key = "settings.open_log_directory"
	SettingsOpenLogErrorPrefix    Key = "settings.open_log_error_prefix"
	SettingsDiagnostics           Key = "settings.diagnostics"
	SettingsDefaultTimeout        Key = "settings.default_timeout"
	SettingsPreferredIPVersion    Key = "settings.preferred_ip_version"
	SettingsCertificateWarning    Key = "settings.certificate_warning"
	SettingsNetwork               Key = "settings.network"
	SettingsUserAgent             Key = "settings.user_agent"
	SettingsMaximumEntries        Key = "settings.maximum_entries"
	SettingsAppearance            Key = "settings.appearance"
	SettingsLogging               Key = "settings.logging"
	SettingsLogLevel              Key = "settings.log_level"
	SettingsPrivacy               Key = "settings.privacy"
	SettingsInvalidDefaultTimeout Key = "settings.invalid_default_timeout"
	SettingsInvalidCheckTimeout   Key = "settings.invalid_check_timeout"
	SettingsInvalidRedirects      Key = "settings.invalid_redirects"
	SettingsInvalidCertificate    Key = "settings.invalid_certificate"
	SettingsInvalidHistoryLimit   Key = "settings.invalid_history_limit"
	PrivacyNoTelemetry            Key = "privacy.no_telemetry"
	PrivacyDataRemainsOnDevice    Key = "privacy.local_data"

	AboutVersion                  Key = "about.version"
	AboutGitCommit                Key = "about.git_commit"
	AboutBuildDate                Key = "about.build_date"
	AboutDirtyTree                Key = "about.dirty_tree"
	AboutGoVersion                Key = "about.go_version"
	AboutPlatform                 Key = "about.platform"
	AboutPlatformFormat           Key = "about.platform_format"
	AboutLicense                  Key = "about.license"
	AboutLicenseMIT               Key = "about.license_mit"
	AboutAcknowledgementsMarkdown Key = "about.acknowledgements_markdown"
	AboutSubtitle                 Key = "about.subtitle"
	AboutBuildInformation         Key = "about.build_information"
	AboutSourceRepository         Key = "about.source_repository"
	AboutAcknowledgements         Key = "about.acknowledgements"

	DialogNoCompletedDiagnosis    Key = "dialog.no_completed_diagnosis"
	DialogRunBeforeExporting      Key = "dialog.run_before_exporting"
	DialogRunBeforeSavingProfile  Key = "dialog.run_before_saving_profile"
	DialogReportFilenameBase      Key = "dialog.report_filename_base"
	DialogRawStructuredData       Key = "dialog.raw_structured_data"
	DialogLogDirectoryUnavailable Key = "dialog.log_directory_unavailable"

	TechnicalJSONEncodingError         Key = "technical.json_encoding_error"
	TechnicalCheckIDFormat             Key = "technical.check_id_format"
	TechnicalStatusFormat              Key = "technical.status_format"
	TechnicalErrorCodeFormat           Key = "technical.error_code_format"
	TechnicalEvidenceCountFormat       Key = "technical.evidence_count_format"
	TechnicalRecommendationCountFormat Key = "technical.recommendation_count_format"

	ThemeUnknownAppearanceFormat Key = "theme.unknown_appearance_format"
)

// Catalog resolves localized strings.
type Catalog interface {
	Text(Key) string
}

// English is the first-version built-in catalog.
type English struct{}

// Normalize returns the supplied catalog or the built-in English catalog.
func Normalize(catalog Catalog) Catalog {
	if catalog == nil {
		return English{}
	}
	return catalog
}

// StatusKey maps a domain status value to its localized display key.
func StatusKey(status string) Key {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running":
		return StatusRunning
	case "passed":
		return StatusPassed
	case "warning":
		return StatusWarning
	case "failed":
		return StatusFailed
	case "skipped":
		return StatusSkipped
	case "cancelled":
		return StatusCancelled
	default:
		return StatusPending
	}
}

// Text resolves an English user-interface string.
func (English) Text(key Key) string {
	if text, ok := english[key]; ok {
		return text
	}
	return string(key)
}

var english = map[Key]string{
	AppName: "OpsDoctor",

	NavigationDiagnose: "Diagnose",
	NavigationHistory:  "History",
	NavigationProfiles: "Profiles",
	NavigationSettings: "Settings",
	NavigationAbout:    "About",

	CommonTarget:           "Target",
	CommonMode:             "Mode",
	CommonIP:               "IP",
	CommonTimeout:          "Timeout",
	CommonPerCheckTimeout:  "Per-check timeout",
	CommonMaximumRedirects: "Maximum redirects",
	CommonHTTPMethod:       "HTTP method",
	CommonDisableProxy:     "Disable proxy",
	CommonSave:             "Save",
	CommonCancel:           "Cancel",
	CommonRefresh:          "Refresh",
	CommonOpen:             "Open",
	CommonRerun:            "Rerun",
	CommonExport:           "Export",
	CommonRun:              "Run",
	CommonEdit:             "Edit",
	CommonDuplicate:        "Duplicate",
	CommonDelete:           "Delete…",
	CommonYes:              "yes",
	CommonNo:               "no",
	CommonUnavailable:      "—",
	CommonListItemFormat:   "• %s",

	OptionAuto:     "Auto",
	OptionTCP:      "TCP",
	OptionTLS:      "TLS",
	OptionIPv4:     "IPv4",
	OptionIPv6:     "IPv6",
	OptionIP4Value: "4",
	OptionIP6Value: "6",
	OptionGET:      "GET",
	OptionHEAD:     "HEAD",
	OptionOPTIONS:  "OPTIONS",
	OptionNormal:   "Normal",
	OptionVerbose:  "Verbose",
	OptionSystem:   "system",
	OptionLight:    "light",
	OptionDark:     "dark",
	OptionDebug:    "debug",
	OptionInfo:     "info",
	OptionWarn:     "warn",
	OptionError:    "error",

	StatusPending:   "PENDING",
	StatusRunning:   "RUNNING",
	StatusPassed:    "PASSED",
	StatusWarning:   "WARNING",
	StatusFailed:    "FAILED",
	StatusSkipped:   "SKIPPED",
	StatusCancelled: "CANCELLED",

	HeaderReady:           "Ready",
	HeaderDevelopment:     "dev",
	HeaderRunning:         "Running",
	HeaderCancelling:      "Cancelling",
	HeaderCancelled:       "Cancelled",
	HeaderError:           "Error",
	HeaderStatusVersion:   "%s · %s",
	HeaderCompletedFormat: "Completed: %s",

	DiagnoseTargetPlaceholder:         "https://example.com or host:port",
	DiagnoseDefaultTimeout:            "15s",
	DiagnoseDefaultCheckTimeout:       "5s",
	DiagnoseDefaultMaxRedirects:       "10",
	DiagnoseZeroDuration:              "0ms",
	DiagnoseInsecureTLS:               "Insecure TLS (verification disabled)",
	DiagnoseReportVerbosity:           "Report verbosity",
	DiagnoseRun:                       "Run diagnostics",
	DiagnoseAdvancedOptions:           "Advanced options",
	DiagnosePreparing:                 "Preparing diagnostic view…",
	DiagnoseReadyTitle:                "Ready to diagnose",
	DiagnoseReadyDetail:               "Enter a target and run diagnostics.",
	DiagnoseCheckNotStarted:           "Check has not started.",
	DiagnoseCheck:                     "Check",
	DiagnoseShortResult:               "Short result",
	DiagnoseSelectStep:                "Select a diagnostic step",
	DiagnoseNoEvidenceSelected:        "No evidence selected.",
	DiagnoseNoRecommendationsSelected: "No recommendations selected.",
	DiagnoseCopyStep:                  "Copy step details",
	DiagnoseSummary:                   "Summary",
	DiagnoseEvidence:                  "Evidence",
	DiagnoseRecommendations:           "Recommendations",
	DiagnoseTechnicalDetails:          "Technical details",
	DiagnoseRawStructuredData:         "Raw structured data",
	DiagnoseDiagnosticSteps:           "Diagnostic steps",
	DiagnoseTimelineSubtitle:          "Ordered timeline with status text",
	DiagnoseSelectedStepDetails:       "Selected step details",
	DiagnoseRunAgain:                  "Run again",
	DiagnoseCopySummary:               "Copy summary",
	DiagnoseExportJSON:                "Export JSON",
	DiagnoseExportMarkdown:            "Export Markdown",
	DiagnoseSaveAsProfile:             "Save as profile",
	DiagnoseTimingWaterfall:           "Timing waterfall",
	DiagnoseTimingSubtitle:            "DNS, TCP, TLS, TTFB, and total",
	DiagnoseInvalidTimeout:            "timeout must be a positive Go duration such as 15s",
	DiagnoseInvalidCheckTimeout:       "per-check timeout must be a positive Go duration such as 5s",
	DiagnoseInvalidRedirects:          "maximum redirects must be between 0 and 50",
	DiagnoseTargetRequired:            "target is required",
	DiagnoseRunningTitle:              "Diagnostics running…",
	DiagnoseRunningDetail:             "Checks will appear as they complete.",
	DiagnoseCouldNotComplete:          "Diagnostics could not be completed",
	DiagnoseCancelledTitle:            "Diagnostics cancelled",
	DiagnoseTimingFormat:              "Started: %s\nFinished: %s\nDuration: %s",
	DiagnoseNoEvidenceRecorded:        "No evidence was recorded.",
	DiagnoseNoRecommendationsRecorded: "No recommendations were recorded.",
	DiagnoseCheckRunning:              "Check is running.",

	TimingDNS:              "DNS",
	TimingTCP:              "TCP",
	TimingTLS:              "TLS",
	TimingTTFB:             "TTFB",
	TimingTotal:            "Total",
	TimingWaiting:          "Timing data will appear after the request.",
	TimingNoData:           "No timing data is available.",
	TimingPercentFormat:    "%s  %s  (%.0f%% of total)",
	StatusAccessibleFormat: "%s — %s",

	HistorySearchPlaceholder:   "Search by target",
	HistoryFilterAll:           "all",
	HistoryFilterPassed:        "passed",
	HistoryFilterWarning:       "warning",
	HistoryFilterFailed:        "failed",
	HistoryFilterCancelled:     "cancelled",
	HistoryNewestFirst:         "newest first",
	HistoryOldestFirst:         "oldest first",
	HistoryNoOverallStatus:     "No overall diagnosis status.",
	HistoryCell:                "cell",
	HistoryOverallStatusFormat: "Overall diagnosis status: %s",
	HistoryColumnDate:          "Date",
	HistoryColumnTarget:        "Target",
	HistoryColumnOverallStatus: "Overall status",
	HistoryColumnDuration:      "Duration",
	HistoryColumnVersion:       "Version",
	HistoryDeleteSelected:      "Delete selected…",
	HistoryClear:               "Clear history…",
	HistoryLoadErrorPrefix:     "History could not be loaded: ",
	HistorySelectFirst:         "Select a history entry first.",
	HistoryDeleteTitle:         "Delete diagnostic history entry?",
	HistoryDeleteBody:          "This removes the selected local diagnosis. This action cannot be undone.",
	HistoryDeleteErrorPrefix:   "History entry was not deleted: ",
	HistoryClearTitle:          "Clear diagnostic history?",
	HistoryClearBody:           "This permanently removes every locally stored diagnostic run.",

	ProfilesSearchPlaceholder:    "Search profiles",
	ProfilesProfile:              "Profile",
	ProfilesTarget:               "target",
	ProfilesSettings:             "settings",
	ProfilesSummaryFormat:        "Mode %s · IP %s · %s",
	ProfilesCreate:               "Create profile",
	ProfilesDelete:               "Delete…",
	ProfilesDuplicateErrorPrefix: "Profile was not duplicated: ",
	ProfilesLoadErrorPrefix:      "Profiles could not be loaded: ",
	ProfilesSelectFirst:          "Select a profile first.",
	ProfilesCopySuffix:           " copy",
	ProfilesDeleteTitle:          "Delete profile?",
	ProfilesDeleteBodyFormat:     "Delete profile %q? Stored diagnostics are not affected.",
	ProfilesDeleteErrorPrefix:    "Profile was not deleted: ",
	ProfilesCreateTitle:          "Create profile",
	ProfilesEditTitle:            "Edit profile",
	ProfilesName:                 "Profile name",
	ProfilesIPPreference:         "IP preference",
	ProfilesProxy:                "Proxy",
	ProfilesInvalidTimeout:       "profile timeout must be a positive duration",
	ProfilesInvalidCheckTimeout:  "profile per-check timeout must be a positive duration",
	ProfilesInvalidRedirects:     "profile maximum redirects must be between 0 and 50",
	ProfilesRequiredFields:       "profile name, target, and a valid IP preference are required",
	ProfilesNameTargetRequired:   "profile name and target are required",
	ProfilesInvalidIPFormat:      "invalid profile IP preference %q",

	SettingsUseSystemProxy:        "Use system proxy settings",
	SettingsSaveHistory:           "Save diagnostic history",
	SettingsSave:                  "Save settings",
	SettingsSaveErrorPrefix:       "Settings were not saved: ",
	SettingsSaved:                 "Settings saved.",
	SettingsOpenLogDirectory:      "Open log directory",
	SettingsOpenLogErrorPrefix:    "Log directory could not be opened: ",
	SettingsDiagnostics:           "Diagnostics",
	SettingsDefaultTimeout:        "Default timeout",
	SettingsPreferredIPVersion:    "Preferred IP version",
	SettingsCertificateWarning:    "Certificate warning",
	SettingsNetwork:               "Network",
	SettingsUserAgent:             "User agent",
	SettingsMaximumEntries:        "Maximum entries",
	SettingsAppearance:            "Appearance",
	SettingsLogging:               "Logging",
	SettingsLogLevel:              "Log level",
	SettingsPrivacy:               "Privacy",
	SettingsInvalidDefaultTimeout: "default timeout: %w",
	SettingsInvalidCheckTimeout:   "per-check timeout: %w",
	SettingsInvalidRedirects:      "maximum redirects: %w",
	SettingsInvalidCertificate:    "certificate warning threshold: %w",
	SettingsInvalidHistoryLimit:   "history limit: %w",
	PrivacyNoTelemetry:            "OpsDoctor does not send telemetry.",
	PrivacyDataRemainsOnDevice:    "Diagnostic data remains on this computer.",

	AboutVersion:                  "Version",
	AboutGitCommit:                "Git commit",
	AboutBuildDate:                "Build date",
	AboutDirtyTree:                "Dirty tree",
	AboutGoVersion:                "Go version",
	AboutPlatform:                 "Platform",
	AboutPlatformFormat:           "%s/%s",
	AboutLicense:                  "License",
	AboutLicenseMIT:               "MIT",
	AboutAcknowledgementsMarkdown: "OpsDoctor is built with [Go](https://go.dev/), [Fyne](https://fyne.io/), [Cobra](https://cobra.dev/), and [modernc SQLite](https://pkg.go.dev/modernc.org/sqlite).",
	AboutSubtitle:                 "Evidence-based network reachability diagnostics.",
	AboutBuildInformation:         "Build information",
	AboutSourceRepository:         "Source repository",
	AboutAcknowledgements:         "Open-source acknowledgements",

	DialogNoCompletedDiagnosis:    "No completed diagnosis",
	DialogRunBeforeExporting:      "Run or open a diagnosis before exporting.",
	DialogRunBeforeSavingProfile:  "Run a diagnosis before saving a profile.",
	DialogReportFilenameBase:      "opsdoctor-report",
	DialogRawStructuredData:       "Raw structured data",
	DialogLogDirectoryUnavailable: "log directory is unavailable",

	TechnicalJSONEncodingError:         "technical details could not be encoded",
	TechnicalCheckIDFormat:             "Check ID: %s",
	TechnicalStatusFormat:              "Status: %s",
	TechnicalErrorCodeFormat:           "Error code: %s",
	TechnicalEvidenceCountFormat:       "Evidence records: %d",
	TechnicalRecommendationCountFormat: "Recommendation records: %d",

	ThemeUnknownAppearanceFormat: "unknown appearance %q",
}
