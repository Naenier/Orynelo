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
	CommonLoading          Key = "common.loading"
	CommonSaving           Key = "common.saving"

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

	StatusPending       Key = "status.pending"
	StatusRunning       Key = "status.running"
	StatusPassed        Key = "status.passed"
	StatusWarning       Key = "status.warning"
	StatusFailed        Key = "status.failed"
	StatusSkipped       Key = "status.skipped"
	StatusNotApplicable Key = "status.not_applicable"
	StatusCancelled     Key = "status.cancelled"

	HeaderReady           Key = "header.ready"
	HeaderDevelopment     Key = "header.development"
	HeaderRunning         Key = "header.running"
	HeaderCancelling      Key = "header.cancelling"
	HeaderCancelled       Key = "header.cancelled"
	HeaderError           Key = "header.error"
	HeaderStatusVersion   Key = "header.status_version"
	HeaderCompletedFormat Key = "header.completed_format"
	HeaderLastRunFormat   Key = "header.last_run_format"

	DiagnoseTargetPlaceholder         Key = "diagnose.target_placeholder"
	DiagnoseRunShortcutHint           Key = "diagnose.run_shortcut_hint"
	DiagnoseDefaultTimeout            Key = "diagnose.default_timeout"
	DiagnoseDefaultCheckTimeout       Key = "diagnose.default_check_timeout"
	DiagnoseDefaultMaxRedirects       Key = "diagnose.default_max_redirects"
	DiagnoseZeroDuration              Key = "diagnose.zero_duration"
	DiagnoseInsecureTLS               Key = "diagnose.insecure_tls"
	DiagnoseAllowInsecureRedirects    Key = "diagnose.allow_insecure_redirects"
	DiagnoseAllowPrivateRedirects     Key = "diagnose.allow_private_redirects"
	DiagnoseReportVerbosity           Key = "diagnose.report_verbosity"
	DiagnoseRun                       Key = "diagnose.run"
	DiagnoseAdvancedOptions           Key = "diagnose.advanced_options"
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
	DiagnoseIdleHint                  Key = "diagnose.idle_hint"
	DiagnoseTargetFormat              Key = "diagnose.target_format"
	DiagnoseRecommendedNextStep       Key = "diagnose.recommended_next_step"
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
	TimingNotMeasured      Key = "timing.not_measured"
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
	HistoryEmptyTitle          Key = "history.empty_title"
	HistoryEmptyHint           Key = "history.empty_hint"
	HistoryNoMatchesTitle      Key = "history.no_matches_title"
	HistoryNoMatchesHint       Key = "history.no_matches_hint"
	HistoryClearFilters        Key = "history.clear_filters"

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
	ProfilesEmptyTitle           Key = "profiles.empty_title"
	ProfilesEmptyHint            Key = "profiles.empty_hint"
	ProfilesNoMatchesTitle       Key = "profiles.no_matches_title"
	ProfilesNoMatchesHint        Key = "profiles.no_matches_hint"
	ProfilesClearSearch          Key = "profiles.clear_search"

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
	SettingsDiagnosticsSubtitle   Key = "settings.diagnostics_subtitle"
	SettingsNetworkSubtitle       Key = "settings.network_subtitle"
	SettingsHistorySubtitle       Key = "settings.history_subtitle"
	SettingsAppearanceSubtitle    Key = "settings.appearance_subtitle"
	SettingsLoggingSubtitle       Key = "settings.logging_subtitle"
	SettingsPrivacySubtitle       Key = "settings.privacy_subtitle"
	SettingsDurationHint          Key = "settings.duration_hint"
	SettingsClearHistoryHint      Key = "settings.clear_history_hint"
	SettingsStoredLocally         Key = "settings.stored_locally"
	SettingsUnsaved               Key = "settings.unsaved"
	SettingsThemeErrorPrefix      Key = "settings.theme_error_prefix"
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
	AboutBuildState               Key = "about.build_state"
	AboutBuildClean               Key = "about.build_clean"
	AboutBuildModified            Key = "about.build_modified"
	AboutBuildSupportHint         Key = "about.build_support_hint"
	AboutCopyBuildInformation     Key = "about.copy_build_information"
	AboutBuildInformationCopied   Key = "about.build_information_copied"
	AboutProjectLinks             Key = "about.project_links"
	AboutProjectLinksSubtitle     Key = "about.project_links_subtitle"
	AboutReportIssue              Key = "about.report_issue"
	AboutViewLicense              Key = "about.view_license"

	DialogNoCompletedDiagnosis    Key = "dialog.no_completed_diagnosis"
	DialogRunBeforeExporting      Key = "dialog.run_before_exporting"
	DialogRunBeforeSavingProfile  Key = "dialog.run_before_saving_profile"
	DialogReportFilenameBase      Key = "dialog.report_filename_base"
	DialogRawStructuredData       Key = "dialog.raw_structured_data"
	DialogLogDirectoryUnavailable Key = "dialog.log_directory_unavailable"
	DialogExportPrivacyTitle      Key = "dialog.export_privacy_title"
	DialogExportPrivacyBody       Key = "dialog.export_privacy_body"
	DialogExportFilename          Key = "dialog.export_filename"
	DialogExportStandard          Key = "dialog.export_standard"
	DialogExportStrict            Key = "dialog.export_strict"
	DialogExportContinue          Key = "dialog.export_continue"
	DialogExportSavedTitle        Key = "dialog.export_saved_title"
	DialogExportSavedAtomicFormat Key = "dialog.export_saved_atomic_format"
	DialogExportSavedURIFormat    Key = "dialog.export_saved_uri_format"
	DialogExportOverwriteTitle    Key = "dialog.export_overwrite_title"
	DialogExportOverwriteFormat   Key = "dialog.export_overwrite_format"
	DialogProfileRedactedTitle    Key = "dialog.profile_redacted_title"
	DialogProfileRedactedFormat   Key = "dialog.profile_redacted_format"

	ErrorValidationGuidance    Key = "error.validation_guidance"
	ErrorConfigurationGuidance Key = "error.configuration_guidance"
	ErrorStorageGuidance       Key = "error.storage_guidance"
	ErrorPermissionGuidance    Key = "error.permission_guidance"
	ErrorCancelledGuidance     Key = "error.cancelled_guidance"
	ErrorNetworkPolicyGuidance Key = "error.network_policy_guidance"
	ErrorInternalGuidance      Key = "error.internal_guidance"
	ErrorReferenceFormat       Key = "error.reference_format"
	ErrorFieldFormat           Key = "error.field_format"

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
	case "not_applicable":
		return StatusNotApplicable
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
	CommonLoading:          "Loading…",
	CommonSaving:           "Saving…",

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
	OptionSystem:   "System",
	OptionLight:    "Light",
	OptionDark:     "Dark",
	OptionDebug:    "Debug",
	OptionInfo:     "Info",
	OptionWarn:     "Warning",
	OptionError:    "Error",

	StatusPending:       "PENDING",
	StatusRunning:       "RUNNING",
	StatusPassed:        "PASSED",
	StatusWarning:       "WARNING",
	StatusFailed:        "FAILED",
	StatusSkipped:       "SKIPPED",
	StatusNotApplicable: "NOT APPLICABLE",
	StatusCancelled:     "CANCELLED",

	HeaderReady:           "Ready",
	HeaderDevelopment:     "dev",
	HeaderRunning:         "Running",
	HeaderCancelling:      "Cancelling",
	HeaderCancelled:       "Cancelled",
	HeaderError:           "Error",
	HeaderStatusVersion:   "%s · %s",
	HeaderCompletedFormat: "Completed: %s",
	HeaderLastRunFormat:   "Last run: %s",

	DiagnoseTargetPlaceholder:         "https://example.com or host:port",
	DiagnoseRunShortcutHint:           "Ctrl+Enter to run",
	DiagnoseDefaultTimeout:            "15s",
	DiagnoseDefaultCheckTimeout:       "5s",
	DiagnoseDefaultMaxRedirects:       "10",
	DiagnoseZeroDuration:              "0ms",
	DiagnoseInsecureTLS:               "Insecure TLS (verification disabled)",
	DiagnoseAllowInsecureRedirects:    "Allow HTTPS to HTTP redirects (unsafe)",
	DiagnoseAllowPrivateRedirects:     "Allow public to private-network redirects (unsafe)",
	DiagnoseReportVerbosity:           "Report verbosity",
	DiagnoseRun:                       "Run diagnostics",
	DiagnoseAdvancedOptions:           "Advanced options",
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
	DiagnoseSelectedStepDetails:       "Selected step details",
	DiagnoseRunAgain:                  "Run again",
	DiagnoseCopySummary:               "Copy summary",
	DiagnoseExportJSON:                "Export JSON",
	DiagnoseExportMarkdown:            "Export Markdown",
	DiagnoseSaveAsProfile:             "Save as profile",
	DiagnoseTimingWaterfall:           "Timing waterfall",
	DiagnoseTimingSubtitle:            "DNS, TCP, TLS, TTFB, and total",
	DiagnoseInvalidTimeout:            "timeout must be a positive Go duration no longer than 24h, such as 15s",
	DiagnoseInvalidCheckTimeout:       "per-check timeout must be positive and no longer than the total timeout",
	DiagnoseInvalidRedirects:          "maximum redirects must be between 0 and 50",
	DiagnoseTargetRequired:            "target is required",
	DiagnoseRunningTitle:              "Diagnostics running…",
	DiagnoseRunningDetail:             "Checks will appear as they complete.",
	DiagnoseIdleHint:                  "Try a URL such as https://example.com or a socket such as host:443.",
	DiagnoseTargetFormat:              "Target: %s",
	DiagnoseRecommendedNextStep:       "Recommended next step",
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
	TimingWaiting:          "Timing data will appear as checks complete.",
	TimingNoData:           "No timing data is available.",
	TimingNotMeasured:      "Not measured",
	StatusAccessibleFormat: "%s — %s",

	HistorySearchPlaceholder:   "Search by target",
	HistoryFilterAll:           "All",
	HistoryFilterPassed:        "Passed",
	HistoryFilterWarning:       "Warning",
	HistoryFilterFailed:        "Failed",
	HistoryFilterCancelled:     "Cancelled",
	HistoryNewestFirst:         "Newest first",
	HistoryOldestFirst:         "Oldest first",
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
	HistoryEmptyTitle:          "No history entries",
	HistoryEmptyHint:           "Completed diagnostics will appear here.",
	HistoryNoMatchesTitle:      "No matching history entries",
	HistoryNoMatchesHint:       "Try another target/status filter or clear the current filters.",
	HistoryClearFilters:        "Clear filters",

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
	ProfilesInvalidCheckTimeout:  "profile per-check timeout must be positive and no longer than the total timeout",
	ProfilesInvalidRedirects:     "profile maximum redirects must be between 0 and 50",
	ProfilesRequiredFields:       "profile name, target, and a valid IP preference are required",
	ProfilesNameTargetRequired:   "profile name and target are required",
	ProfilesInvalidIPFormat:      "invalid profile IP preference %q",
	ProfilesEmptyTitle:           "No profiles yet",
	ProfilesEmptyHint:            "Create a profile to reuse diagnostic settings.",
	ProfilesNoMatchesTitle:       "No matching profiles",
	ProfilesNoMatchesHint:        "Try another search or clear the current query.",
	ProfilesClearSearch:          "Clear search",

	SettingsUseSystemProxy:        "Use proxy environment variables",
	SettingsSaveHistory:           "Save diagnostic history",
	SettingsSave:                  "Save settings",
	SettingsSaveErrorPrefix:       "Settings were not saved: ",
	SettingsSaved:                 "Settings saved.",
	SettingsOpenLogDirectory:      "Open log directory",
	SettingsOpenLogErrorPrefix:    "Log directory could not be opened: ",
	SettingsDiagnostics:           "Diagnostics",
	SettingsDefaultTimeout:        "Default timeout",
	SettingsPreferredIPVersion:    "Preferred IP version",
	SettingsCertificateWarning:    "Warn before certificate expiry",
	SettingsNetwork:               "Network",
	SettingsUserAgent:             "User agent",
	SettingsMaximumEntries:        "Maximum entries",
	SettingsAppearance:            "Appearance",
	SettingsLogging:               "Logging",
	SettingsLogLevel:              "Log level",
	SettingsPrivacy:               "Privacy",
	SettingsDiagnosticsSubtitle:   "Defaults used for new diagnostic runs",
	SettingsNetworkSubtitle:       "Connection defaults for HTTP requests",
	SettingsHistorySubtitle:       "Local diagnostic run retention",
	SettingsAppearanceSubtitle:    "Applied immediately; save to keep it",
	SettingsLoggingSubtitle:       "Tools for troubleshooting OpsDoctor",
	SettingsPrivacySubtitle:       "No accounts, cloud sync, or analytics",
	SettingsDurationHint:          "Durations accept values such as 15s, 5m, 2h, or 30d.",
	SettingsClearHistoryHint:      "Permanently delete every locally stored diagnostic run.",
	SettingsStoredLocally:         "Settings are stored on this device.",
	SettingsUnsaved:               "Unsaved changes",
	SettingsThemeErrorPrefix:      "Theme could not be applied: ",
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
	AboutBuildState:               "Build state",
	AboutBuildClean:               "Clean source tree",
	AboutBuildModified:            "Local changes included",
	AboutBuildSupportHint:         "Copy these details when reporting a problem.",
	AboutCopyBuildInformation:     "Copy build information",
	AboutBuildInformationCopied:   "Build information copied.",
	AboutProjectLinks:             "Project",
	AboutProjectLinksSubtitle:     "Source code, issue tracker, and license",
	AboutReportIssue:              "Report an issue",
	AboutViewLicense:              "View MIT license",

	DialogNoCompletedDiagnosis:    "No completed diagnosis",
	DialogRunBeforeExporting:      "Run or open a diagnosis before exporting.",
	DialogRunBeforeSavingProfile:  "Run a diagnosis before saving a profile.",
	DialogReportFilenameBase:      "opsdoctor-report",
	DialogRawStructuredData:       "Raw structured data",
	DialogLogDirectoryUnavailable: "log directory is unavailable",
	DialogExportPrivacyTitle:      "Export privacy",
	DialogExportPrivacyBody:       "Choose how much identifying context the exported report should retain.",
	DialogExportFilename:          "File name",
	DialogExportStandard:          "Standard — remove credentials and secret-like values",
	DialogExportStrict:            "Strict — also hide URL paths, query values, internal hosts/IPs, and local paths",
	DialogExportContinue:          "Continue",
	DialogExportSavedTitle:        "Export complete",
	DialogExportSavedAtomicFormat: "Report saved atomically to %s.",
	DialogExportSavedURIFormat:    "Report saved to %s. This URI provider does not guarantee atomic replacement.",
	DialogExportOverwriteTitle:    "Replace existing export?",
	DialogExportOverwriteFormat:   "An item already exists at %s. Replace it?",
	DialogProfileRedactedTitle:    "Sensitive target parts will be removed",
	DialogProfileRedactedFormat:   "For privacy, the saved profile target will be:\n\n%s\n\nThe profile may no longer work without the removed value. Save it anyway?",

	ErrorValidationGuidance:    "Check the entered values and try again.",
	ErrorConfigurationGuidance: "Review the application settings and try again.",
	ErrorStorageGuidance:       "Local data is unavailable. Retry the operation; diagnostics can continue without saved history.",
	ErrorPermissionGuidance:    "Permission was denied. Choose a writable destination and try again.",
	ErrorCancelledGuidance:     "The operation was cancelled.",
	ErrorNetworkPolicyGuidance: "Network policy blocked this operation. Review proxy and redirect settings before retrying.",
	ErrorInternalGuidance:      "The operation could not be completed. Retry it; if the problem continues, open the log directory from Settings.",
	ErrorReferenceFormat:       "Error reference: %s",
	ErrorFieldFormat:           "Check field: %s",

	TechnicalJSONEncodingError:         "technical details could not be encoded",
	TechnicalCheckIDFormat:             "Check ID: %s",
	TechnicalStatusFormat:              "Status: %s",
	TechnicalErrorCodeFormat:           "Error code: %s",
	TechnicalEvidenceCountFormat:       "Evidence records: %d",
	TechnicalRecommendationCountFormat: "Recommendation records: %d",

	ThemeUnknownAppearanceFormat: "unknown appearance %q",
}
