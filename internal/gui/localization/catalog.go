// Package localization provides user-interface strings without coupling the
// application to a particular translation framework.
package localization

import (
	"fmt"
	"strings"
)

// Language is a persisted UI/report language preference.
type Language string

const (
	LanguageSystem  Language = "system"
	LanguageRussian Language = "ru"
	LanguageEnglish Language = "en"
)

// Key identifies a user-facing string.
type Key string

// Localization keys are stable identifiers shared by screens, components, and
// user-facing application error rendering.
const (
	AppName Key = "app.name"

	NavigationDiagnose        Key = "navigation.diagnose"
	NavigationHistory         Key = "navigation.history"
	NavigationProfiles        Key = "navigation.profiles"
	NavigationSettings        Key = "navigation.settings"
	NavigationAbout           Key = "navigation.about"
	NavigationToggle          Key = "navigation.toggle"
	MenuFile                  Key = "menu.file"
	MenuNavigate              Key = "menu.navigate"
	MenuHelp                  Key = "menu.help"
	MenuKeyboardShortcuts     Key = "menu.keyboard_shortcuts"
	MenuKeyboardShortcutsBody Key = "menu.keyboard_shortcuts_body"

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
	CommonCopy             Key = "common.copy"
	CommonMore             Key = "common.more"
	CommonStaleData        Key = "common.stale_data"

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
	OptionRussian  Key = "option.russian"
	OptionEnglish  Key = "option.english"

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
	DiagnoseAutoExplanation           Key = "diagnose.auto_explanation"
	DiagnoseTargetPreview             Key = "diagnose.target_preview"
	DiagnoseProbeMode                 Key = "diagnose.probe_mode"
	DiagnoseAddressLimit              Key = "diagnose.address_limit"
	DiagnoseMatrixBudget              Key = "diagnose.matrix_budget"
	DiagnoseExpectedStatus            Key = "diagnose.expected_status"
	DiagnoseLatencyThreshold          Key = "diagnose.latency_threshold"
	DiagnoseConnectIP                 Key = "diagnose.connect_ip"
	DiagnoseServerName                Key = "diagnose.server_name"
	DiagnoseHTTPHost                  Key = "diagnose.http_host"
	DiagnoseCABundle                  Key = "diagnose.ca_bundle"
	DiagnoseRequestHeaders            Key = "diagnose.request_headers"
	DiagnoseCollectDNSDetails         Key = "diagnose.collect_dns_details"
	DiagnoseInspectBody               Key = "diagnose.inspect_body"
	DiagnoseInvalidAddressLimit       Key = "diagnose.invalid_address_limit"
	DiagnoseInvalidMatrixBudget       Key = "diagnose.invalid_matrix_budget"
	DiagnoseInvalidExpectedStatus     Key = "diagnose.invalid_expected_status"
	DiagnoseInvalidLatencyThreshold   Key = "diagnose.invalid_latency_threshold"
	DiagnoseInvalidRequestHeaders     Key = "diagnose.invalid_request_headers"
	DiagnoseInvalidTarget             Key = "diagnose.invalid_target"
	DiagnoseTransportOptions          Key = "diagnose.transport_options"
	DiagnoseTLSOptions                Key = "diagnose.tls_options"
	DiagnoseHTTPOptions               Key = "diagnose.http_options"
	DiagnoseCertificateExplanation    Key = "diagnose.certificate_explanation"
	DiagnoseContextUnknown            Key = "diagnose.context_unknown"
	DiagnoseContextTCP                Key = "diagnose.context_tcp"
	DiagnoseContextTLS                Key = "diagnose.context_tls"
	DiagnoseContextHTTP               Key = "diagnose.context_http"
	DiagnoseContextHTTPS              Key = "diagnose.context_https"
	DiagnoseActualPathFormat          Key = "diagnose.actual_path_format"
	DiagnoseBreakPointFormat          Key = "diagnose.break_point_format"
	DiagnoseStartedFormat             Key = "diagnose.started_format"
	DiagnoseFinishedFormat            Key = "diagnose.finished_format"
	DiagnoseCopiedTitle               Key = "diagnose.copied_title"
	DiagnoseCopiedMessage             Key = "diagnose.copied_message"
	DiagnoseUnattributedEvidence      Key = "diagnose.unattributed_evidence"
	DiagnoseRedactedFact              Key = "diagnose.redacted_fact"
	DiagnoseViewFullValue             Key = "diagnose.view_full_value"
	DiagnoseEvidenceGroupFormat       Key = "diagnose.evidence_group_format"
	DiagnoseSearchJSON                Key = "diagnose.search_json"
	DiagnoseWrapJSON                  Key = "diagnose.wrap_json"
	DiagnoseSearchMatchesFormat       Key = "diagnose.search_matches_format"
	OptionClientEffective             Key = "option.client_effective"
	OptionAddressMatrix               Key = "option.address_matrix"

	TimingDNS              Key = "timing.dns"
	TimingTCP              Key = "timing.tcp"
	TimingTLS              Key = "timing.tls"
	TimingTTFB             Key = "timing.ttfb"
	TimingTotal            Key = "timing.total"
	TimingWaiting          Key = "timing.waiting"
	TimingNoData           Key = "timing.no_data"
	TimingNotMeasured      Key = "timing.not_measured"
	TimingReused           Key = "timing.reused"
	TimingAxisFormat       Key = "timing.axis_format"
	StatusAccessibleFormat Key = "status.accessible_format"

	CheckTarget                  Key = "check.target"
	CheckEnvironment             Key = "check.environment"
	CheckDNS                     Key = "check.dns"
	CheckRoute                   Key = "check.route"
	CheckTCP                     Key = "check.tcp"
	CheckTLS                     Key = "check.tls"
	CheckHTTP                    Key = "check.http"
	PathRoleClient               Key = "path.role_client"
	PathRoleMatrix               Key = "path.role_matrix"
	PathRoleAuxiliary            Key = "path.role_auxiliary"
	PathKindDirect               Key = "path.kind_direct"
	PathKindHTTPProxy            Key = "path.kind_http_proxy"
	PathKindConnect              Key = "path.kind_connect"
	HopKindOrigin                Key = "hop.kind_origin"
	HopKindProxy                 Key = "hop.kind_proxy"
	HopKindRedirect              Key = "hop.kind_redirect"
	RecommendationCheckFormat    Key = "recommendation.check_format"
	RecommendationEvidenceFormat Key = "recommendation.evidence_format"
	EvidenceKindText             Key = "evidence.kind_text"
	EvidenceKindDuration         Key = "evidence.kind_duration"
	EvidenceKindTime             Key = "evidence.kind_time"
	EvidenceKindAddress          Key = "evidence.kind_address"
	EvidenceKindCertificate      Key = "evidence.kind_certificate"
	EvidenceKindHeader           Key = "evidence.kind_header"

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
	HistoryRefreshSuccess      Key = "history.refresh_success"

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
	ProfilesRefreshSuccess       Key = "profiles.refresh_success"
	ProfilesSaveSuccessTitle     Key = "profiles.save_success_title"
	ProfilesSaveSuccessMessage   Key = "profiles.save_success_message"

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
	SettingsLanguage              Key = "settings.language"
	SettingsReportLanguage        Key = "settings.report_language"
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
	SettingsInvalidConfiguration  Key = "settings.invalid_configuration"
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
	DialogExportFilenameInvalid   Key = "dialog.export_filename_invalid"
	DialogExportStandard          Key = "dialog.export_standard"
	DialogExportStrict            Key = "dialog.export_strict"
	DialogExportContinue          Key = "dialog.export_continue"
	DialogExportLanguage          Key = "dialog.export_language"
	DialogExportSavedTitle        Key = "dialog.export_saved_title"
	DialogExportSavedAtomicFormat Key = "dialog.export_saved_atomic_format"
	DialogExportSavedURIFormat    Key = "dialog.export_saved_uri_format"
	DialogExportOverwriteTitle    Key = "dialog.export_overwrite_title"
	DialogExportOverwriteFormat   Key = "dialog.export_overwrite_format"
	DialogProfileRedactedTitle    Key = "dialog.profile_redacted_title"
	DialogProfileRedactedFormat   Key = "dialog.profile_redacted_format"

	RecoveryTitle            Key = "recovery.title"
	RecoveryIntro            Key = "recovery.intro"
	RecoveryReferenceFormat  Key = "recovery.reference_format"
	RecoveryExplanation      Key = "recovery.explanation"
	RecoveryRetry            Key = "recovery.retry"
	RecoveryContinue         Key = "recovery.continue"
	RecoveryOpenConfig       Key = "recovery.open_config"
	RecoveryOpenLogs         Key = "recovery.open_logs"
	RecoveryExit             Key = "recovery.exit"
	RecoveryVersionFormat    Key = "recovery.version_format"
	RecoveryOpenPathError    Key = "recovery.open_path_error"
	RecoveryPathUnavailable  Key = "recovery.path_unavailable"
	StartupLimitedStateTitle Key = "startup.limited_state_title"
	StartupLimitedStateIntro Key = "startup.limited_state_intro"
	StartupWarningFormat     Key = "startup.warning_format"

	PriorityCritical Key = "priority.critical"
	PriorityHigh     Key = "priority.high"
	PriorityMedium   Key = "priority.medium"
	PriorityLow      Key = "priority.low"

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

// ResolveLanguage resolves a persisted preference against an OS locale.
func ResolveLanguage(preference Language, systemLocale string) Language {
	if preference == LanguageRussian || preference == LanguageEnglish {
		return preference
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(systemLocale)), "ru") {
		return LanguageRussian
	}
	return LanguageEnglish
}

// ForLanguage returns a complete built-in catalog for a resolved language.
func ForLanguage(language Language) Catalog {
	if language == LanguageRussian {
		return Russian{}
	}
	return English{}
}

// LanguageOf reports the language of a built-in catalog.
func LanguageOf(catalog Catalog) Language {
	switch catalog.(type) {
	case Russian, *Russian:
		return LanguageRussian
	default:
		return LanguageEnglish
	}
}

// ValidateBuiltins verifies exact key parity and non-empty translations.
func ValidateBuiltins() error {
	if len(english) != len(russian) {
		return fmt.Errorf("catalog key count differs: en=%d ru=%d", len(english), len(russian))
	}
	for key, en := range english {
		ru, ok := russian[key]
		if !ok {
			return fmt.Errorf("Russian catalog is missing %q", key)
		}
		if strings.TrimSpace(en) == "" || strings.TrimSpace(ru) == "" {
			return fmt.Errorf("empty translation for %q", key)
		}
	}
	return nil
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

// Message resolves a stable application message identifier through the
// active catalog. The boolean is false when the identifier has no localized
// representation, allowing callers to retain category-level fallback text.
func Message(catalog Catalog, messageID string) (string, bool) {
	key := Key(strings.TrimSpace(messageID))
	if key == "" {
		return "", false
	}
	message := Normalize(catalog).Text(key)
	if message == "[missing translation]" || message == "[нет перевода]" || strings.TrimSpace(message) == "" {
		return "", false
	}
	return message, true
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

// PriorityLabel returns a localized recommendation priority while preserving
// unknown future values as stable, uppercase identifiers.
func PriorityLabel(catalog Catalog, priority string) string {
	switch strings.ToLower(strings.TrimSpace(priority)) {
	case "critical":
		return Normalize(catalog).Text(PriorityCritical)
	case "high":
		return Normalize(catalog).Text(PriorityHigh)
	case "medium", "normal":
		return Normalize(catalog).Text(PriorityMedium)
	case "low":
		return Normalize(catalog).Text(PriorityLow)
	default:
		return strings.ToUpper(strings.TrimSpace(priority))
	}
}

// Text resolves an English user-interface string.
func (English) Text(key Key) string {
	if text, ok := english[key]; ok {
		return text
	}
	return "[missing translation]"
}

// english contains the complete built-in text catalog.
//
//nolint:gosec // UI copy names credentials and secrets but stores no credential values.
var english = map[Key]string{
	AppName: "Orynelo",

	NavigationDiagnose:        "Diagnose",
	NavigationHistory:         "History",
	NavigationProfiles:        "Profiles",
	NavigationSettings:        "Settings",
	NavigationAbout:           "About",
	NavigationToggle:          "Navigation",
	MenuFile:                  "File",
	MenuNavigate:              "Navigate",
	MenuHelp:                  "Help",
	MenuKeyboardShortcuts:     "Keyboard shortcuts",
	MenuKeyboardShortcutsBody: "Primary+L — focus target\nPrimary+Enter — run diagnostics\nEscape — cancel\nPrimary+E — export Markdown\nPrimary+, — settings",

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
	CommonCopy:             "Copy",
	CommonMore:             "More actions",
	CommonStaleData:        "Showing previously loaded data; it may be stale.",

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
	OptionRussian:  "Russian",
	OptionEnglish:  "English",

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
	DiagnoseAutoExplanation:           "Auto uses the explicit URI scheme; a bare host means HTTPS and host:port means TCP.",
	DiagnoseTargetPreview:             "Effective target: %s",
	DiagnoseProbeMode:                 "Probe mode",
	DiagnoseAddressLimit:              "Address limit",
	DiagnoseMatrixBudget:              "Matrix budget",
	DiagnoseExpectedStatus:            "Expected HTTP status (for example 200-299)",
	DiagnoseLatencyThreshold:          "Latency threshold",
	DiagnoseConnectIP:                 "Connect IP",
	DiagnoseServerName:                "TLS SNI / verification name",
	DiagnoseHTTPHost:                  "HTTP Host",
	DiagnoseCABundle:                  "Custom CA bundle path",
	DiagnoseRequestHeaders:            "One-time request headers (never saved or logged)",
	DiagnoseCollectDNSDetails:         "Collect CNAME, TTL, and resolver details",
	DiagnoseInspectBody:               "Inspect bounded body metadata (body is never stored)",
	DiagnoseInvalidAddressLimit:       "address limit must be between 1 and 16",
	DiagnoseInvalidMatrixBudget:       "matrix budget must be a positive duration",
	DiagnoseInvalidExpectedStatus:     "expected status must be one code or an ascending range from 100 to 599",
	DiagnoseInvalidLatencyThreshold:   "latency threshold must be empty or a positive duration",
	DiagnoseInvalidRequestHeaders:     "request headers must use one Name: value line each and contain no control characters",
	DiagnoseInvalidTarget:             "enter a valid URL, host, or host:port target",
	DiagnoseTransportOptions:          "Transport and address selection",
	DiagnoseTLSOptions:                "TLS and certificate verification",
	DiagnoseHTTPOptions:               "HTTP request, redirects, proxy, and expectations",
	DiagnoseCertificateExplanation:    "Certificate verification uses the effective hostname unless SNI is overridden; a custom CA bundle adds trust only for this run.",
	DiagnoseContextUnknown:            "Enter a target to reveal only the options that apply to it.",
	DiagnoseContextTCP:                "TCP target: HTTP and TLS controls are hidden and ignored.",
	DiagnoseContextTLS:                "TLS target: configure SNI, certificate verification, and optional custom trust.",
	DiagnoseContextHTTP:               "HTTP target: configure the method, proxy, redirects, headers, and expected response.",
	DiagnoseContextHTTPS:              "HTTPS target: HTTP request controls and TLS certificate controls both apply.",
	DiagnoseActualPathFormat:          "Observed client path: %s",
	DiagnoseBreakPointFormat:          "Path first failed at: %s",
	DiagnoseStartedFormat:             "Started: %s",
	DiagnoseFinishedFormat:            "Finished: %s",
	DiagnoseCopiedTitle:               "Copied",
	DiagnoseCopiedMessage:             "The privacy-safe text is now on the clipboard.",
	DiagnoseUnattributedEvidence:      "Check-level evidence",
	DiagnoseRedactedFact:              "Redacted sensitive header/value was present",
	DiagnoseViewFullValue:             "View full value",
	DiagnoseEvidenceGroupFormat:       "Evidence · %s",
	DiagnoseSearchJSON:                "Search JSON",
	DiagnoseWrapJSON:                  "Wrap",
	DiagnoseSearchMatchesFormat:       "%d matches",
	OptionClientEffective:             "Client-effective",
	OptionAddressMatrix:               "Address matrix",

	TimingDNS:              "DNS",
	TimingTCP:              "TCP",
	TimingTLS:              "TLS",
	TimingTTFB:             "TTFB",
	TimingTotal:            "Total",
	TimingWaiting:          "Timing data will appear as checks complete.",
	TimingNoData:           "No timing data is available.",
	TimingNotMeasured:      "Not measured",
	TimingReused:           "reused connection",
	TimingAxisFormat:       "0 s                                      %s",
	StatusAccessibleFormat: "%s — %s",

	CheckTarget:                  "Target validation",
	CheckEnvironment:             "Environment and proxy",
	CheckDNS:                     "DNS resolution",
	CheckRoute:                   "Route and source address",
	CheckTCP:                     "TCP connection",
	CheckTLS:                     "TLS handshake and certificate",
	CheckHTTP:                    "HTTP request",
	PathRoleClient:               "client-observed path",
	PathRoleMatrix:               "address matrix",
	PathRoleAuxiliary:            "auxiliary direct comparison",
	PathKindDirect:               "direct",
	PathKindHTTPProxy:            "HTTP proxy",
	PathKindConnect:              "HTTPS CONNECT proxy",
	HopKindOrigin:                "origin",
	HopKindProxy:                 "proxy peer",
	HopKindRedirect:              "redirect",
	RecommendationCheckFormat:    "check: %s",
	RecommendationEvidenceFormat: "evidence: %s",
	EvidenceKindText:             "text",
	EvidenceKindDuration:         "duration",
	EvidenceKindTime:             "time",
	EvidenceKindAddress:          "network address",
	EvidenceKindCertificate:      "certificate",
	EvidenceKindHeader:           "HTTP header",

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
	HistoryRefreshSuccess:      "History is up to date.",

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
	ProfilesRefreshSuccess:       "Profiles are up to date.",
	ProfilesSaveSuccessTitle:     "Profile saved",
	ProfilesSaveSuccessMessage:   "The diagnostic profile was saved successfully.",

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
	SettingsLoggingSubtitle:       "Tools for troubleshooting Orynelo",
	SettingsPrivacySubtitle:       "No accounts, cloud sync, or analytics",
	SettingsLanguage:              "Interface language",
	SettingsReportLanguage:        "Human-readable report language",
	SettingsDurationHint:          "Durations accept values such as 15s, 5m, 2h, or 30d.",
	SettingsClearHistoryHint:      "Permanently delete every locally stored diagnostic run.",
	SettingsStoredLocally:         "Settings are stored on this device.",
	SettingsUnsaved:               "Unsaved changes",
	SettingsThemeErrorPrefix:      "Theme could not be applied: ",
	SettingsInvalidDefaultTimeout: "Default timeout must be a valid positive duration.",
	SettingsInvalidCheckTimeout:   "Per-check timeout must be a valid positive duration.",
	SettingsInvalidRedirects:      "Maximum redirects must be a valid number.",
	SettingsInvalidCertificate:    "Certificate warning threshold must be a valid duration.",
	SettingsInvalidHistoryLimit:   "History limit must be a valid number.",
	SettingsInvalidConfiguration:  "One or more settings are invalid. Review the values and try again.",
	PrivacyNoTelemetry:            "Orynelo does not send telemetry.",
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
	AboutAcknowledgementsMarkdown: "Orynelo is built with [Go](https://go.dev/), [Fyne](https://fyne.io/), [Cobra](https://cobra.dev/), and [modernc SQLite](https://pkg.go.dev/modernc.org/sqlite).",
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
	DialogReportFilenameBase:      "orynelo-report",
	DialogRawStructuredData:       "Raw structured data",
	DialogLogDirectoryUnavailable: "log directory is unavailable",
	DialogExportPrivacyTitle:      "Export privacy",
	DialogExportPrivacyBody:       "Choose how much identifying context the exported report should retain.",
	DialogExportFilename:          "File name",
	DialogExportFilenameInvalid:   "Enter a safe file name without folders or path separators.",
	DialogExportStandard:          "Standard — remove credentials and secret-like values",
	DialogExportStrict:            "Strict — also hide URL paths, query values, internal hosts/IPs, and local paths",
	DialogExportContinue:          "Continue",
	DialogExportLanguage:          "Language for this human-readable report",
	DialogExportSavedTitle:        "Export complete",
	DialogExportSavedAtomicFormat: "Report saved atomically to %s.",
	DialogExportSavedURIFormat:    "Report saved to %s. This URI provider does not guarantee atomic replacement.",
	DialogExportOverwriteTitle:    "Replace existing export?",
	DialogExportOverwriteFormat:   "An item already exists at %s. Replace it?",
	DialogProfileRedactedTitle:    "Sensitive target parts will be removed",
	DialogProfileRedactedFormat:   "For privacy, the saved profile target will be:\n\n%s\n\nThe profile may no longer work without the removed value. Save it anyway?",

	RecoveryTitle:            "Orynelo startup recovery",
	RecoveryIntro:            "Orynelo could not initialize its local runtime.",
	RecoveryReferenceFormat:  "Error reference: %s",
	RecoveryExplanation:      "Retry, continue without local storage, open the configuration or log location, or exit.",
	RecoveryRetry:            "Retry",
	RecoveryContinue:         "Continue without storage",
	RecoveryOpenConfig:       "Open configuration location",
	RecoveryOpenLogs:         "Open log location",
	RecoveryExit:             "Exit",
	RecoveryVersionFormat:    "Version %s",
	RecoveryOpenPathError:    "The selected location could not be opened.",
	RecoveryPathUnavailable:  "The local path is unavailable on this system.",
	StartupLimitedStateTitle: "Limited local state",
	StartupLimitedStateIntro: "Diagnostics are available, but some local features are disabled:",
	StartupWarningFormat:     "• %s (%s)",

	PriorityCritical: "Critical",
	PriorityHigh:     "High",
	PriorityMedium:   "Medium",
	PriorityLow:      "Low",

	ErrorValidationGuidance:    "Check the entered values and try again.",
	ErrorConfigurationGuidance: "Review the application settings and try again.",
	ErrorStorageGuidance:       "Local data is unavailable. Retry the operation; diagnostics can continue without saved history.",
	ErrorPermissionGuidance:    "Permission was denied. Choose a writable destination and try again.",
	ErrorCancelledGuidance:     "The operation was cancelled.",
	ErrorNetworkPolicyGuidance: "Network policy blocked this operation. Review proxy and redirect settings before retrying.",
	ErrorInternalGuidance:      "The operation could not be completed. Retry it; if the problem continues, open the log directory from Settings.",
	ErrorReferenceFormat:       "Error reference: %s",
	ErrorFieldFormat:           "Check field: %s",

	Key("error.configuration_invalid"):             "The configuration is invalid. Review the highlighted values and try again.",
	Key("error.configuration_load_failed"):         "The configuration could not be loaded. Retry or continue with safe defaults.",
	Key("error.configuration_save_failed"):         "The configuration could not be saved. Retry the operation.",
	Key("error.configuration_store_unavailable"):   "Configuration storage is unavailable. Diagnostics can continue with current settings.",
	Key("error.configuration_values_invalid"):      "One or more configuration values are invalid. Review them and try again.",
	Key("error.application_unavailable"):           "The application service is unavailable. Restart Orynelo and retry.",
	Key("error.cancelled"):                         "The operation was cancelled.",
	Key("error.configuration"):                     "The configuration could not be used. Review the settings and try again.",
	Key("error.diagnose_failed"):                   "Diagnostics could not be completed. Retry the run.",
	Key("error.diagnose_options_invalid"):          "The diagnostic options are invalid. Review them and try again.",
	Key("error.event_delivery_failed"):             "A diagnostic update could not be delivered. Retry the run.",
	Key("error.history_clear_failed"):              "History could not be cleared. Retry the operation.",
	Key("error.history_delete_failed"):             "The history entry could not be deleted. Retry the operation.",
	Key("error.history_get_failed"):                "The history entry could not be loaded. Retry the operation.",
	Key("error.history_id_invalid"):                "The history entry identifier is invalid. Select the entry again.",
	Key("error.history_list_failed"):               "History could not be loaded. Retry the refresh.",
	Key("error.history_search_invalid"):            "The history search is invalid. Review the query and try again.",
	Key("error.history_status_invalid"):            "The selected history status is invalid. Choose another filter.",
	Key("error.history_unavailable"):               "History storage is unavailable. Diagnostics can continue without saved history.",
	Key("error.history_read"):                      "Saved history could not be read. Retry or continue without this entry.",
	Key("error.history_write"):                     "The diagnostic result could not be saved to history. Diagnostics can continue.",
	Key("error.internal"):                          "The operation could not be completed. Retry it and review the logs if it continues.",
	Key("error.log_level_apply_failed"):            "The log level could not be applied. Review the setting and try again.",
	Key("error.log_level_invalid"):                 "The selected log level is invalid. Choose a supported value.",
	Key("error.logging_initialization_failed"):     "Logging could not be initialized. Retry or open the log location.",
	Key("error.paths_prepare_failed"):              "Local application paths could not be prepared. Check permissions and retry.",
	Key("error.paths_resolve_failed"):              "Local application paths could not be resolved. Retry the startup.",
	Key("error.persistence_policy_invalid"):        "The persistence policy is invalid. Continue with safe local defaults.",
	Key("error.profile_delete_failed"):             "The profile could not be deleted. Retry the operation.",
	Key("error.profile_id_invalid"):                "The profile identifier is invalid. Select the profile again.",
	Key("error.profile_list_failed"):               "Profiles could not be loaded. Retry the refresh.",
	Key("error.profile_save_failed"):               "The profile could not be saved. Review its values and retry.",
	Key("error.profile_storage_unavailable"):       "Profile storage is unavailable. Diagnostics can continue without saved profiles.",
	Key("error.profile_values_invalid"):            "One or more profile values are invalid. Review them and try again.",
	Key("error.profile_load"):                      "The saved profile could not be loaded. Select another profile or retry.",
	Key("error.preview_privacy_mode_invalid"):      "The preview privacy mode is invalid. Choose a supported privacy level.",
	Key("error.privacy_mode_invalid"):              "The privacy mode is invalid. Choose a supported privacy level.",
	Key("error.report_destination_inspect_failed"): "The export destination could not be inspected. Choose another location or retry.",
	Key("error.report_destination_invalid"):        "The export destination is invalid. Choose a writable location.",
	Key("error.report_format_invalid"):             "The report format is invalid. Choose a supported format.",
	Key("error.report_language_invalid"):           "The report language is invalid. Choose System, Russian, or English.",
	Key("error.report_pick_failed"):                "The export location could not be selected. Choose another location or retry.",
	Key("error.report_privacy_mode_invalid"):       "The report privacy mode is invalid. Choose a supported privacy level.",
	Key("error.report_render_failed"):              "The report could not be prepared. Retry the export.",
	Key("error.report_renderer_unavailable"):       "Report export is unavailable in this runtime.",
	Key("error.report_write_failed"):               "The report could not be written. Choose a writable location or retry.",
	Key("error.network_policy"):                    "Network policy blocked the operation. Review proxy and redirect settings.",
	Key("error.permission"):                        "Permission was denied. Choose an accessible location and retry.",
	Key("error.redirect_blocked"):                  "A redirect was blocked by the active network safety policy.",
	Key("error.secret"):                            "A sensitive value could not be used safely. Review the input and try again.",
	Key("error.storage"):                           "Local storage is unavailable. Retry or continue without saved local data.",
	Key("error.target_rejected"):                   "The target was rejected by the active network safety policy.",
	Key("error.timed_out"):                         "The operation timed out. Retry it or increase the applicable timeout.",
	Key("error.validation"):                        "The supplied value is invalid. Review it and try again.",
	Key("error.runner_unavailable"):                "The diagnostic runner is unavailable. Restart the application and retry.",
	Key("error.runtime_close_failed"):              "The local runtime could not be closed cleanly. Review the logs before retrying.",
	Key("error.service_initialization_failed"):     "Application services could not be initialized. Retry the startup.",
	Key("error.storage_close_failed"):              "Local storage could not be closed cleanly. Review the logs before retrying.",
	Key("error.storage_initialization_failed"):     "Local storage could not be initialized. Retry or continue without storage.",
	Key("error.gui_task_start_failed"):             "The background operation could not be started. Retry it.",
	Key("error.gui_theme_apply_failed"):            "The selected theme could not be applied. Choose another theme or retry.",
	Key("error.log_directory_open_failed"):         "The log directory could not be opened. Check that the location is available.",

	TechnicalJSONEncodingError:         "technical details could not be encoded",
	TechnicalCheckIDFormat:             "Check ID: %s",
	TechnicalStatusFormat:              "Status: %s",
	TechnicalErrorCodeFormat:           "Error code: %s",
	TechnicalEvidenceCountFormat:       "Evidence records: %d",
	TechnicalRecommendationCountFormat: "Recommendation records: %d",

	ThemeUnknownAppearanceFormat: "unknown appearance %q",
}
