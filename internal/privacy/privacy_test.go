package privacy

import (
	"strings"
	"testing"
	"time"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

func TestStandardDiagnosisProjectsEveryPersistentField(t *testing.T) {
	t.Parallel()

	zone := time.FixedZone("private-zone", 3*60*60)
	started := time.Date(2026, 8, 3, 12, 0, 0, 0, zone)
	input := model.Diagnosis{
		ID: "privacy-test",
		Target: model.Target{
			Original:    "https://alice:password@api.example.test/private?token=target-secret&view=full",
			Normalized:  "https://alice:password@api.example.test:443/private?token=target-secret&view=full",
			Host:        "api.example.test",
			DisplayHost: "api.example.test",
			Path:        "/private",
			RequestURL:  "https://alice:password@api.example.test/private?token=target-secret",
		},
		Options: model.DiagnoseOptions{
			Target:    "https://option-user:option-pass@api.example.test/?api_key=option-secret",
			UserAgent: "Orynelo/1 token=user-agent-secret",
		},
		StartedAt:  started,
		FinishedAt: started.Add(time.Second),
		Summary: model.Summary{
			Title:       "proxy=https://proxy-user:proxy-pass@proxy.example.test/?token=proxy-secret",
			Description: "Authorization: Bearer summary-secret",
			Recommendations: []model.Recommendation{{
				Message: "open https://alice:password@example.test/?token=recommendation-secret",
			}},
		},
		Checks: []model.CheckResult{{
			Name:       "request token=check-name-secret",
			Summary:    "Cookie: session=check-summary-secret",
			StartedAt:  started,
			FinishedAt: started.Add(time.Second),
			Evidence: []model.Evidence{{
				Message: "Proxy-Authorization: Basic evidence-secret",
				Details: map[string]string{
					"Authorization":                "Bearer details-header-secret",
					"responseHeader.Authorization": "Bearer namespaced-header-secret",
					"request.query[access_token]":  "namespaced-query-secret",
					"responseHeader.Content-Type":  "application/json",
					"proxy":                        "http://proxy-user:proxy-pass@proxy.example.test/?token=details-proxy-secret",
				},
			}},
		}},
	}

	got := Standard().Diagnosis(input)
	serialized := strings.Join([]string{
		got.Target.Original,
		got.Target.Normalized,
		got.Target.RequestURL,
		got.Options.Target,
		got.Options.UserAgent,
		got.Summary.Title,
		got.Summary.Description,
		got.Summary.Recommendations[0].Message,
		got.Checks[0].Name,
		got.Checks[0].Summary,
		got.Checks[0].Evidence[0].Message,
		got.Checks[0].Evidence[0].Details["Authorization"],
		got.Checks[0].Evidence[0].Details["responseHeader.Authorization"],
		got.Checks[0].Evidence[0].Details["request.query[access_token]"],
		got.Checks[0].Evidence[0].Details["proxy"],
	}, "\n")
	for _, secret := range []string{
		"alice", "password", "target-secret", "option-user", "option-pass", "option-secret",
		"user-agent-secret", "proxy-user", "proxy-pass", "proxy-secret", "summary-secret",
		"recommendation-secret", "check-name-secret", "check-summary-secret", "evidence-secret",
		"details-header-secret", "namespaced-header-secret", "namespaced-query-secret",
		"details-proxy-secret",
	} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("projection leaked %q:\n%s", secret, serialized)
		}
	}
	if got.Target.RequestURL != "" || !strings.Contains(serialized, "[REDACTED]") {
		t.Fatalf("projection did not clear the request URL or mark redaction: %#v", got)
	}
	if got.Checks[0].Evidence[0].Details["responseHeader.Content-Type"] != "application/json" {
		t.Fatal("projection removed a non-sensitive namespaced response header")
	}
	if !got.Target.PrivacyRedacted {
		t.Fatal("projection did not retain redaction provenance for profile preview")
	}
	if got.StartedAt.Location() != time.UTC || got.Checks[0].StartedAt.Location() != time.UTC {
		t.Fatalf("timestamps were not normalized to UTC: %s, %s", got.StartedAt, got.Checks[0].StartedAt)
	}
	if input.Target.RequestURL == "" || input.Checks[0].Evidence[0].Details["Authorization"] == "[REDACTED]" {
		t.Fatal("projection mutated the caller's diagnosis")
	}
}

func TestStrictProjectionHidesAdditionalIdentifyingContext(t *testing.T) {
	t.Parallel()

	input := model.Diagnosis{
		Target: model.Target{
			Original:    "https://service.internal/private/customer/42?view=full&token=secret",
			Normalized:  "https://service.internal:8443/private/customer/42?view=full&token=secret",
			Host:        "service.internal",
			DisplayHost: "service.internal",
			Path:        "/private/customer/42",
		},
		Options: model.DiagnoseOptions{Target: "https://10.1.2.3/admin?mode=debug"},
		Summary: model.Summary{
			Description: "lookup backend01: no such host; dial tcp backend02:443 failed; connected to 192.168.1.20 and fd00::beef; logs are /home/alice/.local/share/orynelo/app.log, /usr/local/private/file, /data/customer/export, and /workspace/team/result",
		},
		Checks: []model.CheckResult{{Evidence: []model.Evidence{{Details: map[string]string{
			"remoteIp": "fd00::1234",
			"path":     `C:\Users\Alice\AppData\Local\Orynelo\orynelo.db`,
		}}}}},
	}

	standard := Standard().Diagnosis(input)
	if !strings.Contains(standard.Target.Original, "/private/customer/42") ||
		!strings.Contains(standard.Target.Original, "view=full") {
		t.Fatalf("standard mode removed legitimate diagnostic context: %q", standard.Target.Original)
	}

	strict := Strict().Diagnosis(input)
	combined := strings.Join([]string{
		strict.Target.Original,
		strict.Target.Normalized,
		strict.Target.Host,
		strict.Target.Path,
		strict.Options.Target,
		strict.Summary.Description,
		strict.Checks[0].Evidence[0].Details["remoteIp"],
		strict.Checks[0].Evidence[0].Details["path"],
	}, "\n")
	for _, identifying := range []string{
		"service.internal", "private/customer/42", "view=full", "10.1.2.3", "192.168.1.20",
		"fd00::1234", "fd00::beef", "/home/alice", "/usr/local/private/file",
		"/data/customer/export", "/workspace/team/result", "backend01", "backend02",
		`C:\Users\Alice`,
	} {
		if strings.Contains(combined, identifying) {
			t.Fatalf("strict projection retained %q:\n%s", identifying, combined)
		}
	}
	if !strings.Contains(combined, "[REDACTED]") && !strings.Contains(combined, "redacted.invalid") {
		t.Fatalf("strict projection did not make anonymization visible:\n%s", combined)
	}
}

func TestStrictProjectionHandlesSchemeLessInternalTarget(t *testing.T) {
	t.Parallel()

	got := Strict().Target(model.Target{
		Original:   "service.internal:443/private?view=full",
		Normalized: "service.internal:443/private?view=full",
		Host:       "service.internal",
		Path:       "/private",
	})
	combined := got.Original + "\n" + got.Normalized + "\n" + got.Host + "\n" + got.Path
	for _, leaked := range []string{"service.internal", "private", "view=full"} {
		if strings.Contains(combined, leaked) {
			t.Fatalf("strict scheme-less target retained %q: %s", leaked, combined)
		}
	}
}

func TestStrictProjectionHidesSharedCGNATAddressesEverywhere(t *testing.T) {
	t.Parallel()

	strict := Strict().Diagnosis(model.Diagnosis{
		Target: model.Target{
			Original:   "https://100.64.1.2/private",
			Normalized: "https://100.64.1.2:443/private",
			Host:       "100.64.1.2",
		},
		Options: model.DiagnoseOptions{Target: "https://100.64.1.3/private"},
		Summary: model.Summary{
			Description: "connected to 100.64.1.4 through the shared address space",
		},
		Checks: []model.CheckResult{{Evidence: []model.Evidence{{Details: map[string]string{
			"remoteIp": "100.64.1.5",
		}}}}},
	})
	combined := strings.Join([]string{
		strict.Target.Original,
		strict.Target.Normalized,
		strict.Target.Host,
		strict.Options.Target,
		strict.Summary.Description,
		strict.Checks[0].Evidence[0].Details["remoteIp"],
	}, "\n")
	if strings.Contains(combined, "100.64.") || !strings.Contains(combined, "[REDACTED]") {
		t.Fatalf("strict projection retained shared CGNAT context:\n%s", combined)
	}
}

func TestStrictProjectionHidesTLSIdentityMetadata(t *testing.T) {
	t.Parallel()

	input := model.CheckResult{Evidence: []model.Evidence{{Details: map[string]string{
		"sni":               "backend01",
		"dnsSANs":           "backend01, public.example",
		"ipSANs":            "10.1.2.3, 203.0.113.4",
		"subject":           "CN=backend01,O=Private Corp",
		"issuer":            "CN=Private CA,O=Private Corp",
		"verificationError": "x509: certificate is valid for backend01, not service.internal",
		"version":           "TLS 1.3",
		"cipherSuite":       "TLS_AES_128_GCM_SHA256",
	}}}}
	projected := Strict().CheckResult(input)
	details := projected.Evidence[0].Details
	for _, key := range []string{
		"sni", "dnsSANs", "ipSANs", "subject", "issuer", "verificationError",
	} {
		if details[key] != "[REDACTED]" {
			t.Errorf("strict TLS detail %q = %q, want redacted", key, details[key])
		}
	}
	if details["version"] != "TLS 1.3" || details["cipherSuite"] != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("strict projection removed non-identifying TLS context: %#v", details)
	}
}

func TestEventAndProfileUseTheSameProjection(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 8, 3, 12, 0, 0, 0, time.FixedZone("offset", -4*60*60))
	check := model.CheckResult{
		StartedAt: at,
		Summary:   "request https://alice:password@example.test/?token=event-secret",
	}
	event := Standard().Event(model.CheckEvent{At: at, Result: &check})
	if event.At.Location() != time.UTC || event.Result.StartedAt.Location() != time.UTC {
		t.Fatalf("event timestamps are not UTC: %#v", event)
	}
	if strings.Contains(event.Result.Summary, "event-secret") || event.Result == &check {
		t.Fatalf("event result was leaked or aliased: %#v", event.Result)
	}

	profile := model.Profile{
		Target: "alice:password@example.test/path?api_key=profile-secret&view=full",
		Method: "head",
		Mode:   model.DiagnosticModeTLS,
	}
	projected := Standard().Profile(profile)
	if strings.Contains(projected.Target, "alice") || strings.Contains(projected.Target, "profile-secret") {
		t.Fatalf("profile target leaked: %q", projected.Target)
	}
	if strings.Contains(projected.Target, "password") || !strings.HasPrefix(projected.Target, "example.test/") {
		t.Fatalf("scheme-less profile target was not safely preserved: %q", projected.Target)
	}
	if projected.Method != "HEAD" || !projected.EnableTLS {
		t.Fatalf("profile normalization was not preserved: %#v", projected)
	}
}

func TestProfileProjectionRedactsMalformedSchemeLessAuthority(t *testing.T) {
	t.Parallel()

	projected := Standard().Profile(model.Profile{
		Target: "alice:password@example.test/%zz?token=profile-secret#access_token=fragment-secret",
	})
	for _, secret := range []string{"alice", "password", "profile-secret", "fragment-secret"} {
		if strings.Contains(projected.Target, secret) {
			t.Fatalf("malformed scheme-less target leaked %q: %q", secret, projected.Target)
		}
	}
	if !strings.Contains(projected.Target, "%zz") || !strings.Contains(projected.Target, "[REDACTED]") {
		t.Fatalf("malformed target lost safe diagnostic context: %q", projected.Target)
	}
}

func TestParseMode(t *testing.T) {
	t.Parallel()

	if got, err := ParseMode(" STRICT "); err != nil || got != ModeStrict {
		t.Fatalf("ParseMode(strict) = %q, %v", got, err)
	}
	if _, err := ParseMode("none"); err == nil {
		t.Fatal("ParseMode(none) accepted an unknown mode")
	}
}
