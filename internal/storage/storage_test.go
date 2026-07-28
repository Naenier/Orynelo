package storage

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

func TestMigrationsAndDatabasePermissions(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "private", "opsdoctor.db")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	version, err := store.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("SchemaVersion() error = %v", err)
	}
	if version != CurrentSchemaVersion {
		t.Fatalf("SchemaVersion() = %d, want %d", version, CurrentSchemaVersion)
	}

	for _, table := range []string{
		"diagnoses",
		"check_results",
		"evidence",
		"recommendations",
		"profiles",
		"metadata",
	} {
		var count int
		err := store.db.QueryRow(
			`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`,
			table,
		).Scan(&count)
		if err != nil {
			t.Fatalf("inspect table %q: %v", table, err)
		}
		if count != 1 {
			t.Errorf("table %q count = %d, want 1", table, count)
		}
	}

	var metadataVersion string
	if err := store.db.QueryRow(
		`SELECT value FROM metadata WHERE key = 'schema_version'`,
	).Scan(&metadataVersion); err != nil {
		t.Fatalf("read metadata schema version: %v", err)
	}
	if metadataVersion != "3" {
		t.Errorf("metadata schema version = %q, want 3", metadataVersion)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat(database) error = %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("database permissions = %o, want 600", got)
		}
		info, err = os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatalf("Stat(database directory) error = %v", err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Errorf("database directory permissions = %o, want 700", got)
		}
	}
}

func TestMigrationFromVersionOne(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "opsdoctor.db")
	if err := prepareDatabaseFile(path); err != nil {
		t.Fatalf("prepareDatabaseFile() error = %v", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	db.SetMaxOpenConns(1)
	if err := configure(context.Background(), db); err != nil {
		t.Fatalf("configure() error = %v", err)
	}
	if err := applyMigration(context.Background(), db, migrations[0]); err != nil {
		t.Fatalf("applyMigration(v1) error = %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close(v1) error = %v", err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open(v1 database) error = %v", err)
	}
	defer store.Close()
	version, err := store.SchemaVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version != CurrentSchemaVersion {
		t.Fatalf("version after migration = %d, want %d", version, CurrentSchemaVersion)
	}
	var profiles int
	if err := store.db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'profiles'`,
	).Scan(&profiles); err != nil {
		t.Fatal(err)
	}
	if profiles != 1 {
		t.Fatal("profiles table was not added by migration 2")
	}
	var modeColumn int
	if err := store.db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('profiles') WHERE name = 'mode'`,
	).Scan(&modeColumn); err != nil {
		t.Fatal(err)
	}
	if modeColumn != 1 {
		t.Fatal("profile mode column was not added by migration 3")
	}
}

func TestRejectsNewerDatabase(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "opsdoctor.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("Open(newer database) error = %v, want newer-version error", err)
	}
}

func TestDiagnosisHistoryCRUDRedactionAndNormalizedRows(t *testing.T) {
	t.Parallel()

	store := openMemoryStore(t)
	ctx := context.Background()
	input := testDiagnosis("run-1", time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC))
	if err := store.SaveDiagnosis(ctx, input, 200); err != nil {
		t.Fatalf("SaveDiagnosis() error = %v", err)
	}

	got, err := store.GetDiagnosis(ctx, input.ID)
	if err != nil {
		t.Fatalf("GetDiagnosis() error = %v", err)
	}
	if got.ID != input.ID || got.Summary.Status != input.Summary.Status {
		t.Fatalf("GetDiagnosis() = %#v", got)
	}
	if got.Target.RequestURL != "" {
		t.Errorf("stored RequestURL = %q, want empty", got.Target.RequestURL)
	}
	serialized, err := store.GetSnapshot(ctx, input.ID)
	if err != nil {
		t.Fatalf("GetSnapshot() error = %v", err)
	}
	if serialized.SchemaVersion != SnapshotSchemaVersion {
		t.Errorf("snapshot schema = %q", serialized.SchemaVersion)
	}

	var raw string
	if err := store.db.QueryRow(
		`SELECT snapshot_json FROM diagnoses WHERE id = ?`,
		input.ID,
	).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"alice",
		"password",
		"target-secret",
		"option-secret",
		"message-secret",
		"details-secret",
		"recommendation-secret",
	} {
		if strings.Contains(raw, secret) {
			t.Errorf("snapshot contains %q: %s", secret, raw)
		}
	}
	if !strings.Contains(raw, SnapshotSchemaVersion) || !strings.Contains(raw, "[REDACTED]") {
		t.Errorf("snapshot is not explicitly versioned/redacted: %s", raw)
	}
	if input.Target.RequestURL == "" || !strings.Contains(input.Target.Original, "alice") {
		t.Fatal("SaveDiagnosis() mutated caller input")
	}

	counts := map[string]int{
		"check_results":   1,
		"evidence":        1,
		"recommendations": 2,
	}
	for table, want := range counts {
		var got int
		if err := store.db.QueryRow(
			"SELECT COUNT(*) FROM "+table+" WHERE diagnosis_id = ?",
			input.ID,
		).Scan(&got); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if got != want {
			t.Errorf("%s rows = %d, want %d", table, got, want)
		}
	}

	input.Checks[0].Evidence = nil
	input.Checks[0].Recommendations = nil
	input.Summary.Recommendations = nil
	if err := store.SaveDiagnosis(ctx, input, 200); err != nil {
		t.Fatalf("upsert SaveDiagnosis() error = %v", err)
	}
	for _, table := range []string{"evidence", "recommendations"} {
		var count int
		if err := store.db.QueryRow(
			"SELECT COUNT(*) FROM "+table+" WHERE diagnosis_id = ?",
			input.ID,
		).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Errorf("%s rows after upsert = %d, want 0", table, count)
		}
	}

	if err := store.DeleteDiagnosis(ctx, input.ID); err != nil {
		t.Fatalf("DeleteDiagnosis() error = %v", err)
	}
	for _, table := range []string{"diagnoses", "check_results", "evidence", "recommendations"} {
		var count int
		if err := store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Errorf("%s count after delete = %d", table, count)
		}
	}
	if _, err := store.GetDiagnosis(ctx, input.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetDiagnosis(deleted) error = %v, want ErrNotFound", err)
	}
	if err := store.DeleteDiagnosis(ctx, input.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteDiagnosis(deleted) error = %v, want ErrNotFound", err)
	}
}

func TestHistoryRetentionSearchFilterSortAndClear(t *testing.T) {
	t.Parallel()

	store := openMemoryStore(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC)
	for index := 0; index < 5; index++ {
		diagnosis := testDiagnosis(
			"run-"+string(rune('a'+index)),
			base.Add(time.Duration(index)*time.Minute),
		)
		diagnosis.Target.Original = []string{
			"https://api.example.test",
			"https://db.example.test",
			"https://api.internal.test",
			"https://cache.example.test",
			"https://api.last.test",
		}[index]
		diagnosis.Target.Normalized = diagnosis.Target.Original
		diagnosis.Duration = time.Duration(index+1) * time.Second
		if index == 2 {
			diagnosis.Summary.Status = model.StatusFailed
		}
		if err := store.SaveDiagnosis(ctx, diagnosis, 3); err != nil {
			t.Fatalf("SaveDiagnosis(%d) error = %v", index, err)
		}
	}

	count, err := store.HistoryCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("HistoryCount() = %d, want 3", count)
	}
	entries, err := store.ListHistory(ctx, HistoryQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[0].ID != "run-e" || entries[2].ID != "run-c" {
		t.Fatalf("default history order = %#v", entries)
	}

	entries, err = store.ListHistory(ctx, HistoryQuery{
		Search:    "api",
		Sort:      HistorySortDuration,
		Ascending: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].ID != "run-c" || entries[1].ID != "run-e" {
		t.Fatalf("searched/sorted history = %#v", entries)
	}
	entries, err = store.ListHistory(ctx, HistoryQuery{Status: model.StatusFailed})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != "run-c" {
		t.Fatalf("filtered history = %#v", entries)
	}
	entries, err = store.ListHistory(ctx, HistoryQuery{Search: "%"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("literal wildcard search returned %#v", entries)
	}
	if _, err := store.ListHistory(ctx, HistoryQuery{Sort: "date; DROP TABLE diagnoses"}); err == nil {
		t.Fatal("ListHistory() accepted an invalid sort")
	}

	profile, err := store.CreateProfile(ctx, testProfile("preserved"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ClearHistory(ctx); err != nil {
		t.Fatal(err)
	}
	if count, err := store.HistoryCount(ctx); err != nil || count != 0 {
		t.Fatalf("history after clear = %d, %v", count, err)
	}
	if _, err := store.GetProfile(ctx, profile.ID); err != nil {
		t.Fatalf("ClearHistory() removed profile: %v", err)
	}
}

func TestProfileCRUDAndDuplicate(t *testing.T) {
	t.Parallel()

	store := openMemoryStore(t)
	ctx := context.Background()
	profile := testProfile("Production")
	profile.Target = "https://alice:password@example.test/?api_key=profile-secret&view=full"
	profile.Mode = model.DiagnosticModeTLS

	created, err := store.CreateProfile(ctx, profile)
	if err != nil {
		t.Fatalf("CreateProfile() error = %v", err)
	}
	if created.ID <= 0 || created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Fatalf("CreateProfile() = %#v", created)
	}
	for _, secret := range []string{"alice", "password", "profile-secret"} {
		if strings.Contains(created.Target, secret) {
			t.Errorf("created target contains %q: %q", secret, created.Target)
		}
	}
	if created.Method != "HEAD" {
		t.Errorf("created method = %q, want HEAD", created.Method)
	}
	if created.Mode != model.DiagnosticModeTLS || !created.EnableTLS {
		t.Errorf("created TLS mode was not normalized: %#v", created)
	}

	got, err := store.GetProfile(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetProfile() error = %v", err)
	}
	if got != created {
		t.Fatalf("GetProfile() = %#v, want %#v", got, created)
	}

	store.now = func() time.Time { return created.UpdatedAt.Add(time.Minute) }
	got.Name = "Updated"
	got.Timeout = 30 * time.Second
	updated, err := store.UpdateProfile(ctx, got)
	if err != nil {
		t.Fatalf("UpdateProfile() error = %v", err)
	}
	if updated.CreatedAt != created.CreatedAt || !updated.UpdatedAt.After(created.UpdatedAt) {
		t.Fatalf("UpdateProfile() timestamps = %#v", updated)
	}

	duplicate, err := store.DuplicateProfile(ctx, updated.ID, "")
	if err != nil {
		t.Fatalf("DuplicateProfile() error = %v", err)
	}
	if duplicate.ID == updated.ID || duplicate.Name != "Updated (copy)" || duplicate.Target != updated.Target {
		t.Fatalf("DuplicateProfile() = %#v", duplicate)
	}
	list, err := store.ListProfiles(ctx)
	if err != nil {
		t.Fatalf("ListProfiles() error = %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("ListProfiles() length = %d, want 2", len(list))
	}
	if err := store.DeleteProfile(ctx, updated.ID); err != nil {
		t.Fatalf("DeleteProfile() error = %v", err)
	}
	if _, err := store.GetProfile(ctx, updated.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetProfile(deleted) error = %v, want ErrNotFound", err)
	}
	if err := store.DeleteProfile(ctx, updated.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteProfile(deleted) error = %v, want ErrNotFound", err)
	}
}

func TestProfileValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*model.Profile)
	}{
		{name: "name", mutate: func(p *model.Profile) { p.Name = "" }},
		{name: "target", mutate: func(p *model.Profile) { p.Target = "" }},
		{name: "mode", mutate: func(p *model.Profile) { p.Mode = "invalid" }},
		{name: "IP", mutate: func(p *model.Profile) { p.IPVersion = "7" }},
		{name: "timeout", mutate: func(p *model.Profile) { p.Timeout = 0 }},
		{name: "check timeout", mutate: func(p *model.Profile) { p.CheckTimeout = p.Timeout + time.Second }},
		{name: "redirects", mutate: func(p *model.Profile) { p.MaxRedirects = 51 }},
		{name: "method", mutate: func(p *model.Profile) { p.Method = "GET\r\nX: evil" }},
		{name: "unsafe method", mutate: func(p *model.Profile) { p.Method = "DELETE" }},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := openMemoryStore(t)
			profile := testProfile("test")
			tt.mutate(&profile)
			if _, err := store.CreateProfile(context.Background(), profile); err == nil {
				t.Fatal("CreateProfile() error = nil, want validation error")
			}
		})
	}
}

func TestCloseIsIdempotentAndDataPersists(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "opsdoctor.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveDiagnosis(
		context.Background(),
		testDiagnosis("persisted", time.Now().UTC()),
		200,
	); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.GetDiagnosis(context.Background(), "persisted"); err != nil {
		t.Fatalf("GetDiagnosis() after reopen error = %v", err)
	}
}

func openMemoryStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open(:memory:) error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return store
}

func testDiagnosis(id string, started time.Time) model.Diagnosis {
	finished := started.Add(1500 * time.Millisecond)
	return model.Diagnosis{
		ID: id,
		Target: model.Target{
			Original:   "https://alice:password@example.test/path?token=target-secret&view=full",
			Normalized: "https://alice:password@example.test/path?token=target-secret&view=full",
			Scheme:     "https",
			Host:       "example.test",
			Port:       443,
			Kind:       model.TargetHTTP,
			UseTLS:     true,
			RequestURL: "https://alice:password@example.test/path?token=target-secret",
		},
		Options: model.DiagnoseOptions{
			Target:       "https://example.test/?access_token=option-secret",
			Timeout:      15 * time.Second,
			CheckTimeout: 5 * time.Second,
			IPVersion:    model.IPVersionAuto,
			MaxRedirects: 10,
			Method:       "GET",
		},
		StartedAt:  started,
		FinishedAt: finished,
		Duration:   finished.Sub(started),
		Checks: []model.CheckResult{
			{
				ID:         "http",
				Name:       "HTTP",
				Status:     model.StatusWarning,
				StartedAt:  started,
				FinishedAt: finished,
				Duration:   finished.Sub(started),
				Summary:    "URL https://example.test/?api_key=message-secret returned 503",
				Evidence: []model.Evidence{
					{
						ID:      "http-status",
						CheckID: "http",
						Code:    "HTTP_STATUS",
						Message: "Authorization: Bearer message-secret",
						Details: map[string]string{
							"Authorization": "Bearer details-secret",
							"location":      "https://u:p@example.test/?sig=details-secret",
						},
					},
				},
				Recommendations: []model.Recommendation{
					{
						ID:       "retry",
						CheckID:  "http",
						Priority: "medium",
						Message:  "Retry with token=recommendation-secret",
					},
				},
			},
		},
		Summary: model.Summary{
			Status:       model.StatusWarning,
			Title:        "Application-level warning",
			Description:  "HTTP endpoint returned 503",
			EvidenceRefs: []string{"http-status"},
			Recommendations: []model.Recommendation{
				{ID: "owner", Priority: "high", Message: "Contact service owner with key=recommendation-secret"},
			},
		},
		Build: model.BuildInfo{
			Version: "0.1.0",
			Commit:  "abc123",
		},
	}
}

func testProfile(name string) model.Profile {
	return model.Profile{
		Name:         name,
		Target:       "https://example.test",
		Mode:         model.DiagnosticModeAuto,
		IPVersion:    model.IPVersionAuto,
		Timeout:      15 * time.Second,
		CheckTimeout: 5 * time.Second,
		MaxRedirects: 10,
		Method:       "head",
	}
}
