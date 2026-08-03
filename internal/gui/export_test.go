package gui

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/test"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
	"github.com/Naenier/opsdoctor/internal/redaction"
	"github.com/Naenier/opsdoctor/internal/secureio"
)

func TestExportDestinationSelectionDoesNotOpenOrTruncateExistingFile(t *testing.T) {
	test.NewTempApp(t)

	directory := t.TempDir()
	path := filepath.Join(directory, "report.json")
	if err := os.WriteFile(path, []byte("old report"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination, err := exportDestination(storage.NewFileURI(directory), "report.json")
	if err != nil {
		t.Fatal(err)
	}
	if destination.Path() != path {
		t.Fatalf("destination path = %q, want %q", destination.Path(), path)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "old report" {
		t.Fatalf("destination selection altered existing file: %q, %v", content, err)
	}
}

func TestWriteExportURILocalFileIsAtomicAndPrivate(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "report.md")
	destination := storage.NewFileURI(path)
	atomic, err := writeExportURI(destination, []byte("new report"), false)
	if err != nil {
		t.Fatal(err)
	}
	if !atomic {
		t.Fatal("local file export did not report its atomic guarantee")
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "new report" {
		t.Fatalf("export = %q, %v", content, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("permissions = %o, want 600", info.Mode().Perm())
		}
	}
}

func TestWriteExportURIRequiresConfirmationToReplaceLocalFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("old report"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := storage.NewFileURI(path)
	if _, err := writeExportURI(destination, []byte("new report"), false); !errors.Is(err, secureio.ErrDestinationExists) {
		t.Fatalf("unconfirmed write error = %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "old report" {
		t.Fatalf("unconfirmed write changed destination: %q, %v", content, err)
	}
	if _, err := writeExportURI(destination, []byte("new report"), true); err != nil {
		t.Fatalf("confirmed write error = %v", err)
	}
	content, err = os.ReadFile(path)
	if err != nil || string(content) != "new report" {
		t.Fatalf("confirmed write = %q, %v", content, err)
	}
}

func TestNormalizeExportFilenameRejectsPathTraversal(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "..", "../report", `..\\report`, "report\n.json"} {
		if _, err := normalizeExportFilename(value, ".json"); err == nil {
			t.Errorf("normalizeExportFilename(%q) accepted an unsafe name", value)
		}
	}
	if got, err := normalizeExportFilename("report", ".json"); err != nil || got != "report.json" {
		t.Fatalf("normalizeExportFilename(report) = %q, %v", got, err)
	}
}

func TestProjectProfileForSaveWarnsForNewAndPreviouslyRedactedTargets(t *testing.T) {
	t.Parallel()

	profile := model.Profile{
		Target: "alice:password@example.test/%zz?token=profile-secret#access_token=fragment-secret",
		Method: "GET",
		Mode:   model.DiagnosticModeAuto,
	}
	projected, warn := projectProfileForSave(profile)
	if !warn || strings.Contains(projected.Target, "profile-secret") ||
		strings.Contains(projected.Target, "fragment-secret") || strings.Contains(projected.Target, "alice") ||
		strings.Contains(projected.Target, "password") {
		t.Fatalf("secret-bearing target did not produce a safe preview: %#v, warn=%t", projected, warn)
	}

	profile.Target = "https://example.test/?token=" + redaction.Replacement
	_, warn = projectProfileForSave(profile)
	if !warn {
		t.Fatal("previously redacted target did not retain the non-working-profile warning")
	}

	profile.Target = "https://example.test/"
	_, warn = projectProfileForSave(profile, true)
	if !warn {
		t.Fatal("userinfo-removal provenance did not retain the non-working-profile warning")
	}
}
