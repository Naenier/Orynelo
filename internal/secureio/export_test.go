package secureio

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type failingWriteCloser struct {
	written int
	closed  bool
	write   error
	close   error
}

func (w *failingWriteCloser) Write(content []byte) (int, error) {
	w.written = len(content) - 1
	return w.written, w.write
}

func (w *failingWriteCloser) Close() error {
	w.closed = true
	return w.close
}

func TestWriteFileAtomicallyReplacesWithPrivateFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("complete report")); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "complete report" {
		t.Fatalf("content = %q", content)
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

func TestWriteFileRenameFailurePreservesDestinationAndRemovesTemporary(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "report.json")
	if err := os.WriteFile(path, []byte("old report"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("injected rename failure")
	err := writeFile(path, []byte("new report"), func(*os.Root, string, string) error {
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("writeFile() error = %v, want injected rename failure", err)
	}
	content, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(content) != "old report" {
		t.Fatalf("destination after failed rename = %q", content)
	}
	entries, readDirErr := os.ReadDir(directory)
	if readDirErr != nil {
		t.Fatal(readDirErr)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".orynelo-export-") {
			t.Fatalf("temporary export was not removed: %q", entry.Name())
		}
	}
}

func TestWriteFileIfAbsentDoesNotReplaceLateDestination(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "report.json")
	err := writeFileWithPolicy(path, []byte("new report"), false, func(
		root *os.Root,
		oldName,
		newName string,
	) error {
		racing, createErr := root.OpenFile(newName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil {
			return createErr
		}
		if _, writeErr := racing.Write([]byte("racing report")); writeErr != nil {
			_ = racing.Close()
			return writeErr
		}
		if closeErr := racing.Close(); closeErr != nil {
			return closeErr
		}
		return installFile(root, oldName, newName)
	})
	if !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("WriteFileIfAbsent() error = %v, want destination-exists", err)
	}
	content, readErr := os.ReadFile(path)
	if readErr != nil || string(content) != "racing report" {
		t.Fatalf("late destination = %q, %v", content, readErr)
	}
}

func TestWriteFileRejectsSymlink(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	victim := filepath.Join(directory, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "report")
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("symlink is unavailable: %v", err)
	}
	err := WriteFile(link, []byte("replace"))
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("WriteFile() error = %v, want symbolic-link rejection", err)
	}
	content, err := os.ReadFile(victim)
	if err != nil || string(content) != "keep" {
		t.Fatalf("victim = %q, %v", content, err)
	}
}

func TestWriteAndCloseReportsShortWriteAndCloseFailure(t *testing.T) {
	t.Parallel()

	closeErr := errors.New("provider close failed")
	writer := &failingWriteCloser{close: closeErr}
	err := WriteAndClose(writer, []byte("report"))
	if !errors.Is(err, io.ErrShortWrite) || !errors.Is(err, closeErr) {
		t.Fatalf("WriteAndClose() error = %v, want short-write and close errors", err)
	}
	if !writer.closed {
		t.Fatal("WriteAndClose() did not close the provider writer")
	}
}

func TestWriteAndCloseSuccess(t *testing.T) {
	t.Parallel()

	file, err := os.CreateTemp(t.TempDir(), "provider-")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteAndClose(file, []byte("report")); err != nil {
		t.Fatalf("WriteAndClose() error = %v", err)
	}
	content, err := os.ReadFile(file.Name())
	if err != nil || string(content) != "report" {
		t.Fatalf("content = %q, %v", content, err)
	}
}
