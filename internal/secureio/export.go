// Package secureio provides complete-write helpers for privacy-sensitive
// exports.
package secureio

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

type renameFunc func(root *os.Root, oldName, newName string) error

// ErrDestinationExists reports that a no-replace export lost a race with a
// newly created destination. The existing file is left untouched.
var ErrDestinationExists = errors.New("export destination already exists")

// WriteFile atomically replaces a local report with a private regular file.
// The temporary file is created in the target directory, fully written,
// synced, closed, and only then renamed into place.
// WriteFile atomically replaces path with a complete private regular file.
func WriteFile(path string, content []byte) (resultErr error) {
	return writeFile(path, content, replaceFile)
}

// WriteFileIfAbsent atomically installs a complete local report only while the
// destination is absent. It is used after a GUI picker observed no existing
// file, so a file created before commit is never overwritten without consent.
// WriteFileIfAbsent installs content only if path remains absent until commit.
func WriteFileIfAbsent(path string, content []byte) (resultErr error) {
	return writeFileWithPolicy(path, content, false, installFile)
}

func writeFile(path string, content []byte, rename renameFunc) (resultErr error) {
	return writeFileWithPolicy(path, content, true, rename)
}

func writeFileWithPolicy(
	path string,
	content []byte,
	allowExisting bool,
	commit renameFunc,
) (resultErr error) {
	clean := filepath.Clean(path)
	root, err := os.OpenRoot(filepath.Dir(clean))
	if err != nil {
		return fmt.Errorf("open export directory for %q: %w", path, err)
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close export directory for %q: %w", path, closeErr))
		}
	}()

	name := filepath.Base(clean)
	if err := validateDestination(root, name, path, allowExisting); err != nil {
		return err
	}
	file, temporaryName, err := createTemporary(root)
	if err != nil {
		return fmt.Errorf("create temporary export for %q: %w", path, err)
	}
	defer func() {
		_ = file.Close()
		_ = root.Remove(temporaryName)
	}()

	written, writeErr := file.Write(content)
	if written != len(content) {
		writeErr = errors.Join(writeErr, io.ErrShortWrite)
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	var completionErr error
	if writeErr != nil {
		completionErr = errors.Join(completionErr, fmt.Errorf("write export %q: %w", path, writeErr))
	}
	if syncErr != nil {
		completionErr = errors.Join(completionErr, fmt.Errorf("sync export %q: %w", path, syncErr))
	}
	if closeErr != nil {
		completionErr = errors.Join(completionErr, fmt.Errorf("close export %q: %w", path, closeErr))
	}
	if completionErr != nil {
		return completionErr
	}
	if err := validateDestination(root, name, path, allowExisting); err != nil {
		return err
	}
	if err := commit(root, temporaryName, name); err != nil {
		if !allowExisting && errors.Is(err, os.ErrExist) {
			err = errors.Join(ErrDestinationExists, err)
		}
		return fmt.Errorf("replace export %q: %w", path, err)
	}

	if runtime.GOOS != "windows" {
		directory, err := os.Open(filepath.Dir(clean))
		if err != nil {
			return fmt.Errorf("open export directory for sync %q: %w", path, err)
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil {
			return fmt.Errorf("sync export directory for %q: %w", path, syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close synced export directory for %q: %w", path, closeErr)
		}
	}
	return nil
}

// WriteAndClose writes to a non-file destination and always closes it. A
// partial write and a close failure remain independently discoverable through
// errors.Is/errors.As on the joined error.
func WriteAndClose(writer io.WriteCloser, content []byte) error {
	if writer == nil {
		return errors.New("export writer is nil")
	}
	written, writeErr := writer.Write(content)
	if written != len(content) {
		writeErr = errors.Join(writeErr, io.ErrShortWrite)
	}
	closeErr := writer.Close()
	return errors.Join(writeErr, closeErr)
}

func validateDestination(
	root *os.Root,
	name,
	displayPath string,
	allowExisting bool,
) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect export %q: %w", displayPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("export %q is a symbolic link", displayPath)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("export %q is not a regular file", displayPath)
	}
	if !allowExisting {
		return fmt.Errorf("export %q: %w", displayPath, ErrDestinationExists)
	}
	return nil
}

func createTemporary(root *os.Root) (*os.File, string, error) {
	var suffix [16]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return nil, "", err
	}
	name := fmt.Sprintf(".opsdoctor-export-%x", suffix)
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
