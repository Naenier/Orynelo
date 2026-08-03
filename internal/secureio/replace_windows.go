//go:build windows

package secureio

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// replaceFile uses the Windows replace-existing primitive so a confirmed
// overwrite has the same same-directory atomic replacement semantics as the
// POSIX rename path. COPY_ALLOWED is deliberately omitted: crossing a volume
// must fail instead of degrading to copy-and-delete.
func replaceFile(root *os.Root, oldName, newName string) error {
	return moveFile(root, oldName, newName, windows.MOVEFILE_REPLACE_EXISTING)
}

func installFile(root *os.Root, oldName, newName string) error {
	return moveFile(root, oldName, newName, 0)
}

func moveFile(root *os.Root, oldName, newName string, flags uint32) error {
	directory, err := filepath.Abs(root.Name())
	if err != nil {
		return err
	}
	oldPath, err := windows.UTF16PtrFromString(filepath.Join(directory, oldName))
	if err != nil {
		return err
	}
	newPath, err := windows.UTF16PtrFromString(filepath.Join(directory, newName))
	if err != nil {
		return err
	}
	return windows.MoveFileEx(
		oldPath,
		newPath,
		flags|windows.MOVEFILE_WRITE_THROUGH,
	)
}
