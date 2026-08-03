//go:build !windows

package secureio

import "os"

func replaceFile(root *os.Root, oldName, newName string) error {
	return root.Rename(oldName, newName)
}

// installFile creates the final directory entry without a replace window. A
// hard link exposes only the already-synced complete inode and fails atomically
// if another writer created newName first.
func installFile(root *os.Root, oldName, newName string) error {
	if err := root.Link(oldName, newName); err != nil {
		return err
	}
	return root.Remove(oldName)
}
