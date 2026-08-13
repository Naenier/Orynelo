package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Naenier/orynelo/internal/secureio"
)

// RecoveryMode names a safe operator choice after storage verification or
// migration fails.
type RecoveryMode string

const (
	RecoveryReadOnly   RecoveryMode = "read-only"
	RecoveryQuarantine RecoveryMode = "quarantine"
	RecoveryNoStorage  RecoveryMode = "no-storage"
)

// BackupInfo identifies the verified online copy created before migration.
type BackupInfo struct {
	Path     string
	Checksum string
}

// IntegrityError reports a database that failed SQLite's quick consistency
// check. No migration is attempted after this error.
type IntegrityError struct {
	Err error
}

func (e *IntegrityError) Error() string { return "SQLite integrity check failed" }
func (e *IntegrityError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// RecoveryModes returns the non-destructive choices offered after corruption.
func (e *IntegrityError) RecoveryModes() []RecoveryMode {
	return []RecoveryMode{RecoveryReadOnly, RecoveryQuarantine, RecoveryNoStorage}
}

// MigrationError reports a rolled-back schema migration and the verified
// pre-migration copy available for recovery.
type MigrationError struct {
	FromVersion int
	ToVersion   int
	Backup      BackupInfo
	Err         error
}

func (e *MigrationError) Error() string {
	if e == nil {
		return "SQLite migration failed"
	}
	return fmt.Sprintf("SQLite migration from schema %d to %d failed", e.FromVersion, e.ToVersion)
}

func (e *MigrationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// RecoveryModes returns the non-destructive choices offered after rollback.
func (e *MigrationError) RecoveryModes() []RecoveryMode {
	return []RecoveryMode{RecoveryReadOnly, RecoveryQuarantine, RecoveryNoStorage}
}

func quickCheck(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `PRAGMA quick_check`)
	if err != nil {
		return &IntegrityError{Err: err}
	}
	defer rows.Close()
	var messages []string
	checked := false
	for rows.Next() {
		checked = true
		var message string
		if err := rows.Scan(&message); err != nil {
			return &IntegrityError{Err: err}
		}
		if !strings.EqualFold(strings.TrimSpace(message), "ok") {
			messages = append(messages, message)
		}
	}
	if err := rows.Err(); err != nil {
		return &IntegrityError{Err: err}
	}
	if !checked {
		return &IntegrityError{Err: errors.New("SQLite quick_check returned no result")}
	}
	if len(messages) != 0 {
		return &IntegrityError{Err: errors.New(strings.Join(messages, "; "))}
	}
	return nil
}

func createMigrationBackup(
	ctx context.Context,
	db *sql.DB,
	path string,
	version int,
) (BackupInfo, error) {
	directory := filepath.Dir(path)
	placeholder, err := os.CreateTemp(
		directory,
		fmt.Sprintf(".orynelo-schema-%d-*.backup", version),
	)
	if err != nil {
		return BackupInfo{}, fmt.Errorf("reserve migration backup: %w", err)
	}
	backupPath := placeholder.Name()
	if closeErr := placeholder.Close(); closeErr != nil {
		_ = os.Remove(backupPath)
		return BackupInfo{}, fmt.Errorf("close migration backup placeholder: %w", closeErr)
	}
	if err := os.Remove(backupPath); err != nil {
		return BackupInfo{}, fmt.Errorf("prepare migration backup path: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(backupPath)
			_ = os.Remove(backupPath + ".sha256")
		}
	}()

	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, backupPath); err != nil {
		return BackupInfo{}, fmt.Errorf("create online migration backup: %w", err)
	}
	if err := os.Chmod(backupPath, 0o600); err != nil {
		return BackupInfo{}, fmt.Errorf("protect migration backup: %w", err)
	}
	checksum, err := fileSHA256(backupPath)
	if err != nil {
		return BackupInfo{}, err
	}
	manifest := []byte(fmt.Sprintf(
		"%s  %s\ncreated=%s\nsource_schema=%d\n",
		checksum,
		filepath.Base(backupPath),
		time.Now().UTC().Format(time.RFC3339Nano),
		version,
	))
	if err := secureio.WriteFile(backupPath+".sha256", manifest); err != nil {
		return BackupInfo{}, fmt.Errorf("write migration backup checksum: %w", err)
	}
	committed = true
	return BackupInfo{Path: backupPath, Checksum: checksum}, nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open migration backup for checksum: %w", err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", fmt.Errorf("checksum migration backup: %w", err)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
