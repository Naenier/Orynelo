// Package storage persists diagnostic history and saved profiles in SQLite.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Naenier/opsdoctor/internal/platform"
	_ "modernc.org/sqlite"
)

const (
	// SnapshotSchemaVersion identifies the JSON envelope stored beside
	// normalized history rows.
	SnapshotSchemaVersion = "1"

	defaultBusyTimeout = 5 * time.Second
)

// ErrNotFound is returned when a requested diagnosis or profile is absent.
var ErrNotFound = errors.New("storage: not found")

// Store owns a SQLite connection pool. A single connection is intentional:
// OpsDoctor is an interactive application and serialized writes avoid SQLite
// lock contention while still allowing WAL-backed persistence.
type Store struct {
	db       *sql.DB
	path     string
	close    sync.Once
	closeErr error
	now      func() time.Time
}

// Open opens, configures, and migrates a store.
func Open(path string) (*Store, error) {
	return OpenContext(context.Background(), path)
}

// OpenContext opens, configures, and migrates a store.
func OpenContext(ctx context.Context, path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("database path is empty")
	}
	if !isMemoryDatabase(path) {
		if err := prepareDatabaseFile(path); err != nil {
			return nil, err
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database %q: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store := &Store{
		db:   db,
		path: path,
		now:  func() time.Time { return time.Now().UTC() },
	}
	ok := false
	defer func() {
		if !ok {
			_ = db.Close()
		}
	}()

	if err := configure(ctx, db); err != nil {
		return nil, err
	}
	if err := migrate(ctx, db); err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO metadata(key, value) VALUES('snapshot_schema_version', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		SnapshotSchemaVersion,
	); err != nil {
		return nil, fmt.Errorf("record snapshot schema version: %w", err)
	}
	if !isMemoryDatabase(path) {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("set database permissions for %q: %w", path, err)
		}
	}

	ok = true
	return store, nil
}

// OpenDefault opens the database in the current platform data directory.
func OpenDefault() (*Store, error) {
	paths, err := platform.DefaultPaths()
	if err != nil {
		return nil, err
	}
	return Open(paths.DatabaseFile)
}

func prepareDatabaseFile(path string) error {
	if err := platform.EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("database path %q is a symbolic link", path)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("database path %q is not a regular file", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect database path %q: %w", path, err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create database file %q: %w", path, err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("set database file permissions for %q: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close database file %q: %w", path, err)
	}
	return nil
}

func configure(ctx context.Context, db *sql.DB) error {
	statements := []string{
		`PRAGMA foreign_keys = ON`,
		fmt.Sprintf("PRAGMA busy_timeout = %d", defaultBusyTimeout.Milliseconds()),
		`PRAGMA journal_mode = WAL`,
		`PRAGMA synchronous = NORMAL`,
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("configure SQLite (%s): %w", statement, err)
		}
	}
	var foreignKeys int
	if err := db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		return fmt.Errorf("verify SQLite foreign keys: %w", err)
	}
	if foreignKeys != 1 {
		return errors.New("SQLite foreign key enforcement is unavailable")
	}
	return nil
}

func isMemoryDatabase(path string) bool {
	return path == ":memory:" || strings.HasPrefix(path, "file::memory:")
}

// Path returns the configured database path.
func (s *Store) Path() string {
	return s.path
}

// SchemaVersion reports the migrated SQLite schema version.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return 0, fmt.Errorf("read SQLite schema version: %w", err)
	}
	return version, nil
}

// Close flushes and closes SQLite. It is safe to call more than once.
func (s *Store) Close() error {
	s.close.Do(func() {
		s.closeErr = s.db.Close()
		if s.closeErr != nil {
			s.closeErr = fmt.Errorf("close SQLite database: %w", s.closeErr)
		}
	})
	return s.closeErr
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	// Fixed-width fractional seconds preserve chronological ordering when
	// timestamps are sorted as SQLite TEXT.
	return value.UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
}

func parseTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse stored timestamp %q: %w", value, err)
	}
	return parsed, nil
}
