package storage

import (
	"context"
	"database/sql"
	"fmt"
)

// CurrentSchemaVersion is the latest SQLite schema understood by this build.
const CurrentSchemaVersion = 3

type migration struct {
	version    int
	statements []string
}

var migrations = []migration{
	{
		version: 1,
		statements: []string{
			`CREATE TABLE metadata (
				key TEXT PRIMARY KEY NOT NULL,
				value TEXT NOT NULL
			)`,
			`CREATE TABLE diagnoses (
				id TEXT PRIMARY KEY NOT NULL,
				target_original TEXT NOT NULL,
				target_normalized TEXT NOT NULL,
				target_host TEXT NOT NULL,
				target_port INTEGER NOT NULL,
				target_scheme TEXT NOT NULL,
				status TEXT NOT NULL,
				summary_title TEXT NOT NULL,
				summary_description TEXT NOT NULL,
				started_at TEXT NOT NULL,
				finished_at TEXT NOT NULL,
				duration_ns INTEGER NOT NULL,
				version TEXT NOT NULL,
				commit_hash TEXT NOT NULL,
				snapshot_schema_version TEXT NOT NULL,
				snapshot_json TEXT NOT NULL,
				created_at TEXT NOT NULL
			)`,
			`CREATE TABLE check_results (
				diagnosis_id TEXT NOT NULL,
				position INTEGER NOT NULL,
				check_id TEXT NOT NULL,
				name TEXT NOT NULL,
				status TEXT NOT NULL,
				started_at TEXT NOT NULL,
				finished_at TEXT NOT NULL,
				duration_ns INTEGER NOT NULL,
				summary TEXT NOT NULL,
				error_code TEXT NOT NULL,
				PRIMARY KEY (diagnosis_id, position),
				FOREIGN KEY (diagnosis_id) REFERENCES diagnoses(id) ON DELETE CASCADE
			)`,
			`CREATE TABLE evidence (
				row_id INTEGER PRIMARY KEY AUTOINCREMENT,
				diagnosis_id TEXT NOT NULL,
				check_position INTEGER NOT NULL,
				position INTEGER NOT NULL,
				evidence_id TEXT NOT NULL,
				check_id TEXT NOT NULL,
				code TEXT NOT NULL,
				message TEXT NOT NULL,
				details_json TEXT NOT NULL,
				FOREIGN KEY (diagnosis_id, check_position)
					REFERENCES check_results(diagnosis_id, position) ON DELETE CASCADE
			)`,
			`CREATE TABLE recommendations (
				row_id INTEGER PRIMARY KEY AUTOINCREMENT,
				diagnosis_id TEXT NOT NULL,
				scope TEXT NOT NULL,
				check_position INTEGER,
				position INTEGER NOT NULL,
				recommendation_id TEXT NOT NULL,
				check_id TEXT NOT NULL,
				priority TEXT NOT NULL,
				message TEXT NOT NULL,
				FOREIGN KEY (diagnosis_id) REFERENCES diagnoses(id) ON DELETE CASCADE,
				FOREIGN KEY (diagnosis_id, check_position)
					REFERENCES check_results(diagnosis_id, position) ON DELETE CASCADE
			)`,
			`CREATE INDEX diagnoses_started_at_idx ON diagnoses(started_at DESC, id DESC)`,
			`CREATE INDEX diagnoses_status_started_at_idx ON diagnoses(status, started_at DESC)`,
			`CREATE INDEX diagnoses_target_idx ON diagnoses(target_normalized COLLATE NOCASE)`,
			`CREATE INDEX evidence_diagnosis_idx ON evidence(diagnosis_id, check_position, position)`,
			`CREATE INDEX recommendations_diagnosis_idx
				ON recommendations(diagnosis_id, scope, check_position, position)`,
		},
	},
	{
		version: 2,
		statements: []string{
			`CREATE TABLE profiles (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL,
				target TEXT NOT NULL,
				ip_version TEXT NOT NULL,
				timeout_ns INTEGER NOT NULL,
				check_timeout_ns INTEGER NOT NULL,
				no_proxy INTEGER NOT NULL,
				insecure INTEGER NOT NULL,
				enable_tls INTEGER NOT NULL,
				max_redirects INTEGER NOT NULL,
				method TEXT NOT NULL,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			)`,
			`CREATE INDEX profiles_name_idx ON profiles(name COLLATE NOCASE, id)`,
		},
	},
	{
		version: 3,
		statements: []string{
			`ALTER TABLE profiles
			 ADD COLUMN mode TEXT NOT NULL DEFAULT 'auto'
			 CHECK (mode IN ('auto', 'tcp', 'tls'))`,
			`UPDATE profiles SET mode = 'tls' WHERE enable_tls = 1`,
		},
	},
}

func migrate(ctx context.Context, db *sql.DB) error {
	var version int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read SQLite schema version: %w", err)
	}
	if version > CurrentSchemaVersion {
		return fmt.Errorf(
			"database schema version %d is newer than supported version %d",
			version,
			CurrentSchemaVersion,
		)
	}

	for _, item := range migrations {
		if item.version <= version {
			continue
		}
		if item.version != version+1 {
			return fmt.Errorf("missing SQLite migration from version %d", version)
		}
		if err := applyMigration(ctx, db, item); err != nil {
			return err
		}
		version = item.version
	}
	return nil
}

func applyMigration(ctx context.Context, db *sql.DB, item migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin SQLite migration %d: %w", item.version, err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	for _, statement := range item.statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply SQLite migration %d: %w", item.version, err)
		}
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO metadata(key, value) VALUES('schema_version', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		fmt.Sprintf("%d", item.version),
	); err != nil {
		return fmt.Errorf("record SQLite migration %d: %w", item.version, err)
	}
	if _, err := tx.ExecContext(
		ctx,
		fmt.Sprintf("PRAGMA user_version = %d", item.version),
	); err != nil {
		return fmt.Errorf("set SQLite schema version %d: %w", item.version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit SQLite migration %d: %w", item.version, err)
	}
	return nil
}
