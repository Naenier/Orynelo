package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Naenier/opsdoctor/internal/diagnostics/model"
)

const (
	// DefaultMaxHistoryEntries is used when a caller supplies no retention
	// limit.
	DefaultMaxHistoryEntries = 200

	maxHistoryEntries = 10_000
	maxHistoryPage    = 1_000
	maxSnapshotBytes  = 8 << 20
)

// DiagnosisSnapshot is the versioned JSON envelope stored as an additional
// portable representation of normalized history rows.
type DiagnosisSnapshot struct {
	SchemaVersion string          `json:"schemaVersion"`
	Diagnosis     model.Diagnosis `json:"diagnosis"`
}

// Persistence query aliases retain the storage package's public names while
// keeping the application-facing contract in the domain model.
type HistorySort = model.HistorySort

// HistoryQuery aliases the domain history query used by storage callers.
type HistoryQuery = model.HistoryQuery

const (
	HistorySortDate     = model.HistorySortDate
	HistorySortTarget   = model.HistorySortTarget
	HistorySortStatus   = model.HistorySortStatus
	HistorySortDuration = model.HistorySortDuration
	HistorySortVersion  = model.HistorySortVersion
)

// SaveDiagnosis persists normalized rows and a versioned JSON snapshot in one
// transaction, then applies history retention.
func (s *Store) SaveDiagnosis(
	ctx context.Context,
	diagnosis model.Diagnosis,
	maxEntries int,
) error {
	if maxEntries == 0 {
		maxEntries = DefaultMaxHistoryEntries
	}
	if maxEntries < 1 || maxEntries > maxHistoryEntries {
		return fmt.Errorf("maximum history entries must be between 1 and %d", maxHistoryEntries)
	}

	diagnosis = sanitizeDiagnosis(diagnosis)
	if err := validateDiagnosis(diagnosis); err != nil {
		return err
	}
	snapshot := DiagnosisSnapshot{
		SchemaVersion: SnapshotSchemaVersion,
		Diagnosis:     diagnosis,
	}
	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode diagnosis snapshot: %w", err)
	}
	if len(snapshotJSON) > maxSnapshotBytes {
		return fmt.Errorf("diagnosis snapshot exceeds %d bytes", maxSnapshotBytes)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin diagnosis save: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO diagnoses(
			id, target_original, target_normalized, target_host, target_port,
			target_scheme, status, summary_title, summary_description,
			started_at, finished_at, duration_ns, version, commit_hash,
			snapshot_schema_version, snapshot_json, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			target_original = excluded.target_original,
			target_normalized = excluded.target_normalized,
			target_host = excluded.target_host,
			target_port = excluded.target_port,
			target_scheme = excluded.target_scheme,
			status = excluded.status,
			summary_title = excluded.summary_title,
			summary_description = excluded.summary_description,
			started_at = excluded.started_at,
			finished_at = excluded.finished_at,
			duration_ns = excluded.duration_ns,
			version = excluded.version,
			commit_hash = excluded.commit_hash,
			snapshot_schema_version = excluded.snapshot_schema_version,
			snapshot_json = excluded.snapshot_json`,
		diagnosis.ID,
		diagnosis.Target.Original,
		diagnosis.Target.Normalized,
		diagnosis.Target.Host,
		diagnosis.Target.Port,
		diagnosis.Target.Scheme,
		diagnosis.Summary.Status,
		diagnosis.Summary.Title,
		diagnosis.Summary.Description,
		formatTime(diagnosis.StartedAt),
		formatTime(diagnosis.FinishedAt),
		int64(diagnosis.Duration),
		diagnosis.Build.Version,
		diagnosis.Build.Commit,
		SnapshotSchemaVersion,
		string(snapshotJSON),
		formatTime(s.now()),
	); err != nil {
		return fmt.Errorf("store diagnosis %q: %w", diagnosis.ID, err)
	}

	for _, statement := range []string{
		`DELETE FROM recommendations WHERE diagnosis_id = ?`,
		`DELETE FROM evidence WHERE diagnosis_id = ?`,
		`DELETE FROM check_results WHERE diagnosis_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, statement, diagnosis.ID); err != nil {
			return fmt.Errorf("replace normalized diagnosis %q: %w", diagnosis.ID, err)
		}
	}

	for checkPosition, check := range diagnosis.Checks {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO check_results(
				diagnosis_id, position, check_id, name, status, started_at,
				finished_at, duration_ns, summary, error_code
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			diagnosis.ID,
			checkPosition,
			check.ID,
			check.Name,
			check.Status,
			formatTime(check.StartedAt),
			formatTime(check.FinishedAt),
			int64(check.Duration),
			check.Summary,
			check.ErrorCode,
		); err != nil {
			return fmt.Errorf("store check %q for diagnosis %q: %w", check.ID, diagnosis.ID, err)
		}
		for evidencePosition, evidence := range check.Evidence {
			detailsJSON, err := json.Marshal(evidence.Details)
			if err != nil {
				return fmt.Errorf("encode evidence details for check %q: %w", check.ID, err)
			}
			if _, err := tx.ExecContext(
				ctx,
				`INSERT INTO evidence(
					diagnosis_id, check_position, position, evidence_id,
					check_id, code, message, details_json
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				diagnosis.ID,
				checkPosition,
				evidencePosition,
				evidence.ID,
				evidence.CheckID,
				evidence.Code,
				evidence.Message,
				string(detailsJSON),
			); err != nil {
				return fmt.Errorf("store evidence for check %q: %w", check.ID, err)
			}
		}
		for recommendationPosition, recommendation := range check.Recommendations {
			if err := insertRecommendation(
				ctx,
				tx,
				diagnosis.ID,
				"check",
				checkPosition,
				recommendationPosition,
				recommendation,
			); err != nil {
				return err
			}
		}
	}
	for position, recommendation := range diagnosis.Summary.Recommendations {
		if err := insertRecommendation(
			ctx,
			tx,
			diagnosis.ID,
			"summary",
			nil,
			position,
			recommendation,
		); err != nil {
			return err
		}
	}

	if err := pruneHistoryTx(ctx, tx, maxEntries); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit diagnosis %q: %w", diagnosis.ID, err)
	}
	return nil
}

func insertRecommendation(
	ctx context.Context,
	tx *sql.Tx,
	diagnosisID string,
	scope string,
	checkPosition any,
	position int,
	recommendation model.Recommendation,
) error {
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO recommendations(
			diagnosis_id, scope, check_position, position, recommendation_id,
			check_id, priority, message
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		diagnosisID,
		scope,
		checkPosition,
		position,
		recommendation.ID,
		recommendation.CheckID,
		recommendation.Priority,
		recommendation.Message,
	); err != nil {
		return fmt.Errorf("store %s recommendation for diagnosis %q: %w", scope, diagnosisID, err)
	}
	return nil
}

func validateDiagnosis(diagnosis model.Diagnosis) error {
	if !validIdentifier(diagnosis.ID) {
		return errors.New("diagnosis ID must contain 1 to 128 safe identifier characters")
	}
	if diagnosis.StartedAt.IsZero() || diagnosis.FinishedAt.IsZero() {
		return errors.New("diagnosis start and finish timestamps are required")
	}
	if diagnosis.FinishedAt.Before(diagnosis.StartedAt) {
		return errors.New("diagnosis finish timestamp precedes start timestamp")
	}
	if diagnosis.Duration < 0 {
		return errors.New("diagnosis duration must not be negative")
	}
	if !diagnosis.Summary.Status.Valid() {
		return fmt.Errorf("diagnosis has invalid status %q", diagnosis.Summary.Status)
	}
	if diagnosis.Summary.Status == model.StatusPending || diagnosis.Summary.Status == model.StatusRunning {
		return fmt.Errorf("diagnosis has incomplete status %q", diagnosis.Summary.Status)
	}
	for position, check := range diagnosis.Checks {
		if strings.TrimSpace(check.ID) == "" {
			return fmt.Errorf("check at position %d has an empty ID", position)
		}
		if !check.Status.Valid() {
			return fmt.Errorf("check %q has invalid status %q", check.ID, check.Status)
		}
		if check.Status == model.StatusPending || check.Status == model.StatusRunning {
			return fmt.Errorf("check %q has incomplete status %q", check.ID, check.Status)
		}
		if check.StartedAt.IsZero() || check.FinishedAt.IsZero() {
			return fmt.Errorf("check %q is missing timestamps", check.ID)
		}
		if check.FinishedAt.Before(check.StartedAt) || check.Duration < 0 {
			return fmt.Errorf("check %q has invalid timing", check.ID)
		}
	}
	return nil
}

func validIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == '-', char == '_', char == '.', char == ':':
		default:
			return false
		}
	}
	return true
}

// GetDiagnosis loads a complete diagnosis from its versioned snapshot.
func (s *Store) GetDiagnosis(ctx context.Context, id string) (model.Diagnosis, error) {
	snapshot, err := s.GetSnapshot(ctx, id)
	if err != nil {
		return model.Diagnosis{}, err
	}
	return snapshot.Diagnosis, nil
}

// GetSnapshot loads and validates the portable JSON snapshot.
func (s *Store) GetSnapshot(ctx context.Context, id string) (DiagnosisSnapshot, error) {
	var schemaVersion, raw string
	err := s.db.QueryRowContext(
		ctx,
		`SELECT snapshot_schema_version, snapshot_json FROM diagnoses WHERE id = ?`,
		id,
	).Scan(&schemaVersion, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return DiagnosisSnapshot{}, fmt.Errorf("%w: diagnosis %q", ErrNotFound, id)
	}
	if err != nil {
		return DiagnosisSnapshot{}, fmt.Errorf("load diagnosis %q: %w", id, err)
	}
	if schemaVersion != SnapshotSchemaVersion {
		return DiagnosisSnapshot{}, fmt.Errorf(
			"diagnosis %q uses unsupported snapshot schema %q",
			id,
			schemaVersion,
		)
	}
	var snapshot DiagnosisSnapshot
	if err := json.Unmarshal([]byte(raw), &snapshot); err != nil {
		return DiagnosisSnapshot{}, fmt.Errorf("decode diagnosis %q snapshot: %w", id, err)
	}
	if snapshot.SchemaVersion != schemaVersion {
		return DiagnosisSnapshot{}, fmt.Errorf(
			"diagnosis %q snapshot schema mismatch: row=%q JSON=%q",
			id,
			schemaVersion,
			snapshot.SchemaVersion,
		)
	}
	if snapshot.Diagnosis.ID != id {
		return DiagnosisSnapshot{}, fmt.Errorf(
			"diagnosis %q snapshot contains ID %q",
			id,
			snapshot.Diagnosis.ID,
		)
	}
	return snapshot, nil
}

// ListHistory returns compact history rows matching a query.
func (s *Store) ListHistory(
	ctx context.Context,
	query HistoryQuery,
) ([]model.HistoryEntry, error) {
	orderColumn, err := historyOrderColumn(query.Sort)
	if err != nil {
		return nil, err
	}
	if query.Limit == 0 {
		query.Limit = DefaultMaxHistoryEntries
	}
	if query.Limit < 1 || query.Limit > maxHistoryPage {
		return nil, fmt.Errorf("history query limit must be between 1 and %d", maxHistoryPage)
	}
	if query.Offset < 0 {
		return nil, errors.New("history query offset must not be negative")
	}
	if len(query.Search) > 4096 {
		return nil, errors.New("history search must not exceed 4096 characters")
	}
	if query.Status != "" && !query.Status.Valid() {
		return nil, fmt.Errorf("invalid history status %q", query.Status)
	}

	var where []string
	var args []any
	if search := strings.TrimSpace(query.Search); search != "" {
		where = append(
			where,
			`(target_original LIKE ? ESCAPE '\' COLLATE NOCASE
				OR target_normalized LIKE ? ESCAPE '\' COLLATE NOCASE)`,
		)
		pattern := "%" + escapeLike(search) + "%"
		args = append(args, pattern, pattern)
	}
	if query.Status != "" {
		where = append(where, "status = ?")
		args = append(args, query.Status)
	}

	statement := `SELECT id, started_at, target_original, status, duration_ns, version FROM diagnoses`
	if len(where) > 0 {
		statement += " WHERE " + strings.Join(where, " AND ")
	}
	direction := "DESC"
	if query.Ascending {
		direction = "ASC"
	}
	statement += " ORDER BY " + orderColumn + " " + direction + ", id " + direction + " LIMIT ? OFFSET ?"
	args = append(args, query.Limit, query.Offset)

	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, fmt.Errorf("list diagnostic history: %w", err)
	}
	defer rows.Close()

	entries := make([]model.HistoryEntry, 0)
	for rows.Next() {
		var entry model.HistoryEntry
		var date, status string
		var duration int64
		if err := rows.Scan(
			&entry.ID,
			&date,
			&entry.Target,
			&status,
			&duration,
			&entry.Version,
		); err != nil {
			return nil, fmt.Errorf("scan diagnostic history: %w", err)
		}
		entry.Date, err = parseTime(date)
		if err != nil {
			return nil, err
		}
		entry.Status = model.Status(status)
		entry.Duration = time.Duration(duration)
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate diagnostic history: %w", err)
	}
	return entries, nil
}

func historyOrderColumn(sort HistorySort) (string, error) {
	switch sort {
	case "", HistorySortDate:
		return "started_at", nil
	case HistorySortTarget:
		return "target_normalized COLLATE NOCASE", nil
	case HistorySortStatus:
		return "status", nil
	case HistorySortDuration:
		return "duration_ns", nil
	case HistorySortVersion:
		return "version COLLATE NOCASE", nil
	default:
		return "", fmt.Errorf("invalid history sort %q", sort)
	}
}

func escapeLike(value string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		`%`, `\%`,
		`_`, `\_`,
	)
	return replacer.Replace(value)
}

// DeleteDiagnosis removes one diagnosis and all normalized child rows.
func (s *Store) DeleteDiagnosis(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM diagnoses WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete diagnosis %q: %w", id, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect deletion of diagnosis %q: %w", id, err)
	}
	if affected == 0 {
		return fmt.Errorf("%w: diagnosis %q", ErrNotFound, id)
	}
	return nil
}

// ClearHistory removes every diagnosis but leaves saved profiles intact.
func (s *Store) ClearHistory(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM diagnoses`); err != nil {
		return fmt.Errorf("clear diagnostic history: %w", err)
	}
	return nil
}

// HistoryCount reports the number of stored diagnostic runs.
func (s *Store) HistoryCount(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM diagnoses`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count diagnostic history: %w", err)
	}
	return count, nil
}

// PruneHistory applies a new retention limit immediately.
func (s *Store) PruneHistory(ctx context.Context, maxEntries int) error {
	if maxEntries < 1 || maxEntries > maxHistoryEntries {
		return fmt.Errorf("maximum history entries must be between 1 and %d", maxHistoryEntries)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin history pruning: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if err := pruneHistoryTx(ctx, tx, maxEntries); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit history pruning: %w", err)
	}
	return nil
}

func pruneHistoryTx(ctx context.Context, tx *sql.Tx, maxEntries int) error {
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM diagnoses
		 WHERE id IN (
			SELECT id FROM diagnoses
			ORDER BY started_at DESC, created_at DESC, id DESC
			LIMIT -1 OFFSET ?
		 )`,
		maxEntries,
	); err != nil {
		return fmt.Errorf("prune diagnostic history to %d entries: %w", maxEntries, err)
	}
	return nil
}
