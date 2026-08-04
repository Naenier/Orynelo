package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

// CreateProfile stores reusable, redacted diagnostic settings.
func (s *Store) CreateProfile(
	ctx context.Context,
	profile model.Profile,
) (model.Profile, error) {
	profile = sanitizeProfile(profile)
	profile.ID = 0
	if err := validateProfile(profile); err != nil {
		return model.Profile{}, err
	}
	now := s.now()
	profile.CreatedAt = now
	profile.UpdatedAt = now

	result, err := s.db.ExecContext(
		ctx,
		`INSERT INTO profiles(
			name, target, mode, ip_version, timeout_ns, check_timeout_ns, no_proxy,
			insecure, enable_tls, max_redirects, method, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		profile.Name,
		profile.Target,
		profile.Mode,
		profile.IPVersion,
		int64(profile.Timeout),
		int64(profile.CheckTimeout),
		profile.NoProxy,
		false,
		profile.EnableTLS,
		profile.MaxRedirects,
		profile.Method,
		formatTime(profile.CreatedAt),
		formatTime(profile.UpdatedAt),
	)
	if err != nil {
		return model.Profile{}, fmt.Errorf("create profile %q: %w", profile.Name, err)
	}
	profile.ID, err = result.LastInsertId()
	if err != nil {
		return model.Profile{}, fmt.Errorf("read created profile ID: %w", err)
	}
	return profile, nil
}

// GetProfile loads one saved profile.
func (s *Store) GetProfile(ctx context.Context, id int64) (model.Profile, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT id, name, target, mode, ip_version, timeout_ns, check_timeout_ns,
			no_proxy, insecure, enable_tls, max_redirects, method, created_at,
			updated_at
		 FROM profiles WHERE id = ?`,
		id,
	)
	profile, err := scanProfile(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Profile{}, fmt.Errorf("%w: profile %d", ErrNotFound, id)
	}
	if err != nil {
		return model.Profile{}, fmt.Errorf("load profile %d: %w", id, err)
	}
	return profile, nil
}

// ListProfiles returns profiles in case-insensitive name order.
func (s *Store) ListProfiles(ctx context.Context) ([]model.Profile, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT id, name, target, mode, ip_version, timeout_ns, check_timeout_ns,
			no_proxy, insecure, enable_tls, max_redirects, method, created_at,
			updated_at
		 FROM profiles
		 ORDER BY name COLLATE NOCASE ASC, id ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list profiles: %w", err)
	}
	defer rows.Close()

	profiles := make([]model.Profile, 0)
	for rows.Next() {
		profile, err := scanProfile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan profile: %w", err)
		}
		profiles = append(profiles, profile)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate profiles: %w", err)
	}
	return profiles, nil
}

// UpdateProfile replaces editable settings while preserving creation time.
func (s *Store) UpdateProfile(
	ctx context.Context,
	profile model.Profile,
) (model.Profile, error) {
	if profile.ID <= 0 {
		return model.Profile{}, errors.New("profile ID must be positive")
	}
	profile = sanitizeProfile(profile)
	if err := validateProfile(profile); err != nil {
		return model.Profile{}, err
	}

	var createdAt string
	err := s.db.QueryRowContext(
		ctx,
		`SELECT created_at FROM profiles WHERE id = ?`,
		profile.ID,
	).Scan(&createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Profile{}, fmt.Errorf("%w: profile %d", ErrNotFound, profile.ID)
	}
	if err != nil {
		return model.Profile{}, fmt.Errorf("load profile %d creation time: %w", profile.ID, err)
	}
	profile.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return model.Profile{}, err
	}
	profile.UpdatedAt = s.now()

	result, err := s.db.ExecContext(
		ctx,
		`UPDATE profiles SET
			name = ?, target = ?, mode = ?, ip_version = ?, timeout_ns = ?,
			check_timeout_ns = ?, no_proxy = ?, insecure = ?, enable_tls = ?,
			max_redirects = ?, method = ?, updated_at = ?
		 WHERE id = ?`,
		profile.Name,
		profile.Target,
		profile.Mode,
		profile.IPVersion,
		int64(profile.Timeout),
		int64(profile.CheckTimeout),
		profile.NoProxy,
		false,
		profile.EnableTLS,
		profile.MaxRedirects,
		profile.Method,
		formatTime(profile.UpdatedAt),
		profile.ID,
	)
	if err != nil {
		return model.Profile{}, fmt.Errorf("update profile %d: %w", profile.ID, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return model.Profile{}, fmt.Errorf("inspect update of profile %d: %w", profile.ID, err)
	}
	if affected == 0 {
		return model.Profile{}, fmt.Errorf("%w: profile %d", ErrNotFound, profile.ID)
	}
	return profile, nil
}

// DuplicateProfile copies a profile with a new identity. An empty new name
// receives a readable "(copy)" suffix.
func (s *Store) DuplicateProfile(
	ctx context.Context,
	id int64,
	newName string,
) (model.Profile, error) {
	original, err := s.GetProfile(ctx, id)
	if err != nil {
		return model.Profile{}, err
	}
	original.ID = 0
	original.CreatedAt = time.Time{}
	original.UpdatedAt = time.Time{}
	if strings.TrimSpace(newName) == "" {
		original.Name += " (copy)"
	} else {
		original.Name = newName
	}
	return s.CreateProfile(ctx, original)
}

// DeleteProfile removes one saved profile without affecting history.
func (s *Store) DeleteProfile(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM profiles WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete profile %d: %w", id, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect deletion of profile %d: %w", id, err)
	}
	if affected == 0 {
		return fmt.Errorf("%w: profile %d", ErrNotFound, id)
	}
	return nil
}

func validateProfile(profile model.Profile) error {
	var problems []string
	if profile.Name == "" || len(profile.Name) > 128 || containsControl(profile.Name) {
		problems = append(problems, "name must contain 1 to 128 characters without control characters")
	}
	if profile.Target == "" || len(profile.Target) > 4096 || containsControl(profile.Target) {
		problems = append(problems, "target must contain 1 to 4096 characters without control characters")
	}
	if !profile.Mode.Valid() {
		problems = append(problems, `mode must be "auto", "tcp", or "tls"`)
	}
	if !profile.IPVersion.Valid() {
		problems = append(problems, `IP version must be "auto", "4", or "6"`)
	}
	if profile.Timeout <= 0 || profile.Timeout > 24*time.Hour {
		problems = append(problems, "timeout must be greater than zero and at most 24h")
	}
	if profile.CheckTimeout <= 0 || profile.CheckTimeout > profile.Timeout {
		problems = append(problems, "check timeout must be greater than zero and no longer than timeout")
	}
	if profile.MaxRedirects < 0 || profile.MaxRedirects > 50 {
		problems = append(problems, "maximum redirects must be between 0 and 50")
	}
	if !validHTTPMethod(profile.Method) {
		problems = append(problems, "HTTP method is invalid")
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid profile: %s", strings.Join(problems, "; "))
	}
	return nil
}

func containsControl(value string) bool {
	for _, char := range value {
		if unicode.IsControl(char) {
			return true
		}
	}
	return false
}

func validHTTPMethod(method string) bool {
	switch method {
	case "GET", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}

type scanner interface {
	Scan(dest ...any) error
}

func scanProfile(source scanner) (model.Profile, error) {
	var profile model.Profile
	var mode, ipVersion, createdAt, updatedAt string
	var timeout, checkTimeout int64
	var noProxy, legacyInsecure, enableTLS int
	err := source.Scan(
		&profile.ID,
		&profile.Name,
		&profile.Target,
		&mode,
		&ipVersion,
		&timeout,
		&checkTimeout,
		&noProxy,
		&legacyInsecure,
		&enableTLS,
		&profile.MaxRedirects,
		&profile.Method,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return model.Profile{}, err
	}
	profile.Mode = model.DiagnosticMode(mode)
	profile.IPVersion = model.IPVersion(ipVersion)
	profile.Timeout = time.Duration(timeout)
	profile.CheckTimeout = time.Duration(checkTimeout)
	profile.NoProxy = noProxy != 0
	// The legacy insecure column remains for schema compatibility, but
	// insecure TLS is a run-only control and is never restored from a profile.
	profile.EnableTLS = enableTLS != 0
	profile.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return model.Profile{}, err
	}
	profile.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return model.Profile{}, err
	}
	return profile, nil
}
