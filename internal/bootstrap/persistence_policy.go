package bootstrap

import (
	"fmt"
	"strings"
)

// PersistencePolicy controls which optional local adapters bootstrap opens.
type PersistencePolicy string

const (
	// PersistenceDefault enables configuration, logging, and history while
	// allowing diagnostics to continue when an optional adapter is unavailable.
	PersistenceDefault PersistencePolicy = "default"
	// PersistenceNoHistory enables configuration and logging but never opens
	// the history/profile database.
	PersistenceNoHistory PersistencePolicy = "no-history"
	// PersistenceEphemeral runs entirely in memory and performs no filesystem
	// discovery, directory creation, logging, configuration, or database I/O.
	PersistenceEphemeral PersistencePolicy = "ephemeral"
)

// ParsePersistencePolicy validates a command-line persistence policy.
func ParsePersistencePolicy(value string) (PersistencePolicy, error) {
	policy := PersistencePolicy(strings.ToLower(strings.TrimSpace(value)))
	if policy == "" {
		policy = PersistenceDefault
	}
	switch policy {
	case PersistenceDefault, PersistenceNoHistory, PersistenceEphemeral:
		return policy, nil
	default:
		return "", fmt.Errorf("persistence policy must be default, no-history, or ephemeral")
	}
}

// RuntimeOptions controls composition of optional runtime adapters.
type RuntimeOptions struct {
	Persistence PersistencePolicy
}
