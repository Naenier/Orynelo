package model

import (
	"encoding/json"
	"time"
)

// MarshalJSON enforces the public UTC contract independently of the process
// timezone or the offset carried by an injected clock.
func (r CheckResult) MarshalJSON() ([]byte, error) {
	type alias CheckResult
	return json.Marshal(struct {
		alias
		StartedAt  time.Time `json:"startedAt"`
		FinishedAt time.Time `json:"finishedAt"`
	}{alias: alias(r), StartedAt: jsonUTC(r.StartedAt), FinishedAt: jsonUTC(r.FinishedAt)})
}

// MarshalJSON enforces UTC event timestamps.
func (e CheckEvent) MarshalJSON() ([]byte, error) {
	type alias CheckEvent
	return json.Marshal(struct {
		alias
		At time.Time `json:"at"`
	}{alias: alias(e), At: jsonUTC(e.At)})
}

// MarshalJSON enforces UTC diagnosis timestamps.
func (d Diagnosis) MarshalJSON() ([]byte, error) {
	type alias Diagnosis
	return json.Marshal(struct {
		alias
		StartedAt  time.Time `json:"startedAt"`
		FinishedAt time.Time `json:"finishedAt"`
	}{alias: alias(d), StartedAt: jsonUTC(d.StartedAt), FinishedAt: jsonUTC(d.FinishedAt)})
}

// MarshalJSON enforces UTC profile timestamps.
func (p Profile) MarshalJSON() ([]byte, error) {
	type alias Profile
	return json.Marshal(struct {
		alias
		CreatedAt time.Time `json:"createdAt"`
		UpdatedAt time.Time `json:"updatedAt"`
	}{alias: alias(p), CreatedAt: jsonUTC(p.CreatedAt), UpdatedAt: jsonUTC(p.UpdatedAt)})
}

// MarshalJSON enforces UTC history timestamps.
func (h HistoryEntry) MarshalJSON() ([]byte, error) {
	type alias HistoryEntry
	return json.Marshal(struct {
		alias
		Date time.Time `json:"date"`
	}{alias: alias(h), Date: jsonUTC(h.Date)})
}

// MarshalJSON enforces UTC certificate validity timestamps.
func (c CertificateInfo) MarshalJSON() ([]byte, error) {
	type alias CertificateInfo
	return json.Marshal(struct {
		alias
		NotBefore time.Time `json:"notBefore,omitempty"`
		NotAfter  time.Time `json:"notAfter,omitempty"`
	}{alias: alias(c), NotBefore: jsonUTC(c.NotBefore), NotAfter: jsonUTC(c.NotAfter)})
}

func jsonUTC(value time.Time) time.Time {
	if value.IsZero() {
		return value
	}
	return value.UTC()
}
