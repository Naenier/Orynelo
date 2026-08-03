package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestJSONTimestampsAreAlwaysUTC(t *testing.T) {
	t.Parallel()

	offset := time.FixedZone("non-utc", 5*60*60+30*60)
	value := time.Date(2026, 8, 3, 15, 45, 12, 123000000, offset)
	values := []struct {
		name  string
		value any
	}{
		{name: "diagnosis", value: Diagnosis{StartedAt: value, FinishedAt: value}},
		{name: "check", value: CheckResult{StartedAt: value, FinishedAt: value}},
		{name: "event", value: CheckEvent{At: value}},
		{name: "profile", value: Profile{CreatedAt: value, UpdatedAt: value}},
		{name: "history", value: HistoryEntry{Date: value}},
		{name: "certificate", value: CertificateInfo{NotBefore: value, NotAfter: value}},
	}
	for _, test := range values {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			encoded, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			text := string(encoded)
			if strings.Contains(text, "+05:30") || !strings.Contains(text, "Z") {
				t.Fatalf("JSON timestamp is not UTC: %s", text)
			}
		})
	}
}
