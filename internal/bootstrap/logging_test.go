package bootstrap

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestLoggingRedactsSecretsAndUpdatesLevel(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	logging, err := newLogging(&buffer, "info")
	if err != nil {
		t.Fatal(err)
	}
	logging.Logger.Debug("hidden")
	if strings.Contains(buffer.String(), "hidden") {
		t.Fatal("debug message was emitted at info level")
	}
	if err := logging.SetLevel("debug"); err != nil {
		t.Fatal(err)
	}
	logging.Logger.Debug(
		"request https://alice:secret@example.test/?token=top-secret",
		slog.String("Authorization", "Bearer private"),
	)
	text := buffer.String()
	if !strings.Contains(text, `"level":"DEBUG"`) {
		t.Fatalf("dynamic log level was not applied: %s", text)
	}
	for _, secret := range []string{"alice", "secret", "top-secret", "Bearer private"} {
		if strings.Contains(text, secret) {
			t.Fatalf("log contains %q: %s", secret, text)
		}
	}
	if !strings.Contains(text, "[REDACTED]") {
		t.Fatalf("log does not contain redaction marker: %s", text)
	}
}
