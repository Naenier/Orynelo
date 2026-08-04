//go:build integration

package diagnostics

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Naenier/orynelo/internal/diagnostics/model"
)

func TestIntegrationLoopbackHTTPPipeline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.UserAgent() == "" {
			t.Error("request did not include a user agent")
		}
		writer.Header().Set("X-Orynelo-Test", "loopback")
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	options := model.DefaultDiagnoseOptions(server.URL)
	options.NoProxy = true
	diagnosis, err := NewRunner().Diagnose(context.Background(), options, nil)
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if diagnosis.Summary.Status != model.StatusPassed {
		t.Fatalf("overall status = %s, checks = %#v", diagnosis.Summary.Status, diagnosis.Checks)
	}
	assertIntegrationCheck(t, diagnosis, "tcp", model.StatusPassed)
	assertIntegrationCheck(t, diagnosis, "http", model.StatusPassed)
}

func TestIntegrationLoopbackTLSPipeline(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(writer, "ok")
	}))
	defer server.Close()

	options := model.DefaultDiagnoseOptions(server.URL)
	options.NoProxy = true
	options.Insecure = true
	diagnosis, err := NewRunner().Diagnose(context.Background(), options, nil)
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	assertIntegrationCheck(t, diagnosis, "tcp", model.StatusPassed)
	assertIntegrationCheck(t, diagnosis, "tls", model.StatusWarning)
	assertIntegrationCheck(t, diagnosis, "http", model.StatusPassed)
}

func assertIntegrationCheck(
	t *testing.T,
	diagnosis model.Diagnosis,
	id string,
	want model.Status,
) {
	t.Helper()
	for _, check := range diagnosis.Checks {
		if check.ID == id {
			if check.Status != want {
				t.Fatalf("%s status = %s, want %s: %#v", id, check.Status, want, check)
			}
			return
		}
	}
	t.Fatalf("diagnosis did not include %q: %#v", id, diagnosis.Checks)
}
