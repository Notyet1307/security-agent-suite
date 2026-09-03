package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/app"
	"github.com/Notyet1307/security-agent-suite/internal/artifacts"
	"github.com/Notyet1307/security-agent-suite/internal/catalog"
	"github.com/Notyet1307/security-agent-suite/internal/domain"
	mockexecutor "github.com/Notyet1307/security-agent-suite/internal/executor/mock"
	"github.com/Notyet1307/security-agent-suite/internal/observability"
	"github.com/Notyet1307/security-agent-suite/internal/policy"
	"github.com/Notyet1307/security-agent-suite/internal/prompt"
	memorystore "github.com/Notyet1307/security-agent-suite/internal/store/memory"
)

func TestHTTPRunLifecycleAndTenantIsolation(t *testing.T) {
	agentCatalog, err := catalog.Load("../../configs/agents.json")
	if err != nil {
		t.Fatal(err)
	}
	artifactStore, err := artifacts.New(filepath.Join(t.TempDir(), "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	metrics := observability.NewMetrics()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service := app.New(app.Config{Workers: 1, QueueSize: 4, MaxRunTimeout: time.Minute}, memorystore.New(), agentCatalog, policy.New(), mockexecutor.New(artifactStore), prompt.New(), metrics, logger)
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	server := httptest.NewServer(New(Config{APIKey: "test-key", MaxBodyBytes: 1 << 20, RateLimitPerMinute: 1000}, service, artifactStore, metrics, logger).Handler())
	defer server.Close()

	resp, err := http.Get(server.URL + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("health status=%v err=%v", responseStatus(resp), err)
	}
	_ = resp.Body.Close()

	resp, err = http.Get(server.URL + "/v1/agents")
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%v err=%v", responseStatus(resp), err)
	}
	_ = resp.Body.Close()

	requestBody := domain.CreateRunRequest{RequestID: "http-run-1", Mode: "triage", Inputs: []domain.InputRef{{Type: "alert", URI: "artifact://alerts/1"}}, Scope: domain.Scope{TenantID: "tenant-a"}}
	data, _ := json.Marshal(requestBody)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/agents/event-triage/runs", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-key")
	req.Header.Set("X-Tenant-ID", "tenant-a")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create status=%d body=%s", resp.StatusCode, body)
	}
	var created domain.Run
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		loaded := getRunHTTP(t, server.URL, "test-key", "tenant-a", created.ID)
		if loaded.Status.Terminal() {
			if loaded.Status != domain.RunStatusSucceeded || loaded.Result == nil || len(loaded.Result.Artifacts) != 1 {
				t.Fatalf("unexpected completed run: %+v", loaded)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	req, _ = http.NewRequest(http.MethodGet, server.URL+"/v1/runs/"+created.ID, nil)
	req.Header.Set("X-API-Key", "test-key")
	req.Header.Set("X-Tenant-ID", "tenant-b")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-tenant read should be hidden, got %d", resp.StatusCode)
	}
}

func getRunHTTP(t *testing.T, baseURL, apiKey, tenantID, runID string) domain.Run {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v1/runs/"+runID, nil)
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("X-Tenant-ID", tenantID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var run domain.Run
	if err := json.NewDecoder(resp.Body).Decode(&run); err != nil {
		t.Fatal(err)
	}
	return run
}

func responseStatus(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}
