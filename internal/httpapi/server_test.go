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
	server := httptest.NewServer(New(Config{APIKey: "test-key", MaxBodyBytes: 1024, RateLimitPerMinute: 1000, Ready: func() bool { return true }}, service, artifactStore, metrics, logger).Handler())
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

	var completed domain.Run
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		loaded := getRunHTTP(t, server.URL, "test-key", "tenant-a", created.ID)
		if loaded.Status.Terminal() {
			if loaded.Status != domain.RunStatusSucceeded || loaded.Result == nil || len(loaded.Result.Artifacts) != 1 {
				t.Fatalf("unexpected completed run: %+v", loaded)
			}
			completed = loaded
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !completed.Status.Terminal() {
		t.Fatal("run did not complete")
	}
	artifact := completed.Result.Artifacts[0]
	stored, _, err := artifactStore.Open(context.Background(), completed.ID, artifact)
	if err != nil {
		t.Fatal(err)
	}
	want, err := io.ReadAll(stored)
	_ = stored.Close()
	if err != nil {
		t.Fatal(err)
	}

	req, _ = http.NewRequest(http.MethodGet, server.URL+"/v1/runs/"+completed.ID+"/artifacts/"+artifact.ID, nil)
	req.Header.Set("X-API-Key", "test-key")
	req.Header.Set("X-Tenant-ID", "tenant-a")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("ETag") != `"sha256:`+artifact.SHA256+`"` || int64(len(got)) != artifact.SizeBytes || !bytes.Equal(got, want) {
		t.Fatalf("artifact download status=%d content-type=%q etag=%q size=%d want-size=%d body-match=%v", resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("ETag"), len(got), artifact.SizeBytes, bytes.Equal(got, want))
	}

	uploadBody := []byte("uploaded evidence")
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/v1/runs/"+completed.ID+"/artifacts?name=uploaded-evidence.txt", bytes.NewReader(uploadBody))
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("X-Artifact-SHA256", "cd95569c49f302489b692431d2e0b42a3487e598d4c95c240c76413c00fee80a")
	req.Header.Set("X-API-Key", "test-key")
	req.Header.Set("X-Tenant-ID", "tenant-a")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("artifact upload status=%d body=%s", resp.StatusCode, body)
	}
	var uploaded domain.ArtifactRef
	if err := json.NewDecoder(resp.Body).Decode(&uploaded); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if uploaded.Name != "uploaded-evidence.txt" || uploaded.MediaType != "text/plain; charset=utf-8" || uploaded.SHA256 != "cd95569c49f302489b692431d2e0b42a3487e598d4c95c240c76413c00fee80a" || uploaded.SizeBytes != int64(len(uploadBody)) {
		t.Fatalf("unexpected uploaded artifact: %+v", uploaded)
	}

	req, _ = http.NewRequest(http.MethodGet, server.URL+"/v1/runs/"+completed.ID+"/artifacts", nil)
	req.Header.Set("X-API-Key", "test-key")
	req.Header.Set("X-Tenant-ID", "tenant-a")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var listing struct {
		RunID     string               `json:"run_id"`
		Artifacts []domain.ArtifactRef `json:"artifacts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listing); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || listing.RunID != completed.ID || len(listing.Artifacts) != 2 {
		t.Fatalf("artifact listing status=%d body=%+v", resp.StatusCode, listing)
	}

	req, _ = http.NewRequest(http.MethodGet, server.URL+"/v1/runs/"+completed.ID+"/artifacts/"+uploaded.ID, nil)
	req.Header.Set("X-API-Key", "test-key")
	req.Header.Set("X-Tenant-ID", "tenant-a")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	uploadedDownload, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" || resp.Header.Get("ETag") != `"sha256:`+uploaded.SHA256+`"` || !bytes.Equal(uploadedDownload, uploadBody) {
		t.Fatalf("uploaded artifact download status=%d content-type=%q etag=%q body=%q", resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("ETag"), uploadedDownload)
	}

	req, _ = http.NewRequest(http.MethodPost, server.URL+"/v1/runs/"+completed.ID+"/artifacts?name=forbidden.txt", bytes.NewReader(uploadBody))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-API-Key", "test-key")
	req.Header.Set("X-Tenant-ID", "tenant-b")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var uploadFailure errorResponse
	if err := json.NewDecoder(resp.Body).Decode(&uploadFailure); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || uploadFailure.Error.Code != "not_found" {
		t.Fatalf("cross-tenant upload status=%d body=%+v", resp.StatusCode, uploadFailure)
	}

	req, _ = http.NewRequest(http.MethodPost, server.URL+"/v1/runs/"+completed.ID+"/artifacts?name=too-large.bin", bytes.NewReader(bytes.Repeat([]byte{'x'}, 1025)))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-API-Key", "test-key")
	req.Header.Set("X-Tenant-ID", "tenant-a")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	uploadFailure = errorResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&uploadFailure); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge || uploadFailure.Error.Code != "artifact_too_large" {
		t.Fatalf("oversized upload status=%d body=%+v", resp.StatusCode, uploadFailure)
	}

	req, _ = http.NewRequest(http.MethodGet, server.URL+"/v1/runs/"+completed.ID+"/artifacts/"+artifact.ID, nil)
	req.Header.Set("X-API-Key", "test-key")
	req.Header.Set("X-Tenant-ID", "tenant-b")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	otherTenantBody, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	var failure errorResponse
	if resp.StatusCode != http.StatusNotFound || bytes.Equal(otherTenantBody, want) || json.Unmarshal(otherTenantBody, &failure) != nil || failure.Error.Code != "not_found" {
		t.Fatalf("cross-tenant artifact response status=%d body=%s", resp.StatusCode, otherTenantBody)
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

func TestReadinessUsesInjectedState(t *testing.T) {
	metrics := observability.NewMetrics()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ready := false
	handler := New(Config{Ready: func() bool { return ready }}, nil, nil, metrics, logger).Handler()

	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	request.Header.Set("X-Request-ID", "readiness-test")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("not-ready status=%d body=%s", response.Code, response.Body.String())
	}
	var failure errorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &failure); err != nil {
		t.Fatalf("not-ready response is not structured JSON: %v", err)
	}
	if failure.Error.Code != "not_ready" || failure.Error.RequestID != "readiness-test" {
		t.Fatalf("not-ready response=%+v", failure)
	}

	healthRequest := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	healthResponse := httptest.NewRecorder()
	handler.ServeHTTP(healthResponse, healthRequest)
	if healthResponse.Code != http.StatusOK {
		t.Fatalf("health status=%d", healthResponse.Code)
	}

	ready = true
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("ready status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestReadinessDefaultsToNotReady(t *testing.T) {
	metrics := observability.NewMetrics()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := New(Config{}, nil, nil, metrics, logger).Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil readiness status=%d body=%s", response.Code, response.Body.String())
	}
}

type blockingCancelExecutor struct {
	started        chan struct{}
	cancelObserved chan struct{}
	release        chan struct{}
}

func (e *blockingCancelExecutor) Name() string { return "blocking-cancel" }

func (e *blockingCancelExecutor) Execute(ctx context.Context, _ domain.ExecutionRequest) (domain.ExecutionResult, error) {
	close(e.started)
	<-ctx.Done()
	close(e.cancelObserved)
	<-e.release
	return domain.ExecutionResult{Status: domain.RunStatusFailed, Result: domain.RunResult{Provenance: &domain.ExecutionProvenance{
		DaemonRunID: "daemon-http-canceled",
		SandboxID:   "sandbox-http-canceled",
		Status:      "canceled",
	}}}, ctx.Err()
}

func TestHTTPCancelRunStatusReflectsCancellationProgress(t *testing.T) {
	agentCatalog, err := catalog.Load("../../configs/agents.json")
	if err != nil {
		t.Fatal(err)
	}
	artifactStore, err := artifacts.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	newHarness := func(runtime *blockingCancelExecutor) (*app.Service, http.Handler) {
		metrics := observability.NewMetrics()
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		service := app.New(app.Config{Workers: 1, QueueSize: 4, MaxRunTimeout: time.Minute}, memorystore.New(), agentCatalog, policy.New(), runtime, prompt.New(), metrics, logger)
		return service, New(Config{APIKey: "test-key", RateLimitPerMinute: 1000}, service, artifactStore, metrics, logger).Handler()
	}
	cancel := func(t *testing.T, handler http.Handler, runID string) (int, domain.Run) {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/v1/runs/"+runID+"/cancel", bytes.NewBufferString(`{"actor":"tester","reason":"stop"}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-API-Key", "test-key")
		request.Header.Set("X-Tenant-ID", "tenant")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var run domain.Run
		if err := json.Unmarshal(response.Body.Bytes(), &run); err != nil {
			t.Fatalf("decode cancellation response: %v body=%s", err, response.Body.String())
		}
		return response.Code, run
	}
	get := func(t *testing.T, handler http.Handler, runID string) domain.Run {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "/v1/runs/"+runID, nil)
		request.Header.Set("X-API-Key", "test-key")
		request.Header.Set("X-Tenant-ID", "tenant")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("get run status=%d body=%s", response.Code, response.Body.String())
		}
		var run domain.Run
		if err := json.Unmarshal(response.Body.Bytes(), &run); err != nil {
			t.Fatalf("decode get run response: %v body=%s", err, response.Body.String())
		}
		return run
	}

	t.Run("running", func(t *testing.T) {
		runtime := &blockingCancelExecutor{started: make(chan struct{}), cancelObserved: make(chan struct{}), release: make(chan struct{})}
		service, handler := newHarness(runtime)
		if err := service.Start(); err != nil {
			t.Fatal(err)
		}
		defer service.Close()
		defer close(runtime.release)
		run, _, err := service.CreateRun(context.Background(), "event-triage", domain.CreateRunRequest{RequestID: "http-cancel-running", Mode: "triage", Scope: domain.Scope{TenantID: "tenant"}})
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-runtime.started:
		case <-time.After(time.Second):
			t.Fatal("executor did not start")
		}
		status, updated := cancel(t, handler, run.ID)
		if status != http.StatusAccepted || updated.Status != domain.RunStatusRunning {
			t.Fatalf("running cancel status=%d run_status=%s", status, updated.Status)
		}
		select {
		case <-runtime.cancelObserved:
		case <-time.After(time.Second):
			t.Fatal("executor did not observe cancellation")
		}
		runtime.release <- struct{}{}
		deadline := time.Now().Add(time.Second)
		for {
			completed := get(t, handler, run.ID)
			if completed.Status.Terminal() {
				if completed.Status != domain.RunStatusCancelled || completed.Result == nil || completed.Result.ErrorCode != "executor_cancelled" || completed.Result.Provenance == nil || completed.Result.Provenance.DaemonRunID != "daemon-http-canceled" || completed.Result.Provenance.SandboxID != "sandbox-http-canceled" || completed.Result.Provenance.Status != "canceled" {
					t.Fatalf("terminal cancellation result was not preserved: %+v", completed)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("run did not become terminal after cancellation")
			}
			time.Sleep(time.Millisecond)
		}
	})

	t.Run("queued", func(t *testing.T) {
		runtime := &blockingCancelExecutor{started: make(chan struct{}), cancelObserved: make(chan struct{}), release: make(chan struct{})}
		service, handler := newHarness(runtime)
		defer service.Close()
		run, _, err := service.CreateRun(context.Background(), "event-triage", domain.CreateRunRequest{RequestID: "http-cancel-queued", Mode: "triage", Scope: domain.Scope{TenantID: "tenant"}})
		if err != nil {
			t.Fatal(err)
		}
		status, updated := cancel(t, handler, run.ID)
		if status != http.StatusOK || updated.Status != domain.RunStatusCancelled {
			t.Fatalf("queued cancel status=%d run_status=%s", status, updated.Status)
		}
	})
}
