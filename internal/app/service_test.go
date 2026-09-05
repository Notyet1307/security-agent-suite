package app

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/artifacts"
	"github.com/Notyet1307/security-agent-suite/internal/catalog"
	"github.com/Notyet1307/security-agent-suite/internal/domain"
	mockexecutor "github.com/Notyet1307/security-agent-suite/internal/executor/mock"
	"github.com/Notyet1307/security-agent-suite/internal/observability"
	"github.com/Notyet1307/security-agent-suite/internal/policy"
	"github.com/Notyet1307/security-agent-suite/internal/prompt"
	filestore "github.com/Notyet1307/security-agent-suite/internal/store/file"
	memorystore "github.com/Notyet1307/security-agent-suite/internal/store/memory"
	"github.com/Notyet1307/security-agent-suite/internal/validation"
)

func TestServiceCompletesMockRun(t *testing.T) {
	catalog, err := catalog.Load("../../configs/agents.json")
	if err != nil {
		t.Fatal(err)
	}
	artifactStore, err := artifacts.New(filepath.Join(t.TempDir(), "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	service := New(Config{Workers: 1, QueueSize: 4, MaxRunTimeout: time.Minute}, memorystore.New(), catalog, policy.New(), mockexecutor.New(artifactStore), prompt.New(), observability.NewMetrics(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	run, created, err := service.CreateRun(context.Background(), "event-triage", domain.CreateRunRequest{RequestID: "req-service-1", Mode: "triage", Inputs: []domain.InputRef{{Type: "alert", URI: "artifact://alerts/1"}}, Scope: domain.Scope{TenantID: "t1"}})
	if err != nil || !created {
		t.Fatalf("create run: created=%v err=%v", created, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		loaded, getErr := service.GetRun(context.Background(), "t1", run.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if loaded.Status.Terminal() {
			if loaded.Status != domain.RunStatusSucceeded || loaded.Result == nil || len(loaded.Result.Artifacts) != 1 {
				t.Fatalf("unexpected result: %+v", loaded)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("run did not complete")
}

func TestServiceApprovalGate(t *testing.T) {
	catalog, _ := catalog.Load("../../configs/agents.json")
	artifactStore, _ := artifacts.New(t.TempDir())
	service := New(Config{Workers: 1, QueueSize: 4, MaxRunTimeout: time.Minute}, memorystore.New(), catalog, policy.New(), mockexecutor.New(artifactStore), prompt.New(), observability.NewMetrics(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	_ = service.Start()
	defer service.Close()

	req := domain.CreateRunRequest{RequestID: "req-attack", Mode: "active_validate", Inputs: []domain.InputRef{{Type: "scanner-result", URI: "artifact://scanner/1"}}, Scope: domain.Scope{TenantID: "t1", AuthorizationRef: "AUTH-1", Assets: []string{"https://target.example"}}, Policy: domain.PolicyRequest{ActiveValidation: true, NetworkAccess: "restricted", MaxRequests: 10}}
	run, _, err := service.CreateRun(context.Background(), "attack-path-validation", req)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != domain.RunStatusWaitingApproval {
		t.Fatalf("expected waiting approval, got %s", run.Status)
	}
	approved, err := service.ApproveRun(context.Background(), "t1", run.ID, domain.ApprovalRequest{ApprovalID: "APP-1", Actor: "reviewer", Reason: "authorized test"})
	if err != nil || approved.Status != domain.RunStatusQueued {
		t.Fatalf("approve: run=%+v err=%v", approved, err)
	}
}

type fixedExecutor struct{ result domain.ExecutionResult }

func (e fixedExecutor) Name() string { return "future-executor" }
func (e fixedExecutor) Execute(context.Context, domain.ExecutionRequest) (domain.ExecutionResult, error) {
	return e.result, nil
}

func TestServiceGatesSuccessfulFutureExecutorOutput(t *testing.T) {
	catalog, err := catalog.Load("../../configs/agents.json")
	if err != nil {
		t.Fatal(err)
	}
	executor := fixedExecutor{result: domain.ExecutionResult{Status: domain.RunStatusSucceeded, Result: domain.RunResult{RawOutput: []byte(`{"protocol":"wrong"}`)}}}
	service := New(Config{Workers: 1, QueueSize: 4, MaxRunTimeout: time.Minute}, memorystore.New(), catalog, policy.New(), executor, prompt.New(), observability.NewMetrics(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	run, created, err := service.CreateRun(context.Background(), "event-triage", domain.CreateRunRequest{RequestID: "req-gate", Mode: "triage", Inputs: []domain.InputRef{{Type: "alert", URI: "artifact://alerts/1"}}, Scope: domain.Scope{TenantID: "t1"}})
	if err != nil || !created {
		t.Fatalf("create run: created=%v err=%v", created, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		loaded, getErr := service.GetRun(context.Background(), "t1", run.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if loaded.Status.Terminal() {
			if loaded.Status != domain.RunStatusFailed || loaded.Result == nil || loaded.Result.ErrorCode != validation.CodeContractInvalid {
				t.Fatalf("unexpected gated result: %+v", loaded)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("run did not complete")
}

func TestServicePersistsExecutionProvenance(t *testing.T) {
	root := t.TempDir()
	store, err := filestore.New(root)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := catalog.Load("../../configs/agents.json")
	if err != nil {
		t.Fatal(err)
	}
	output := []byte(`{"protocol":"security-agent-suite.event-triage.v1","status":"completed","summary":"ok","classification":"benign","severity":"informational","confidence":1,"hypotheses":[],"evidence":[],"findings":[],"recommended_actions":[],"limitations":[]}`)
	executor := fixedExecutor{result: domain.ExecutionResult{Status: domain.RunStatusSucceeded, Result: domain.RunResult{
		RawOutput:  output,
		Provenance: &domain.ExecutionProvenance{DaemonRunID: "daemon-persisted", SandboxID: "sandbox-persisted", Provider: "pi"},
	}}}
	service := New(Config{Workers: 1, QueueSize: 4, MaxRunTimeout: time.Minute}, store, catalog, policy.New(), executor, prompt.New(), observability.NewMetrics(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	run, created, err := service.CreateRun(context.Background(), "event-triage", domain.CreateRunRequest{RequestID: "req-provenance", Mode: "triage", Scope: domain.Scope{TenantID: "tenant"}})
	if err != nil || !created {
		t.Fatalf("create run: created=%v err=%v", created, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		loaded, getErr := service.GetRun(context.Background(), "tenant", run.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if loaded.Status.Terminal() {
			if loaded.Status != domain.RunStatusSucceeded || loaded.Result == nil || loaded.Result.Provenance == nil || loaded.Result.Provenance.DaemonRunID != "daemon-persisted" {
				t.Fatalf("unexpected persisted result: %+v", loaded)
			}
			service.Close()
			reloadedStore, reloadErr := filestore.New(root)
			if reloadErr != nil {
				t.Fatal(reloadErr)
			}
			reloaded, reloadErr := reloadedStore.Get(context.Background(), run.ID)
			if reloadErr != nil || reloaded.Result == nil || reloaded.Result.Provenance == nil || reloaded.Result.Provenance.SandboxID != "sandbox-persisted" {
				t.Fatalf("provenance did not survive reload: run=%+v err=%v", reloaded, reloadErr)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	service.Close()
	t.Fatal("run did not complete")
}
