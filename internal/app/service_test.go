package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/artifacts"
	"github.com/Notyet1307/security-agent-suite/internal/catalog"
	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/executor"
	mockexecutor "github.com/Notyet1307/security-agent-suite/internal/executor/mock"
	"github.com/Notyet1307/security-agent-suite/internal/observability"
	"github.com/Notyet1307/security-agent-suite/internal/policy"
	"github.com/Notyet1307/security-agent-suite/internal/prompt"
	"github.com/Notyet1307/security-agent-suite/internal/store"
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

func TestServicePreservesCanceledExecutorResult(t *testing.T) {
	catalog, err := catalog.Load("../../configs/agents.json")
	if err != nil {
		t.Fatal(err)
	}
	executor := fixedExecutor{result: domain.ExecutionResult{Status: domain.RunStatusCancelled, Result: domain.RunResult{ErrorCode: "agent_compose_cancelled", ErrorMessage: "agent-compose runtime canceled"}}}
	service := New(Config{Workers: 1, QueueSize: 4, MaxRunTimeout: time.Minute}, memorystore.New(), catalog, policy.New(), executor, prompt.New(), observability.NewMetrics(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	run, created, err := service.CreateRun(context.Background(), "event-triage", domain.CreateRunRequest{RequestID: "req-canceled-result", Mode: "triage", Scope: domain.Scope{TenantID: "t1"}})
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
			if loaded.Status != domain.RunStatusCancelled || loaded.Result == nil || loaded.Result.ErrorCode != "agent_compose_cancelled" {
				t.Fatalf("canceled executor result was changed: %+v", loaded)
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

func canceledExecutionResult() domain.ExecutionResult {
	return domain.ExecutionResult{Status: domain.RunStatusFailed, Result: domain.RunResult{Provenance: &domain.ExecutionProvenance{
		DaemonRunID: "daemon-canceled",
		SandboxID:   "sandbox-canceled",
		Status:      "canceled",
	}}}
}

type blockingCancellationExecutor struct {
	started        chan struct{}
	cancelObserved chan struct{}
	release        chan struct{}
}

func (e *blockingCancellationExecutor) Name() string { return "blocking-cancellation" }

func (e *blockingCancellationExecutor) Execute(ctx context.Context, _ domain.ExecutionRequest) (domain.ExecutionResult, error) {
	close(e.started)
	<-ctx.Done()
	close(e.cancelObserved)
	<-e.release
	return canceledExecutionResult(), ctx.Err()
}

type blockingSuccessExecutor struct {
	started chan struct{}
	release chan struct{}
}

func (e *blockingSuccessExecutor) Name() string { return "blocking-success" }

func (e *blockingSuccessExecutor) Execute(context.Context, domain.ExecutionRequest) (domain.ExecutionResult, error) {
	close(e.started)
	<-e.release
	return domain.ExecutionResult{Status: domain.RunStatusSucceeded, Result: domain.RunResult{
		Summary:   "completed",
		RawOutput: []byte(`{"protocol":"security-agent-suite.event-triage.v1","status":"completed","summary":"completed","classification":"benign","severity":"informational","confidence":1,"hypotheses":[],"evidence":[],"findings":[],"recommended_actions":[],"limitations":[]}`),
	}}, nil
}

type testExecutor struct {
	err  error
	wait bool
}

func (e testExecutor) Name() string { return "test-executor" }

func (e testExecutor) Execute(ctx context.Context, _ domain.ExecutionRequest) (domain.ExecutionResult, error) {
	if e.wait {
		<-ctx.Done()
		return canceledExecutionResult(), ctx.Err()
	}
	return domain.ExecutionResult{}, e.err
}

type cancellationRaceStore struct {
	base                   *memorystore.Store
	blockCancelUpdate      bool
	validationReached      chan struct{}
	allowValidation        chan struct{}
	cancelUpdateEntered    chan struct{}
	allowCancelUpdate      chan struct{}
	runningUpdateAttempted chan struct{}
	validationSeen         atomic.Bool
	cancelUpdateSeen       atomic.Bool
	runningUpdateSeen      atomic.Bool
}

func (s *cancellationRaceStore) Create(ctx context.Context, run *domain.Run) error {
	return s.base.Create(ctx, run)
}
func (s *cancellationRaceStore) Get(ctx context.Context, id string) (*domain.Run, error) {
	return s.base.Get(ctx, id)
}
func (s *cancellationRaceStore) FindByRequestID(ctx context.Context, tenantID, requestID string) (*domain.Run, error) {
	return s.base.FindByRequestID(ctx, tenantID, requestID)
}
func (s *cancellationRaceStore) List(ctx context.Context, filter store.ListFilter) ([]domain.Run, error) {
	return s.base.List(ctx, filter)
}
func (s *cancellationRaceStore) Update(ctx context.Context, id string, mutate func(*domain.Run) error) (*domain.Run, error) {
	before, err := s.base.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if s.blockCancelUpdate && before.Status == domain.RunStatusValidating {
		if s.cancelUpdateSeen.CompareAndSwap(false, true) {
			close(s.cancelUpdateEntered)
			<-s.allowCancelUpdate
		} else if s.runningUpdateSeen.CompareAndSwap(false, true) {
			close(s.runningUpdateAttempted)
		}
	}
	updated, err := s.base.Update(ctx, id, mutate)
	if err == nil && before.Status == domain.RunStatusQueued && updated.Status == domain.RunStatusValidating && s.validationSeen.CompareAndSwap(false, true) {
		close(s.validationReached)
		<-s.allowValidation
	}
	return updated, err
}

type cancellationRaceExecutor struct {
	started         chan struct{}
	contextCanceled chan struct{}
	release         chan struct{}
}

func (e *cancellationRaceExecutor) Name() string { return "cancellation-race" }
func (e *cancellationRaceExecutor) Execute(ctx context.Context, _ domain.ExecutionRequest) (domain.ExecutionResult, error) {
	close(e.started)
	select {
	case <-ctx.Done():
		close(e.contextCanceled)
		return domain.ExecutionResult{}, ctx.Err()
	case <-e.release:
		return domain.ExecutionResult{Status: domain.RunStatusSucceeded}, nil
	}
}

func TestServiceCancellationClosesContextWhenFallbackRacesWorker(t *testing.T) {
	agentCatalog, err := catalog.Load("../../configs/agents.json")
	if err != nil {
		t.Fatal(err)
	}
	runtime := &cancellationRaceExecutor{started: make(chan struct{}), contextCanceled: make(chan struct{}), release: make(chan struct{})}
	raceStore := &cancellationRaceStore{
		base:                   memorystore.New(),
		blockCancelUpdate:      true,
		validationReached:      make(chan struct{}),
		allowValidation:        make(chan struct{}),
		cancelUpdateEntered:    make(chan struct{}),
		allowCancelUpdate:      make(chan struct{}),
		runningUpdateAttempted: make(chan struct{}),
	}
	service := New(Config{Workers: 1, QueueSize: 4, MaxRunTimeout: time.Minute}, raceStore, agentCatalog, policy.New(), runtime, prompt.New(), observability.NewMetrics(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(runtime.release)
		service.Close()
	}()
	run, created, err := service.CreateRun(context.Background(), "event-triage", domain.CreateRunRequest{RequestID: "req-cancel-race", Mode: "triage", Scope: domain.Scope{TenantID: "t1"}})
	if err != nil || !created {
		t.Fatalf("create run: created=%v err=%v", created, err)
	}
	select {
	case <-raceStore.validationReached:
	case <-time.After(time.Second):
		t.Fatal("worker did not reach validation barrier")
	}
	type cancellation struct {
		run *domain.Run
		err error
	}
	cancelDone := make(chan cancellation, 1)
	go func() {
		updated, cancelErr := service.CancelRun(context.Background(), "t1", run.ID, "tester", "stop now")
		cancelDone <- cancellation{run: updated, err: cancelErr}
	}()
	select {
	case <-raceStore.cancelUpdateEntered:
	case <-time.After(time.Second):
		t.Fatal("CancelRun did not reach fallback update barrier")
	}
	close(raceStore.allowValidation)
	workerReached := false
	select {
	case <-raceStore.runningUpdateAttempted:
		workerReached = true
	case <-time.After(250 * time.Millisecond):
	}
	close(raceStore.allowCancelUpdate)
	select {
	case outcome := <-cancelDone:
		if outcome.err != nil || outcome.run == nil || outcome.run.Status != domain.RunStatusCancelled {
			t.Fatalf("cancel outcome=%+v", outcome)
		}
	case <-time.After(time.Second):
		t.Fatal("CancelRun did not complete")
	}
	if !workerReached {
		select {
		case <-runtime.started:
			t.Fatal("executor started after fallback cancellation completed")
		default:
			return
		}
	}
	select {
	case <-runtime.started:
	case <-time.After(time.Second):
		t.Fatal("worker reached running transition but executor did not start")
	}
	select {
	case <-runtime.contextCanceled:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("executor context was not canceled after fallback cancellation")
	}
}

func newStartedTestService(t *testing.T, runtime executor.Executor, timeout time.Duration) *Service {
	t.Helper()
	agentCatalog, err := catalog.Load("../../configs/agents.json")
	if err != nil {
		t.Fatal(err)
	}
	service := New(Config{Workers: 1, QueueSize: 4, MaxRunTimeout: timeout}, memorystore.New(), agentCatalog, policy.New(), runtime, prompt.New(), observability.NewMetrics(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	return service
}

func waitForTerminalRun(t *testing.T, service *Service, tenantID, runID string) *domain.Run {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		run, err := service.GetRun(context.Background(), tenantID, runID)
		if err != nil {
			t.Fatal(err)
		}
		if run.Status.Terminal() {
			return run
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("run did not complete")
	return nil
}

func TestServiceCancellationWaitsForExecutor(t *testing.T) {
	executor := &blockingCancellationExecutor{started: make(chan struct{}), cancelObserved: make(chan struct{}), release: make(chan struct{})}
	service := newStartedTestService(t, executor, time.Minute)
	run, created, err := service.CreateRun(context.Background(), "event-triage", domain.CreateRunRequest{RequestID: "req-cancel-running", Mode: "triage", Scope: domain.Scope{TenantID: "t1"}})
	if err != nil || !created {
		t.Fatalf("create run: created=%v err=%v", created, err)
	}
	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("executor did not start")
	}
	updated, err := service.CancelRun(context.Background(), "t1", run.ID, "tester", "stop now")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != domain.RunStatusRunning {
		t.Fatalf("cancellation exposed terminal status before executor return: %s", updated.Status)
	}
	if len(updated.Events) == 0 || updated.Events[len(updated.Events)-1].Type != "run.cancel_requested" || updated.Events[len(updated.Events)-1].Actor != "tester" || updated.Events[len(updated.Events)-1].Message != "stop now" {
		t.Fatalf("cancellation request was not recorded: %+v", updated.Events)
	}
	select {
	case <-executor.cancelObserved:
	case <-time.After(time.Second):
		t.Fatal("executor did not observe cancellation")
	}
	stillRunning, err := service.GetRun(context.Background(), "t1", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stillRunning.Status != domain.RunStatusRunning {
		t.Fatalf("run became terminal before executor returned: %s", stillRunning.Status)
	}
	close(executor.release)
	completed := waitForTerminalRun(t, service, "t1", run.ID)
	if completed.Status != domain.RunStatusCancelled || completed.Result == nil || completed.Result.ErrorCode != "executor_cancelled" || completed.Result.Provenance == nil || completed.Result.Provenance.DaemonRunID != "daemon-canceled" || completed.Result.Provenance.SandboxID != "sandbox-canceled" || completed.Result.Provenance.Status != "canceled" {
		t.Fatalf("executor cancellation result was not preserved: %+v", completed)
	}
}

func TestServiceCancellationMapsContextCanceledToCancelled(t *testing.T) {
	service := newStartedTestService(t, testExecutor{wait: true}, time.Minute)
	run, created, err := service.CreateRun(context.Background(), "event-triage", domain.CreateRunRequest{RequestID: "req-cancel-context", Mode: "triage", Scope: domain.Scope{TenantID: "t1"}})
	if err != nil || !created {
		t.Fatalf("create run: created=%v err=%v", created, err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		loaded, getErr := service.GetRun(context.Background(), "t1", run.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if loaded.Status == domain.RunStatusRunning {
			break
		}
		time.Sleep(time.Millisecond)
	}
	loaded, err := service.GetRun(context.Background(), "t1", run.ID)
	if err != nil || loaded.Status != domain.RunStatusRunning {
		t.Fatalf("run did not reach running state: run=%+v err=%v", loaded, err)
	}
	if _, err := service.CancelRun(context.Background(), "t1", run.ID, "tester", "stop now"); err != nil {
		t.Fatal(err)
	}
	completed := waitForTerminalRun(t, service, "t1", run.ID)
	if completed.Status != domain.RunStatusCancelled || completed.Result == nil || completed.Result.ErrorCode != "executor_cancelled" || completed.Result.Provenance == nil || completed.Result.Provenance.DaemonRunID != "daemon-canceled" || completed.Result.Provenance.SandboxID != "sandbox-canceled" || completed.Result.Provenance.Status != "canceled" {
		t.Fatalf("context cancellation was not classified or preserved: %+v", completed)
	}
}
func TestServiceCancellationDoesNotOverrideSuccessfulExecutor(t *testing.T) {
	executor := &blockingSuccessExecutor{started: make(chan struct{}), release: make(chan struct{})}
	service := newStartedTestService(t, executor, time.Minute)
	run, created, err := service.CreateRun(context.Background(), "event-triage", domain.CreateRunRequest{RequestID: "req-cancel-success", Mode: "triage", Scope: domain.Scope{TenantID: "t1"}})
	if err != nil || !created {
		t.Fatalf("create run: created=%v err=%v", created, err)
	}
	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("executor did not start")
	}
	updated, err := service.CancelRun(context.Background(), "t1", run.ID, "tester", "stop now")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != domain.RunStatusRunning {
		t.Fatalf("cancellation exposed terminal status before executor return: %s", updated.Status)
	}
	close(executor.release)
	completed := waitForTerminalRun(t, service, "t1", run.ID)
	if completed.Status != domain.RunStatusSucceeded {
		t.Fatalf("executor success was overwritten by cancellation: %s", completed.Status)
	}
}

func TestServiceQueuedCancellationRemainsImmediate(t *testing.T) {
	executor := &blockingCancellationExecutor{started: make(chan struct{}), cancelObserved: make(chan struct{}), release: make(chan struct{})}
	agentCatalog, err := catalog.Load("../../configs/agents.json")
	if err != nil {
		t.Fatal(err)
	}
	service := New(Config{Workers: 1, QueueSize: 4, MaxRunTimeout: time.Minute}, memorystore.New(), agentCatalog, policy.New(), executor, prompt.New(), observability.NewMetrics(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer service.Close()
	run, created, err := service.CreateRun(context.Background(), "event-triage", domain.CreateRunRequest{RequestID: "req-cancel-queued", Mode: "triage", Scope: domain.Scope{TenantID: "t1"}})
	if err != nil || !created || run.Status != domain.RunStatusQueued {
		t.Fatalf("create queued run: run=%+v created=%v err=%v", run, created, err)
	}
	updated, err := service.CancelRun(context.Background(), "t1", run.ID, "tester", "remove queued work")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != domain.RunStatusCancelled {
		t.Fatalf("expected immediate queued cancellation, got %s", updated.Status)
	}
	select {
	case <-executor.started:
		t.Fatal("queued cancellation invoked executor")
	default:
	}
}

func TestServiceExecutorTimeoutAndErrorRemainFailures(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		service := newStartedTestService(t, testExecutor{wait: true}, 10*time.Millisecond)
		run, _, err := service.CreateRun(context.Background(), "event-triage", domain.CreateRunRequest{RequestID: "req-timeout", Mode: "triage", Scope: domain.Scope{TenantID: "t1"}})
		if err != nil {
			t.Fatal(err)
		}
		completed := waitForTerminalRun(t, service, "t1", run.ID)
		if completed.Status != domain.RunStatusFailed || completed.Result == nil || completed.Result.ErrorCode != "executor_timeout" {
			t.Fatalf("unexpected timeout result: %+v", completed)
		}
	})
	t.Run("error", func(t *testing.T) {
		service := newStartedTestService(t, testExecutor{err: errors.New("executor exploded")}, time.Minute)
		run, _, err := service.CreateRun(context.Background(), "event-triage", domain.CreateRunRequest{RequestID: "req-error", Mode: "triage", Scope: domain.Scope{TenantID: "t1"}})
		if err != nil {
			t.Fatal(err)
		}
		completed := waitForTerminalRun(t, service, "t1", run.ID)
		if completed.Status != domain.RunStatusFailed || completed.Result == nil || completed.Result.ErrorCode != "executor_error" || completed.Result.ErrorMessage != "executor exploded" {
			t.Fatalf("unexpected executor error result: %+v", completed)
		}
	})
}
