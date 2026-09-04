package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/catalog"
	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/executor"
	"github.com/Notyet1307/security-agent-suite/internal/id"
	"github.com/Notyet1307/security-agent-suite/internal/observability"
	"github.com/Notyet1307/security-agent-suite/internal/policy"
	"github.com/Notyet1307/security-agent-suite/internal/prompt"
	"github.com/Notyet1307/security-agent-suite/internal/store"
	"github.com/Notyet1307/security-agent-suite/internal/validation"
)

type Config struct {
	Workers       int
	QueueSize     int
	MaxRunTimeout time.Duration
}

type Service struct {
	cfg      Config
	store    store.RunStore
	catalog  *catalog.Catalog
	policy   *policy.Engine
	executor executor.Executor
	prompt   *prompt.Builder
	metrics  *observability.Metrics
	logger   *slog.Logger

	queue chan string
	ctx   context.Context
	stop  context.CancelFunc
	wg    sync.WaitGroup

	cancelMu  sync.Mutex
	cancels   map[string]context.CancelFunc
	startOnce sync.Once
	stopOnce  sync.Once
}

func New(cfg Config, runStore store.RunStore, agentCatalog *catalog.Catalog, policyEngine *policy.Engine, runtime executor.Executor, promptBuilder *prompt.Builder, metrics *observability.Metrics, logger *slog.Logger) *Service {
	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 64
	}
	if cfg.MaxRunTimeout <= 0 {
		cfg.MaxRunTimeout = 30 * time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{
		cfg: cfg, store: runStore, catalog: agentCatalog, policy: policyEngine,
		executor: runtime, prompt: promptBuilder, metrics: metrics, logger: logger,
		queue: make(chan string, cfg.QueueSize), ctx: ctx, stop: cancel,
		cancels: map[string]context.CancelFunc{},
	}
}

func (s *Service) Start() error {
	var startErr error
	s.startOnce.Do(func() {
		// Start workers before recovery so a persisted backlog larger than the
		// in-memory queue can drain while it is being re-enqueued.
		for i := 0; i < s.cfg.Workers; i++ {
			s.wg.Add(1)
			go s.worker(i + 1)
		}
		startErr = s.recoverRuns()
		if startErr != nil {
			s.stop()
			s.wg.Wait()
		}
	})
	return startErr
}

func (s *Service) Close() {
	s.stopOnce.Do(func() {
		s.stop()
		s.cancelMu.Lock()
		for _, cancel := range s.cancels {
			cancel()
		}
		s.cancelMu.Unlock()
		s.wg.Wait()
	})
}

func (s *Service) ListAgents() []domain.AgentDefinition { return s.catalog.List() }

func (s *Service) GetAgent(agentID string) (domain.AgentDefinition, error) {
	agent, ok := s.catalog.Get(agentID)
	if !ok {
		return domain.AgentDefinition{}, domain.ErrNotFound
	}
	return agent, nil
}

func (s *Service) CreateRun(ctx context.Context, agentID string, req domain.CreateRunRequest) (*domain.Run, bool, error) {
	agent, ok := s.catalog.Get(agentID)
	if !ok {
		return nil, false, domain.ErrNotFound
	}
	decision, err := s.policy.NormalizeAndEvaluate(agent, &req)
	if err != nil {
		return nil, false, err
	}
	if existing, err := s.store.FindByRequestID(ctx, req.Scope.TenantID, req.RequestID); err == nil {
		if existing.AgentID != agentID {
			return nil, false, fmt.Errorf("%w: request_id is already used by another agent", domain.ErrConflict)
		}
		return existing, false, nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return nil, false, err
	}

	now := time.Now()
	runID, err := id.New("run", now)
	if err != nil {
		return nil, false, err
	}
	run := domain.NewRun(runID, agent.ID, agent.DisplayName, req, decision.InitialStatus, now)
	run.RecordEvent("policy.preflight_passed", decision.Reason, "policy-engine", nil, now)
	if err := s.store.Create(ctx, run); err != nil {
		if errors.Is(err, domain.ErrAlreadyExists) {
			existing, findErr := s.store.FindByRequestID(ctx, req.Scope.TenantID, req.RequestID)
			if findErr == nil {
				return existing, false, nil
			}
		}
		return nil, false, err
	}
	s.metrics.RunCreated()
	if run.Status == domain.RunStatusQueued {
		if err := s.enqueue(ctx, run.ID); err != nil {
			failed, _ := s.failRun(context.Background(), run.ID, "queue_unavailable", err.Error())
			return failed, true, nil
		}
	}
	return run, true, nil
}

func (s *Service) GetRun(ctx context.Context, tenantID, runID string) (*domain.Run, error) {
	run, err := s.store.Get(ctx, runID)
	if err != nil {
		return nil, err
	}
	if run.Scope.TenantID != tenantID {
		return nil, domain.ErrNotFound
	}
	return run, nil
}

func (s *Service) ListRuns(ctx context.Context, filter store.ListFilter) ([]domain.Run, error) {
	if strings.TrimSpace(filter.TenantID) == "" {
		return nil, fmt.Errorf("%w: tenant id is required", domain.ErrInvalidRequest)
	}
	if filter.Limit <= 0 || filter.Limit > 200 {
		filter.Limit = 50
	}
	return s.store.List(ctx, filter)
}

func (s *Service) ApproveRun(ctx context.Context, tenantID, runID string, req domain.ApprovalRequest) (*domain.Run, error) {
	req.ApprovalID = strings.TrimSpace(req.ApprovalID)
	req.Actor = strings.TrimSpace(req.Actor)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.ApprovalID == "" || req.Actor == "" || req.Reason == "" {
		return nil, fmt.Errorf("%w: approval_id, actor, and reason are required", domain.ErrInvalidRequest)
	}
	run, err := s.GetRun(ctx, tenantID, runID)
	if err != nil {
		return nil, err
	}
	if run.Status != domain.RunStatusWaitingApproval {
		return nil, fmt.Errorf("%w: run is not waiting for approval", domain.ErrConflict)
	}
	now := time.Now()
	updated, err := s.store.Update(ctx, runID, func(current *domain.Run) error {
		if current.Scope.TenantID != tenantID {
			return domain.ErrNotFound
		}
		if current.Status != domain.RunStatusWaitingApproval {
			return fmt.Errorf("%w: run is not waiting for approval", domain.ErrConflict)
		}
		current.SetApproval(domain.Approval{ID: req.ApprovalID, Actor: req.Actor, Reason: req.Reason, CreatedAt: now.UTC()}, now)
		return current.Transition(domain.RunStatusQueued, "approved run queued", req.Actor, now)
	})
	if err != nil {
		return nil, err
	}
	if err := s.enqueue(ctx, runID); err != nil {
		return s.failRun(context.Background(), runID, "queue_unavailable", err.Error())
	}
	return updated, nil
}

func (s *Service) CancelRun(ctx context.Context, tenantID, runID, actor, reason string) (*domain.Run, error) {
	if strings.TrimSpace(actor) == "" {
		actor = "api"
	}
	if strings.TrimSpace(reason) == "" {
		reason = "cancel requested"
	}
	if _, err := s.GetRun(ctx, tenantID, runID); err != nil {
		return nil, err
	}
	s.cancelMu.Lock()
	if cancel, ok := s.cancels[runID]; ok {
		cancel()
	}
	s.cancelMu.Unlock()
	now := time.Now()
	transitioned := false
	updated, err := s.store.Update(ctx, runID, func(current *domain.Run) error {
		if current.Scope.TenantID != tenantID {
			return domain.ErrNotFound
		}
		if current.Status.Terminal() {
			return nil
		}
		current.SetResult(domain.RunResult{Executor: s.executor.Name(), Summary: "运行已取消。", ErrorCode: "cancelled", ErrorMessage: reason}, now)
		if err := current.Transition(domain.RunStatusCancelled, reason, actor, now); err != nil {
			return err
		}
		transitioned = true
		return nil
	})
	if err == nil && transitioned {
		s.metrics.RunCompleted(domain.RunStatusCancelled)
	}
	return updated, err
}

func (s *Service) enqueue(ctx context.Context, runID string) error {
	select {
	case <-s.ctx.Done():
		return fmt.Errorf("service is stopping")
	case <-ctx.Done():
		return ctx.Err()
	case s.queue <- runID:
		s.metrics.SetQueueDepth(len(s.queue))
		return nil
	default:
		return fmt.Errorf("run queue is full")
	}
}

func (s *Service) worker(number int) {
	defer s.wg.Done()
	logger := s.logger.With("worker", number)
	for {
		select {
		case <-s.ctx.Done():
			return
		case runID := <-s.queue:
			s.metrics.SetQueueDepth(len(s.queue))
			if err := s.process(runID); err != nil {
				logger.Error("process run", "run_id", runID, "error", err)
			}
		}
	}
}

func (s *Service) process(runID string) error {
	ctx := s.ctx
	now := time.Now()
	run, err := s.store.Update(ctx, runID, func(current *domain.Run) error {
		if current.Status == domain.RunStatusCancelled || current.Status.Terminal() {
			return nil
		}
		if current.Status != domain.RunStatusQueued {
			return fmt.Errorf("%w: run status is %s, expected queued", domain.ErrConflict, current.Status)
		}
		return current.Transition(domain.RunStatusValidating, "worker started deterministic validation", "worker", now)
	})
	if err != nil {
		return err
	}
	if run.Status.Terminal() {
		return nil
	}
	agent, ok := s.catalog.Get(run.AgentID)
	if !ok {
		_, err := s.failRun(ctx, runID, "agent_not_found", "agent definition disappeared from catalog")
		return err
	}
	if err := s.policy.ValidateExecution(agent, *run); err != nil {
		_, failErr := s.failRun(ctx, runID, "execution_policy_denied", err.Error())
		return failErr
	}
	promptText, err := s.prompt.Build(*run, agent)
	if err != nil {
		_, failErr := s.failRun(ctx, runID, "prompt_build_failed", err.Error())
		return failErr
	}
	now = time.Now()
	run, err = s.store.Update(ctx, runID, func(current *domain.Run) error {
		if current.Status == domain.RunStatusCancelled {
			return nil
		}
		return current.Transition(domain.RunStatusRunning, "executor invocation started", s.executor.Name(), now)
	})
	if err != nil || run.Status == domain.RunStatusCancelled {
		return err
	}

	timeout := agent.DefaultTimeout
	if timeout <= 0 || timeout > s.cfg.MaxRunTimeout {
		timeout = s.cfg.MaxRunTimeout
	}
	if run.Policy.MaxDuration != "" {
		if requested, parseErr := time.ParseDuration(run.Policy.MaxDuration); parseErr == nil && requested < timeout {
			timeout = requested
		}
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	s.registerCancel(runID, cancel)
	result, execErr := s.executor.Execute(execCtx, domain.ExecutionRequest{Run: *run, Agent: agent, Prompt: promptText, Timeout: timeout})
	cancel()
	s.unregisterCancel(runID)
	if execErr == nil {
		result = validation.Gate(agent.ID, result, s.executor.Name())
	}

	finish := time.Now()
	completedByWorker := false
	updated, updateErr := s.store.Update(context.Background(), runID, func(current *domain.Run) error {
		if current.Status.Terminal() {
			return nil
		}
		if execErr != nil {
			code := "executor_error"
			message := execErr.Error()
			if errors.Is(execErr, context.DeadlineExceeded) {
				code = "executor_timeout"
			}
			if errors.Is(execErr, context.Canceled) {
				code = "executor_cancelled"
			}
			failureResult := result.Result
			failureResult.Executor = s.executor.Name()
			failureResult.ErrorCode = code
			failureResult.ErrorMessage = message
			if failureResult.Summary == "" {
				failureResult.Summary = "执行器未完成运行。"
			}
			current.SetResult(failureResult, finish)
			if err := current.Transition(domain.RunStatusFailed, message, s.executor.Name(), finish); err != nil {
				return err
			}
			completedByWorker = true
			return nil
		}
		status := result.Status
		switch status {
		case domain.RunStatusSucceeded, domain.RunStatusPartial, domain.RunStatusFailed:
		default:
			status = domain.RunStatusFailed
			result.Result.ErrorCode = "invalid_executor_status"
			result.Result.ErrorMessage = "executor returned a non-terminal status"
		}
		current.SetResult(result.Result, finish)
		if err := current.Transition(status, "executor invocation completed", s.executor.Name(), finish); err != nil {
			return err
		}
		completedByWorker = true
		return nil
	})
	if updateErr != nil {
		return updateErr
	}
	if completedByWorker {
		s.metrics.RunCompleted(updated.Status)
	}
	return nil
}

func (s *Service) failRun(ctx context.Context, runID, code, message string) (*domain.Run, error) {
	now := time.Now()
	transitioned := false
	updated, err := s.store.Update(ctx, runID, func(current *domain.Run) error {
		if current.Status.Terminal() {
			return nil
		}
		current.SetResult(domain.RunResult{Executor: s.executor.Name(), Summary: "运行失败。", ErrorCode: code, ErrorMessage: message}, now)
		if err := current.Transition(domain.RunStatusFailed, message, "system", now); err != nil {
			return err
		}
		transitioned = true
		return nil
	})
	if err == nil && transitioned {
		s.metrics.RunCompleted(domain.RunStatusFailed)
	}
	return updated, err
}

func (s *Service) registerCancel(runID string, cancel context.CancelFunc) {
	s.cancelMu.Lock()
	defer s.cancelMu.Unlock()
	s.cancels[runID] = cancel
}

func (s *Service) unregisterCancel(runID string) {
	s.cancelMu.Lock()
	defer s.cancelMu.Unlock()
	delete(s.cancels, runID)
}

func (s *Service) recoverRuns() error {
	for _, status := range []domain.RunStatus{domain.RunStatusValidating, domain.RunStatusRunning} {
		runs, err := s.store.List(context.Background(), store.ListFilter{Status: status, Limit: 10000})
		if err != nil {
			return err
		}
		for _, run := range runs {
			if _, err := s.failRun(context.Background(), run.ID, "service_restarted", "service restarted before run completed"); err != nil {
				return err
			}
		}
	}
	queued, err := s.store.List(context.Background(), store.ListFilter{Status: domain.RunStatusQueued, Limit: 10000})
	if err != nil {
		return err
	}
	for _, run := range queued {
		if err := s.enqueue(context.Background(), run.ID); err != nil {
			return err
		}
	}
	return nil
}
