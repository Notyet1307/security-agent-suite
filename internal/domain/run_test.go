package domain

import (
	"errors"
	"testing"
	"time"
)

func TestRunTransitions(t *testing.T) {
	now := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	run := NewRun("run_1", "event-triage", "事件研判智能体", CreateRunRequest{RequestID: "req-1", Mode: "triage", Scope: Scope{TenantID: "t1"}}, RunStatusQueued, now)
	for _, status := range []RunStatus{RunStatusValidating, RunStatusRunning, RunStatusSucceeded} {
		now = now.Add(time.Second)
		if err := run.Transition(status, "test", "tester", now); err != nil {
			t.Fatalf("transition to %s: %v", status, err)
		}
	}
	if !run.Status.Terminal() || run.StartedAt == nil || run.CompletedAt == nil {
		t.Fatalf("unexpected terminal state: %+v", run)
	}
	if len(run.Events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(run.Events))
	}
	if err := run.Transition(RunStatusRunning, "invalid", "tester", now); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected invalid transition, got %v", err)
	}
}

func TestApprovalTransition(t *testing.T) {
	now := time.Now()
	run := NewRun("run_2", "attack-path-validation", "攻击路径验证智能体", CreateRunRequest{RequestID: "req-2", Mode: "active_validate", Scope: Scope{TenantID: "t1"}}, RunStatusWaitingApproval, now)
	run.SetApproval(Approval{ID: "approval-1", Actor: "alice", Reason: "authorized", CreatedAt: now}, now)
	if err := run.Transition(RunStatusQueued, "approved", "alice", now); err != nil {
		t.Fatal(err)
	}
	if run.Approval == nil || run.Status != RunStatusQueued {
		t.Fatalf("approval not recorded: %+v", run)
	}
}
