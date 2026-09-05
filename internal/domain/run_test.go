package domain

import (
	"encoding/json"
	"errors"
	"strings"
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
func TestSetResultBoundsSummaryAndError(t *testing.T) {
	run := NewRun("run-bounds", "event-triage", "event", CreateRunRequest{}, RunStatusRunning, time.Now())
	run.SetResult(RunResult{Summary: strings.Repeat("你", MaxSummaryBytes), ErrorMessage: strings.Repeat("x", MaxErrorMessageBytes+10)}, time.Now())
	if len([]byte(run.Result.Summary)) > MaxSummaryBytes || len([]byte(run.Result.ErrorMessage)) > MaxErrorMessageBytes {
		t.Fatalf("result text exceeded bounds: summary=%d error=%d", len([]byte(run.Result.Summary)), len([]byte(run.Result.ErrorMessage)))
	}
}

func TestExecutionProvenanceRoundTrips(t *testing.T) {
	run := NewRun("run-provenance", "event-triage", "event", CreateRunRequest{}, RunStatusRunning, time.Now())
	run.SetResult(RunResult{
		Summary: "runtime",
		Provenance: &ExecutionProvenance{
			DaemonRunID: "daemon-1",
			SandboxID:   "sandbox-1",
			Provider:    "pi",
			Warnings:    []string{"warning"},
			Labels:      map[string]string{"suite": "test"},
		},
	}, time.Now())
	data, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	var loaded Run
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.Result == nil || loaded.Result.Provenance == nil || loaded.Result.Provenance.DaemonRunID != "daemon-1" || loaded.Result.Provenance.Labels["suite"] != "test" {
		t.Fatalf("provenance did not round-trip: %+v", loaded.Result)
	}
}
