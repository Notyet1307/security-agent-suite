package mock

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/artifacts"
	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/validation"
)

func TestExecuteProducesClearlyMarkedMockArtifact(t *testing.T) {
	store, _ := artifacts.New(filepath.Join(t.TempDir(), "artifacts"))
	executor := New(store)
	result, err := executor.Execute(context.Background(), domain.ExecutionRequest{
		Run:   domain.Run{ID: "run-mock", Mode: "triage", Inputs: []domain.InputRef{{Type: "alert"}}},
		Agent: domain.AgentDefinition{ID: "event-triage"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.RunStatusSucceeded || len(result.Result.Artifacts) != 1 || len(result.Result.Findings) != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(result.Result.Limitations) == 0 {
		t.Fatal("mock output must state limitations")
	}
}

func TestExecuteOutputsPassGateForEveryKnownAgent(t *testing.T) {
	for _, agentID := range validation.SupportedAgents() {
		t.Run(agentID, func(t *testing.T) {
			store, err := artifacts.New(filepath.Join(t.TempDir(), "artifacts"))
			if err != nil {
				t.Fatal(err)
			}
			result, err := New(store).Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-" + agentID}, Agent: domain.AgentDefinition{ID: agentID}})
			if err != nil {
				t.Fatal(err)
			}
			gated := validation.Gate(agentID, result, "mock")
			if gated.Status != domain.RunStatusSucceeded {
				t.Fatalf("status=%s error=%s", gated.Status, gated.Result.ErrorMessage)
			}
			if len(gated.Result.RawOutput) == 0 || len(gated.Result.Artifacts) != 1 {
				t.Fatalf("raw/artifact not retained: %+v", gated.Result)
			}
		})
	}
}

func TestExecuteRejectsUnknownAgent(t *testing.T) {
	store, err := artifacts.New(filepath.Join(t.TempDir(), "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := New(store).Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-unknown"}, Agent: domain.AgentDefinition{ID: "unknown-agent"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status == domain.RunStatusSucceeded {
		t.Fatal("unknown agent must not succeed")
	}
}

func TestExecuteHonorsCancellation(t *testing.T) {
	store, _ := artifacts.New(t.TempDir())
	executor := New(store)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := executor.Execute(ctx, domain.ExecutionRequest{Run: domain.Run{ID: "run-cancel"}, Agent: domain.AgentDefinition{ID: "event-triage"}, Timeout: time.Second})
	if err == nil {
		t.Fatal("expected cancellation")
	}
}
