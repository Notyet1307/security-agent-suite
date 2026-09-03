package mock

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/artifacts"
	"github.com/Notyet1307/security-agent-suite/internal/domain"
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
