package mock

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/artifacts"
	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

type Executor struct {
	artifacts *artifacts.Store
	delay     time.Duration
}

func New(store *artifacts.Store) *Executor {
	return &Executor{artifacts: store, delay: 20 * time.Millisecond}
}

func (e *Executor) Name() string { return "mock" }

func (e *Executor) Execute(ctx context.Context, request domain.ExecutionRequest) (domain.ExecutionResult, error) {
	select {
	case <-ctx.Done():
		return domain.ExecutionResult{}, ctx.Err()
	case <-time.After(e.delay):
	}

	payload := map[string]any{
		"protocol":    "security-agent-suite.mock-result.v1",
		"run_id":      request.Run.ID,
		"agent_id":    request.Agent.ID,
		"mode":        request.Run.Mode,
		"input_count": len(request.Run.Inputs),
		"message":     "Mock execution completed. No real security conclusion was produced.",
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return domain.ExecutionResult{}, err
	}
	artifact, err := e.artifacts.Put(ctx, request.Run.ID, "mock-result.json", "application/json", data, time.Now())
	if err != nil {
		return domain.ExecutionResult{}, fmt.Errorf("write mock artifact: %w", err)
	}
	return domain.ExecutionResult{
		Status: domain.RunStatusSucceeded,
		Result: domain.RunResult{
			Executor:  e.Name(),
			Summary:   "Mock 执行器已完成端到端联调；未读取真实数据，也未生成真实安全结论。",
			Artifacts: []domain.ArtifactRef{artifact},
			Limitations: []string{
				"mock_executor",
				"no_real_tools_called",
				"no_security_finding_generated",
			},
			RawOutput: data,
		},
	}, nil
}
