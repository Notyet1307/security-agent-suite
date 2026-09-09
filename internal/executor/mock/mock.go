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

	var payload map[string]any
	switch request.Agent.ID {
	case "event-triage":
		payload = map[string]any{"protocol": "security-agent-suite.event-triage.v1", "status": "completed", "summary": "Mock execution completed. No real security conclusion was produced.", "classification": "insufficient_evidence", "severity": "undetermined", "confidence": 0, "hypotheses": []any{}, "evidence": []any{}, "findings": []any{}, "recommended_actions": []any{}, "limitations": []string{"mock_executor", "no_real_tools_called", "no_security_finding_generated"}}
	case "traffic-analysis":
		payload = map[string]any{"protocol": "security-agent-suite.traffic-analysis.v1", "status": "completed", "summary": "Mock execution completed. No real security conclusion was produced.", "evidence": []any{}, "timeline": []any{}, "findings": []any{}, "limitations": []string{"mock_executor", "no_real_tools_called", "no_security_finding_generated"}}
	case "security-report":
		payload = map[string]any{"protocol": "security-agent-suite.security-report.v1", "status": "completed", "report_type": "daily", "period": map[string]any{"start": "1970-01-01T00:00:00Z", "end": "1970-01-01T00:00:00Z", "timezone": "UTC"}, "executive_summary": "No real security conclusion was produced.", "metrics": []any{}, "key_events": []any{}, "recommendations": []any{}, "artifacts": []any{}, "validation": map[string]any{"numbers": "not_applicable", "citations": "not_applicable", "template": "not_applicable", "sensitive_data": "not_applicable"}, "limitations": []string{"mock_executor", "no_real_tools_called", "no_security_finding_generated"}}
	case "compliance-query":
		payload = map[string]any{"protocol": "security-agent-suite.compliance-query.v1", "status": "completed", "answer": "No real compliance conclusion was produced.", "applicability": map[string]any{"applies": "unknown", "assumptions": []any{}, "reason": "No real sources were consulted."}, "citations": []any{}, "control_gaps": []any{}, "evidence_requirements": []any{}, "recommendations": []any{}, "uncertainty": []string{"mock_executor produced no source-backed assessment."}}
	case "attack-path-validation":
		payload = map[string]any{"protocol": "security-agent-suite.attack-path-validation.v1", "status": "completed", "summary": "Mock execution completed. No real security conclusion was produced.", "scope_check": map[string]any{"authorized": false, "authorization_ref": "", "approval_id": "", "targets": []any{}, "checks": []any{}}, "validations": []any{}, "evidence": []any{}, "findings": []any{}, "attack_paths": []any{}, "stop_reason": "mock_executor", "limitations": []string{"mock_executor", "no_real_tools_called", "no_security_finding_generated"}}
	default:
		return domain.ExecutionResult{Status: domain.RunStatusFailed, Result: domain.RunResult{Executor: e.Name(), Summary: "Mock executor rejected unknown agent.", ErrorCode: "unsupported_agent", ErrorMessage: "no mock output contract for agent " + request.Agent.ID}}, nil
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
