package policy

import (
	"errors"
	"testing"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

func attackAgent() domain.AgentDefinition {
	return domain.AgentDefinition{ID: "attack-path-validation", AllowedModes: []string{"assess", "active_validate"}, InputTypes: []string{"scanner-result"}, OutputFormats: []string{"json"}, ApprovalRequiredModes: []string{"active_validate"}}
}

func TestActiveValidationRequiresScopeAndApproval(t *testing.T) {
	engine := New()
	req := domain.CreateRunRequest{RequestID: "r1", Mode: "active_validate", Inputs: []domain.InputRef{{Type: "scanner-result", URI: "artifact://x/y"}}, Scope: domain.Scope{TenantID: "tenant"}, Policy: domain.PolicyRequest{ActiveValidation: true, NetworkAccess: "restricted"}}
	_, err := engine.NormalizeAndEvaluate(attackAgent(), &req)
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected forbidden, got %v", err)
	}

	req.Scope.AuthorizationRef = "AUTH-1"
	req.Scope.Assets = []string{"https://target.example"}
	decision, err := engine.NormalizeAndEvaluate(attackAgent(), &req)
	if err != nil {
		t.Fatal(err)
	}
	if decision.InitialStatus != domain.RunStatusWaitingApproval || req.Policy.MaxRequests != 100 {
		t.Fatalf("unexpected decision: %+v request=%+v", decision, req)
	}
}

func TestRejectsUnsupportedOutput(t *testing.T) {
	engine := New()
	agent := domain.AgentDefinition{ID: "event-triage", AllowedModes: []string{"triage"}, InputTypes: []string{"alert"}, OutputFormats: []string{"json"}}
	req := domain.CreateRunRequest{RequestID: "r", Mode: "triage", Inputs: []domain.InputRef{{Type: "alert", URI: "artifact://x"}}, Scope: domain.Scope{TenantID: "t"}, Output: domain.OutputRequest{Formats: []string{"docx"}}}
	_, err := engine.NormalizeAndEvaluate(agent, &req)
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("expected invalid request, got %v", err)
	}
}
