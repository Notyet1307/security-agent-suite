package validation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

const validBlockedAttackOutput = `{"protocol":"security-agent-suite.attack-path-validation.v1","status":"blocked_by_policy","summary":"blocked","scope_check":{"authorized":false,"authorization_ref":"","approval_id":"","targets":[],"checks":[]},"validations":[],"evidence":[],"findings":[],"attack_paths":[],"stop_reason":"policy","limitations":[]}`

const gateEvidenceClaimOutput = `{"protocol":"security-agent-suite.event-triage.v1","status":"completed","summary":"bad","classification":"suspicious","severity":"high","confidence":1,"hypotheses":[],"evidence":[{"id":"model-e1","type":"log"}],"findings":[{"id":"f1","type":"risk","title":"bad","severity":"high","confidence":1,"status":"open","evidence_refs":["model-e1"]}],"recommended_actions":[],"limitations":[]}`

func TestGateMapsValidatedOutputStatuses(t *testing.T) {
	for _, test := range []struct {
		name    string
		agentID string
		raw     string
		want    domain.RunStatus
	}{
		{name: "completed", agentID: "event-triage", raw: validEventOutput("completed"), want: domain.RunStatusSucceeded},
		{name: "partial", agentID: "event-triage", raw: validEventOutput("partial"), want: domain.RunStatusPartial},
		{name: "insufficient", agentID: "event-triage", raw: validEventOutput("insufficient_evidence"), want: domain.RunStatusPartial},
		{name: "blocked by policy", agentID: "attack-path-validation", raw: validBlockedAttackOutput, want: domain.RunStatusFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := Gate(test.agentID, domain.ExecutionResult{
				Status: domain.RunStatusSucceeded,
				Result: domain.RunResult{RawOutput: []byte(test.raw)},
			}, "future-executor")
			if result.Status != test.want || result.Result.ErrorCode != "" {
				t.Fatalf("status=%q error_code=%q want status=%q", result.Status, result.Result.ErrorCode, test.want)
			}
		})
	}
}

func TestGatePreservesExecutionProvenance(t *testing.T) {
	provenance := &domain.ExecutionProvenance{DaemonRunID: "daemon-1", SandboxID: "sandbox-1", Provider: "pi"}
	got := Gate("event-triage", domain.ExecutionResult{
		Status: domain.RunStatusSucceeded,
		Result: domain.RunResult{RawOutput: []byte(validEventOutput("completed")), Provenance: provenance},
	}, "agentcompose-cli")
	if got.Status != domain.RunStatusSucceeded || got.Result.Provenance != provenance {
		t.Fatalf("provenance was not preserved: %+v", got.Result.Provenance)
	}
}
func TestGateCannotUpgradeRawPartialOrFailedStatus(t *testing.T) {
	raw := []byte(validEventOutput("completed"))
	for _, test := range []struct {
		name string
		raw  domain.RunStatus
		want domain.RunStatus
	}{
		{"partial", domain.RunStatusPartial, domain.RunStatusPartial},
		{"failed", domain.RunStatusFailed, domain.RunStatusFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := Gate("event-triage", domain.ExecutionResult{Status: test.raw, Result: domain.RunResult{RawOutput: raw}}, "future-executor")
			if got.Status != test.want {
				t.Fatalf("status=%q want %q", got.Status, test.want)
			}
		})
	}
}

func TestGateRejectsRuntimeTranscriptEnvelope(t *testing.T) {
	valid := validEventOutput("completed")
	for _, raw := range []string{`{"output":` + valid + `}`, `{"result":` + valid + `}`} {
		got := Gate("event-triage", domain.ExecutionResult{Status: domain.RunStatusSucceeded, Result: domain.RunResult{RawOutput: []byte(raw)}}, "future-executor")
		if got.Status != domain.RunStatusFailed || got.Result.ErrorCode != CodeContractInvalid {
			t.Fatalf("runtime transcript was accepted: status=%q code=%q", got.Status, got.Result.ErrorCode)
		}
	}
}

func TestGateClassifiesValidJSONNonObjectsAsContractInvalid(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
	}{
		{name: "array", raw: `[]`},
		{name: "string", raw: `"text"`},
		{name: "number", raw: `1`},
		{name: "boolean", raw: `true`},
		{name: "null", raw: `null`},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := Gate("event-triage", domain.ExecutionResult{
				Status: domain.RunStatusSucceeded,
				Result: domain.RunResult{RawOutput: []byte(test.raw)},
			}, "future-executor")
			if got.Status != domain.RunStatusFailed || got.Result.ErrorCode != CodeContractInvalid || string(got.Result.RawOutput) != test.raw {
				t.Fatalf("status=%q error_code=%q raw=%q", got.Status, got.Result.ErrorCode, got.Result.RawOutput)
			}
		})
	}
}

func TestParseAndGateRejectTrailingJSONValue(t *testing.T) {
	raw := validEventOutput("completed") + `{"second":true}`
	if _, err := Parse("event-triage", []byte(raw)); Code(err) != CodeMalformed {
		t.Fatalf("Parse code=%q err=%v", Code(err), err)
	}
	got := Gate("event-triage", domain.ExecutionResult{
		Status: domain.RunStatusSucceeded,
		Result: domain.RunResult{RawOutput: []byte(raw)},
	}, "future-executor")
	if got.Status != domain.RunStatusFailed || got.Result.ErrorCode != CodeMalformed || string(got.Result.RawOutput) != raw {
		t.Fatalf("Gate status=%q error_code=%q raw=%q", got.Status, got.Result.ErrorCode, got.Result.RawOutput)
	}
}

func TestGateRejectsUntrustedHighFinding(t *testing.T) {
	got := Gate("event-triage", domain.ExecutionResult{
		Status: domain.RunStatusSucceeded,
		Result: domain.RunResult{RawOutput: []byte(gateEvidenceClaimOutput)},
	}, "future-executor")
	if got.Status != domain.RunStatusFailed || got.Result.ErrorCode != CodeUntrustedClaims {
		t.Fatalf("status=%q error_code=%q result=%+v", got.Status, got.Result.ErrorCode, got.Result)
	}
	if len(got.Result.Evidence) != 0 || string(got.Result.RawOutput) != gateEvidenceClaimOutput {
		t.Fatalf("untrusted evidence was retained or raw output changed: %+v", got.Result)
	}
}

func TestGateUsesTrustedExecutorEvidence(t *testing.T) {
	trusted := domain.EvidenceRef{ID: "model-e1", Type: "trusted-log", SourceURI: "artifact://trusted/e1"}
	raw := strings.Replace(gateEvidenceClaimOutput, `"evidence":[{"id":"model-e1","type":"log"}]`, `"evidence":[]`, 1)
	got := Gate("event-triage", domain.ExecutionResult{
		Status: domain.RunStatusSucceeded,
		Result: domain.RunResult{RawOutput: []byte(raw), Evidence: []domain.EvidenceRef{trusted}},
	}, "future-executor")
	if got.Status != domain.RunStatusSucceeded || got.Result.ErrorCode != "" || len(got.Result.Evidence) != 1 {
		t.Fatalf("status=%q error_code=%q evidence=%+v", got.Status, got.Result.ErrorCode, got.Result.Evidence)
	}
	if got.Result.Evidence[0].Type != trusted.Type || got.Result.Evidence[0].SourceURI != trusted.SourceURI {
		t.Fatalf("model evidence was promoted: %+v", got.Result.Evidence)
	}
}

func TestGatePreservesSyntheticMockBypass(t *testing.T) {
	raw := `{"protocol":"security-agent-suite.mock-result.v1","evidence":[{"id":"fake"}]}`
	execution := domain.ExecutionResult{Status: domain.RunStatusSucceeded, Result: domain.RunResult{Summary: "mock", RawOutput: []byte(raw)}}
	got := Gate("event-triage", execution, "mock")
	if got.Status != execution.Status || got.Result.Summary != execution.Result.Summary || string(got.Result.RawOutput) != raw || got.Result.ErrorCode != "" {
		t.Fatalf("synthetic mock was not bypassed: %+v", got)
	}
}
func TestGateBoundsEarlyResultText(t *testing.T) {
	for _, status := range []domain.RunStatus{domain.RunStatusFailed, domain.RunStatusCancelled} {
		execution := domain.ExecutionResult{Status: status, Result: domain.RunResult{Summary: strings.Repeat("s", domain.MaxSummaryBytes+1), ErrorMessage: strings.Repeat("e", domain.MaxErrorMessageBytes+1)}}
		got := Gate("event-triage", execution, "future-executor")
		if got.Status != status || len([]byte(got.Result.Summary)) > domain.MaxSummaryBytes || len([]byte(got.Result.ErrorMessage)) > domain.MaxErrorMessageBytes {
			t.Fatalf("status=%q result text exceeded bounds", got.Status)
		}
	}
	raw := []byte(`{"protocol":"security-agent-suite.mock-result.v1"}`)
	got := Gate("event-triage", domain.ExecutionResult{Status: domain.RunStatusSucceeded, Result: domain.RunResult{Summary: strings.Repeat("s", domain.MaxSummaryBytes+1), ErrorMessage: strings.Repeat("e", domain.MaxErrorMessageBytes+1), RawOutput: raw}}, "mock")
	if len([]byte(got.Result.Summary)) > domain.MaxSummaryBytes || len([]byte(got.Result.ErrorMessage)) > domain.MaxErrorMessageBytes {
		t.Fatal("synthetic result text exceeded bounds")
	}
}

func TestGateRejectsUntrustedReportClaims(t *testing.T) {
	tests := []struct {
		name    string
		agentID string
		raw     string
	}{
		{
			name:    "security report metric",
			agentID: "security-report",
			raw:     `{"protocol":"security-agent-suite.security-report.v1","status":"completed","report_type":"daily","period":{"start":"2026-01-01T00:00:00Z","end":"2026-01-02T00:00:00Z","timezone":"UTC"},"executive_summary":"ok","metrics":[{"name":"count","value":1,"unit":"count","formula":"source","source_refs":[],"validated":true}],"key_events":[],"recommendations":[],"artifacts":[],"validation":{"numbers":"passed","citations":"passed","template":"passed","sensitive_data":"passed"},"limitations":[]}`,
		},
		{
			name:    "compliance citation",
			agentID: "compliance-query",
			raw:     `{"protocol":"security-agent-suite.compliance-query.v1","status":"completed","answer":"ok","applicability":{"applies":"yes","assumptions":[],"reason":"ok"},"citations":[{"document":"policy","issuer":"issuer","version":"1","effective_date":"2026-01-01","location":"p1","source_uri":"https://example.test/policy","summary":"ok"}],"control_gaps":[],"evidence_requirements":[],"recommendations":[],"uncertainty":[]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Gate(test.agentID, domain.ExecutionResult{
				Status: domain.RunStatusSucceeded,
				Result: domain.RunResult{RawOutput: []byte(test.raw)},
			}, "future-executor")
			if got.Status != domain.RunStatusFailed || got.Result.ErrorCode != CodeUntrustedClaims || string(got.Result.RawOutput) != test.raw {
				t.Fatalf("status=%q error_code=%q raw=%q", got.Status, got.Result.ErrorCode, got.Result.RawOutput)
			}
		})
	}
}

func TestGateRejectsUntrustedExpandedEvidenceReferences(t *testing.T) {
	tests := []struct {
		name    string
		agentID string
		raw     string
	}{
		{
			name:    "source_refs",
			agentID: "security-report",
			raw:     `{"protocol":"security-agent-suite.security-report.v1","status":"completed","report_type":"daily","period":{"start":"2026-01-01T00:00:00Z","end":"2026-01-02T00:00:00Z","timezone":"UTC"},"executive_summary":"ok","metrics":[],"key_events":[{"title":"event","severity":"informational","summary":"event","source_refs":["untrusted-source"]}],"recommendations":[],"artifacts":[],"validation":{"numbers":"passed","citations":"passed","template":"passed","sensitive_data":"passed"},"limitations":[]}`,
		},
		{
			name:    "supporting_evidence",
			agentID: "event-triage",
			raw:     `{"protocol":"security-agent-suite.event-triage.v1","status":"completed","summary":"ok","classification":"benign","severity":"informational","confidence":1,"hypotheses":[{"hypothesis":"h","status":"possible","supporting_evidence":["untrusted-support"],"contradicting_evidence":[],"gaps":[]}],"evidence":[],"findings":[],"recommended_actions":[],"limitations":[]}`,
		},
		{
			name:    "customer_evidence_refs",
			agentID: "compliance-query",
			raw:     `{"protocol":"security-agent-suite.compliance-query.v1","status":"completed","answer":"ok","applicability":{"applies":"yes","assumptions":[],"reason":"ok"},"citations":[],"control_gaps":[{"control":"AC-1","status":"not_assessed","requirement_citation":"req","customer_evidence_refs":["untrusted-customer"],"reason":"unknown"}],"evidence_requirements":[],"recommendations":[],"uncertainty":[]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Gate(test.agentID, domain.ExecutionResult{
				Status: domain.RunStatusSucceeded,
				Result: domain.RunResult{RawOutput: []byte(test.raw)},
			}, "future-executor")
			if got.Status != domain.RunStatusFailed || got.Result.ErrorCode != CodeUntrustedClaims || string(got.Result.RawOutput) != test.raw {
				t.Fatalf("status=%q error_code=%q raw=%q", got.Status, got.Result.ErrorCode, got.Result.RawOutput)
			}
		})
	}
}

func validEventOutput(status string) string {
	return strings.Replace(`{"protocol":"security-agent-suite.event-triage.v1","status":"completed","summary":"ok","classification":"benign","severity":"informational","confidence":1,"hypotheses":[],"evidence":[],"findings":[],"recommended_actions":[],"limitations":[]}`, `"completed"`, `"`+status+`"`, 1)
}
func TestParseMinimalEnvelopeForEveryAgent(t *testing.T) {
	tests := map[string]map[string]any{
		"traffic-analysis": {
			"protocol": "security-agent-suite.traffic-analysis.v1", "status": "completed", "summary": "ok",
			"evidence": []any{}, "timeline": []any{}, "findings": []any{}, "limitations": []any{},
		},
		"security-report": {
			"protocol": "security-agent-suite.security-report.v1", "status": "completed", "report_type": "daily",
			"period":            map[string]any{"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z", "timezone": "UTC"},
			"executive_summary": "ok", "metrics": []any{}, "key_events": []any{}, "recommendations": []any{}, "artifacts": []any{},
			"validation": map[string]any{"numbers": "passed", "citations": "passed", "template": "passed", "sensitive_data": "passed"}, "limitations": []any{},
		},
		"compliance-query": {
			"protocol": "security-agent-suite.compliance-query.v1", "status": "completed", "answer": "ok",
			"applicability": map[string]any{"applies": "yes", "assumptions": []any{}, "reason": "ok"}, "citations": []any{}, "control_gaps": []any{},
			"evidence_requirements": []any{}, "recommendations": []any{}, "uncertainty": []any{},
		},
		"event-triage": {
			"protocol": "security-agent-suite.event-triage.v1", "status": "completed", "summary": "ok", "classification": "benign", "severity": "informational", "confidence": 1.0,
			"hypotheses": []any{}, "evidence": []any{}, "findings": []any{}, "recommended_actions": []any{}, "limitations": []any{},
		},
		"attack-path-validation": {
			"protocol": "security-agent-suite.attack-path-validation.v1", "status": "completed", "summary": "ok",
			"scope_check": map[string]any{"authorized": true, "authorization_ref": "AUTH-1", "approval_id": "APP-1", "targets": []any{}, "checks": []any{}},
			"validations": []any{}, "evidence": []any{}, "findings": []any{}, "attack_paths": []any{}, "stop_reason": "done", "limitations": []any{},
		},
	}
	for agentID, payload := range tests {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		result, err := Parse(agentID, raw)
		if err != nil {
			t.Fatalf("%s: result=%+v err=%v", agentID, result, err)
		}
	}
}

func TestParseRejectsMalformedProtocolAndUnknownFields(t *testing.T) {
	_, err := Parse("event-triage", []byte("{"))
	if Code(err) != CodeMalformed {
		t.Fatalf("malformed code=%q err=%v", Code(err), err)
	}
	_, err = Parse("event-triage", []byte(`{"protocol":"wrong"}`))
	if Code(err) != CodeContractInvalid {
		t.Fatalf("contract code=%q err=%v", Code(err), err)
	}
	_, err = Parse("event-triage", []byte(`{"protocol":"security-agent-suite.event-triage.v1","status":"completed","summary":"ok","classification":"benign","severity":"informational","confidence":1,"hypotheses":[],"evidence":[],"findings":[],"recommended_actions":[],"limitations":[],"extra":true}`))
	if Code(err) != CodeContractInvalid {
		t.Fatalf("unknown field code=%q err=%v", Code(err), err)
	}
}

func TestParseRejectsHighFindingWithoutEvidence(t *testing.T) {
	payload := `{"protocol":"security-agent-suite.event-triage.v1","status":"completed","summary":"bad","classification":"suspicious","severity":"high","confidence":1,"hypotheses":[],"evidence":[],"findings":[{"id":"f1","type":"risk","title":"bad","severity":"high","confidence":1,"status":"open","evidence_refs":[]}],"recommended_actions":[],"limitations":[]}`
	_, err := Parse("event-triage", []byte(payload))
	if Code(err) != CodeEvidenceInvalid {
		t.Fatalf("evidence code=%q err=%v", Code(err), err)
	}
}

func TestParseRejectsInvalidEvidenceMetadata(t *testing.T) {
	for name, evidence := range map[string]string{
		"sha":      `{"id":"e1","type":"log","sha256":"bad"}`,
		"metadata": `{"id":"e1","type":"log","metadata":{"source":1}}`,
	} {
		payload := `{"protocol":"security-agent-suite.event-triage.v1","status":"completed","summary":"ok","classification":"benign","severity":"informational","confidence":1,"hypotheses":[],"evidence":[` + evidence + `],"findings":[],"recommended_actions":[],"limitations":[]}`
		if _, err := Parse("event-triage", []byte(payload)); Code(err) != CodeContractInvalid {
			t.Fatalf("%s: code=%q err=%v", name, Code(err), err)
		}
	}
}
