package prompt

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

func TestBuildStructuredEnvelope(t *testing.T) {
	run := domain.Run{
		ID: "run-1", RequestID: "req-1", AgentID: "event-triage", Mode: "triage",
		Inputs: []domain.InputRef{{Type: "alert", URI: "artifact://alerts/1"}},
		Scope:  domain.Scope{TenantID: "tenant-1"},
	}
	agent := domain.AgentDefinition{ID: "event-triage"}
	text, err := New().Build(run, agent)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "untrusted data") || !strings.Contains(text, "Return the final JSON object only") {
		t.Fatalf("missing safety wrapper: %s", text)
	}
	start := strings.Index(text, "<task-envelope>\n") + len("<task-envelope>\n")
	end := strings.Index(text, "\n</task-envelope>")
	if start < len("<task-envelope>\n") || end <= start {
		t.Fatal("task envelope tags missing")
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(text[start:end]), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["protocol"] != "security-agent-suite.task.v1" || payload["agent_id"] != "event-triage" {
		t.Fatalf("unexpected envelope: %+v", payload)
	}
}
