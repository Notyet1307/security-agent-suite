package agentcompose

import (
	"strings"
	"testing"
)

func TestExtractSummary(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{`{"output":"done"}`, "done"},
		{`{"result":{"summary":"nested"}}`, "nested"},
		{"plain text", "plain text"},
	} {
		if got := extractSummary([]byte(test.input)); got != test.want {
			t.Fatalf("extractSummary(%q)=%q want %q", test.input, got, test.want)
		}
	}
}

func TestRedactArguments(t *testing.T) {
	got := redactArguments([]string{"--json", "run", "event-triage", "--prompt", "secret envelope", "--rm"})
	joined := strings.Join(got, " ")
	if strings.Contains(joined, "secret envelope") || !strings.Contains(joined, "<redacted-task-envelope>") {
		t.Fatalf("prompt not redacted: %v", got)
	}
}

func TestCappedBuffer(t *testing.T) {
	var buffer cappedBuffer
	payload := strings.Repeat("x", maxCapturedOutput+10)
	written, err := buffer.Write([]byte(payload))
	if err != nil || written != len(payload) || buffer.Len() != maxCapturedOutput || !buffer.truncated {
		t.Fatalf("unexpected capped buffer: written=%d len=%d truncated=%v err=%v", written, buffer.Len(), buffer.truncated, err)
	}
}
