package agentcompose

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Notyet1307/security-agent-suite/internal/artifacts"
	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/validation"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	payload := strings.Repeat("x", maxCapturedOutput+10)

	var atLimit cappedBuffer
	written, err := atLimit.Write([]byte(payload[:maxCapturedOutput]))
	if err != nil || written != maxCapturedOutput || atLimit.Len() != maxCapturedOutput || atLimit.truncated {
		t.Fatalf("unexpected exact-limit buffer: written=%d len=%d truncated=%v err=%v", written, atLimit.Len(), atLimit.truncated, err)
	}
	written, err = atLimit.Write(nil)
	if err != nil || written != 0 || atLimit.truncated {
		t.Fatalf("empty write changed truncation: written=%d truncated=%v err=%v", written, atLimit.truncated, err)
	}

	var buffer cappedBuffer
	written, err = buffer.Write([]byte(payload))
	if err != nil || written != len(payload) || buffer.Len() != maxCapturedOutput || !buffer.truncated {
		t.Fatalf("unexpected capped buffer: written=%d len=%d truncated=%v err=%v", written, buffer.Len(), buffer.truncated, err)
	}
}

const validEventOutput = `{"protocol":"security-agent-suite.event-triage.v1","status":"completed","summary":"ok","classification":"benign","severity":"informational","confidence":1,"hypotheses":[],"evidence":[],"findings":[],"recommended_actions":[],"limitations":[]}`

func TestExecuteCapturesFinalOutputForApplicationGate(t *testing.T) {
	for name, output := range map[string]string{"valid": validEventOutput, "malformed": "not-json", "empty": ""} {
		executor := testExecutor(t, output, 0)
		result, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-" + name}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
		if err != nil || result.Status != domain.RunStatusSucceeded || len(result.Result.RawOutput) == 0 {
			t.Fatalf("%s: adapter must preserve process output: result=%+v err=%v", name, result, err)
		}
		if _, marshalErr := json.Marshal(result.Result); marshalErr != nil {
			t.Fatalf("raw output is not JSON-marshalable: %v", marshalErr)
		}
		if name != "empty" && len(result.Result.Artifacts) == 0 {
			t.Fatalf("%s: stdout artifact missing", name)
		}
	}
}

func TestEmptyStdoutFailsGateWithCodeEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-compose")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '%s' 'diagnostic' >&2\n"), 0755); err != nil {
		t.Fatal(err)
	}
	store, err := artifacts.New(filepath.Join(t.TempDir(), "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	executor := New(Config{Binary: path, Timeout: time.Second}, store)
	const runID = "run-empty"
	execution, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: runID}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err != nil || execution.Status != domain.RunStatusSucceeded {
		t.Fatalf("adapter execution=%+v err=%v", execution, err)
	}
	gated := validation.Gate("event-triage", execution, executor.Name())
	if gated.Status != domain.RunStatusFailed || gated.Result.ErrorCode != validation.CodeEmpty {
		t.Fatalf("gated result=%+v", gated)
	}
	if !json.Valid(gated.Result.RawOutput) {
		t.Fatalf("diagnostic raw output is not valid JSON: %q", gated.Result.RawOutput)
	}
	if len(gated.Result.Artifacts) != 1 || gated.Result.Artifacts[0].Name != "agent-compose-stderr.log" {
		t.Fatalf("stderr artifact was not retained: %+v", gated.Result.Artifacts)
	}
	if _, err := json.Marshal(gated.Result); err != nil {
		t.Fatalf("gated result is not persistence-safe: %v", err)
	}
}

func TestMalformedStdoutFailsGateWithCodeMalformed(t *testing.T) {
	executor := testExecutor(t, "not-json", 0)
	const runID = "run-malformed"
	execution, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: runID}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err != nil || execution.Status != domain.RunStatusSucceeded {
		t.Fatalf("adapter execution=%+v err=%v", execution, err)
	}
	gated := validation.Gate("event-triage", execution, executor.Name())
	if gated.Status != domain.RunStatusFailed || gated.Result.ErrorCode != validation.CodeMalformed {
		t.Fatalf("gated result=%+v", gated)
	}
	if string(gated.Result.RawOutput) != string(execution.Result.RawOutput) || !strings.Contains(string(gated.Result.RawOutput), `"stdout_valid_json":false`) {
		t.Fatalf("outer diagnostic output was not preserved: %q", gated.Result.RawOutput)
	}
	if len(gated.Result.Artifacts) != 1 || gated.Result.Artifacts[0].Name != "agent-compose-stdout.json" {
		t.Fatalf("stdout artifact was not retained: %+v", gated.Result.Artifacts)
	}
}

func TestExecutePreservesFullStdout(t *testing.T) {
	raw := `{"result":` + validEventOutput + `}`
	const runID = "run-raw"
	executor := testExecutor(t, raw, 0)
	result, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: runID}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err != nil || result.Status != domain.RunStatusSucceeded || string(result.Result.RawOutput) != raw {
		t.Fatalf("raw output changed: result=%+v err=%v", result, err)
	}
	if len(result.Result.Artifacts) != 1 {
		t.Fatalf("stdout artifact missing: %+v", result.Result.Artifacts)
	}
	file, _, err := executor.artifacts.Open(context.Background(), runID, result.Result.Artifacts[0])
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	captured, err := io.ReadAll(file)
	if err != nil || string(captured) != raw {
		t.Fatalf("stdout artifact changed: len=%d err=%v", len(captured), err)
	}
}

func TestExecuteFailsOnTruncatedOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-compose")
	if err := os.WriteFile(path, []byte("#!/bin/sh\ndd if=/dev/zero bs=1048576 count=9 2>/dev/null\n"), 0755); err != nil {
		t.Fatal(err)
	}
	store, err := artifacts.New(filepath.Join(t.TempDir(), "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	executor := New(Config{Binary: path, Timeout: time.Second}, store)
	const runID = "run-truncated"
	result, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: runID}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err != nil || result.Status != domain.RunStatusFailed || result.Result.ErrorCode != outputTruncatedCode {
		t.Fatalf("truncated result=%+v err=%v", result, err)
	}
	if !strings.Contains(string(result.Result.RawOutput), outputTruncatedMarker) || len(result.Result.Limitations) != 1 || result.Result.Limitations[0] != outputTruncatedMarker {
		t.Fatalf("truncation marker missing: %+v", result.Result)
	}
	if len(result.Result.Artifacts) != 1 || result.Result.Artifacts[0].Name != "agent-compose-stdout.json" {
		t.Fatalf("stdout artifact missing: %+v", result.Result.Artifacts)
	}
	file, _, err := executor.artifacts.Open(context.Background(), runID, result.Result.Artifacts[0])
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	captured, err := io.ReadAll(file)
	if err != nil || len(captured) != maxCapturedOutput {
		t.Fatalf("captured output length=%d err=%v", len(captured), err)
	}
}

func TestExecuteTimeoutWinsOverTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-compose")
	if err := os.WriteFile(path, []byte("#!/bin/sh\ndd if=/dev/zero bs=1048576 count=9 2>/dev/null\nsleep 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	store, err := artifacts.New(filepath.Join(t.TempDir(), "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	executor := New(Config{Binary: path, Timeout: time.Second}, store)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	const runID = "run-timeout-truncated"
	result, err := executor.Execute(ctx, domain.ExecutionRequest{Run: domain.Run{ID: runID}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if !errors.Is(err, context.DeadlineExceeded) || result.Status != domain.RunStatusFailed || result.Result.ErrorCode == outputTruncatedCode {
		t.Fatalf("timeout should win: result=%+v err=%v", result, err)
	}
	if !strings.Contains(string(result.Result.RawOutput), outputTruncatedMarker) || len(result.Result.Artifacts) == 0 {
		t.Fatalf("truncation diagnostics/artifact missing: %+v", result)
	}
}

func TestExecutePreservesNonzeroAndTimeoutFailures(t *testing.T) {
	executor := testExecutor(t, "failed", 7)
	result, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-exit"}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err != nil || result.Status != domain.RunStatusFailed || result.Result.ErrorCode != "agent_compose_exit" {
		t.Fatalf("exit result=%+v err=%v", result, err)
	}

	executor = testExecutor(t, "", 0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	// A shell sleep makes cancellation deterministic without relying on agent-compose.
	executor.cfg.Binary = executor.cfg.Binary + "-sleep"
	if err := os.WriteFile(executor.cfg.Binary, []byte("#!/bin/sh\nsleep 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	result, err = executor.Execute(ctx, domain.ExecutionRequest{Run: domain.Run{ID: "run-timeout"}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err == nil || result.Status != domain.RunStatusFailed || len(result.Result.RawOutput) == 0 {
		t.Fatalf("timeout result=%+v err=%v", result, err)
	}
}

func testExecutor(t *testing.T, output string, exit int) *Executor {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent-compose")
	body := "#!/bin/sh\n"
	if output != "" {
		body += "printf '%s' '" + output + "'\n"
	}
	if exit != 0 {
		body += "exit " + string(rune('0'+exit)) + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	store, err := artifacts.New(filepath.Join(t.TempDir(), "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	return New(Config{Binary: path, Timeout: time.Second}, store)
}
