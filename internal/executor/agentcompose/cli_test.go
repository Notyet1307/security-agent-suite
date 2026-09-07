package agentcompose

import (
	"context"
	"errors"
	"github.com/Notyet1307/security-agent-suite/internal/artifacts"
	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/validation"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

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

func TestExecuteRejectsNilArtifactStore(t *testing.T) {
	executor := New(Config{Binary: "true", Timeout: time.Second}, nil)
	if _, err := executor.Execute(context.Background(), domain.ExecutionRequest{}); err == nil || !strings.Contains(err.Error(), "artifact store") {
		t.Fatalf("expected controlled artifact store error, got %v", err)
	}
}

// Provenance: agent-compose v2609.1.0 composeRunOutput and Pi AgentResult:
// https://github.com/chaitin/agent-compose/blob/v2609.1.0/cmd/agent-compose/cli_run_output.go
// https://github.com/chaitin/agent-compose/blob/v2609.1.0/runtime/javascript/src/types.ts
func TestParseRuntimeEnvelope(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	fixture, err := os.ReadFile(filepath.Join(filepath.Dir(file), "testdata", "fixtures", "agent-compose-v2609.1.0-pi-runtime-envelope.json"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, result, err := ParseRuntimeEnvelope(fixture)
	if err != nil || envelope.Status == "" || result.FinalText == "" {
		t.Fatalf("fixture parse: envelope=%+v result=%+v err=%v", envelope, result, err)
	}
	if envelope.ExitCode != 0 || envelope.Error != "" || envelope.CleanupError != "" || envelope.Output == "" || envelope.ResultJSON == "" {
		t.Fatalf("fixture core metadata not decoded: %+v", envelope)
	}
	if envelope.ID != "run-contract-smoke" || envelope.ShortID != "run-cs" || envelope.ProjectID != "project-suite" || envelope.ProjectName != "security-agent-suite" || envelope.AgentName != "event-triage" || envelope.Source != "manual" || envelope.SandboxID != "sandbox-cs" || envelope.SandboxShortID != "sb-cs" {
		t.Fatalf("fixture IDs metadata not decoded: %+v", envelope)
	}
	if envelope.LogsPath != "/tmp/contract-smoke.log" || envelope.ArtifactsDir != "/tmp/contract-smoke-artifacts" || envelope.Driver != "docker" || envelope.ImageRef != "guest:fixture" || envelope.LogsCommand == "" || envelope.JupyterURL == "" || envelope.JupyterPath != "/workspace" {
		t.Fatalf("fixture paths/runtime metadata not decoded: %+v", envelope)
	}
	if len(envelope.Warnings) != 1 || envelope.Warnings[0] != "fixture warning" || envelope.Labels["suite"] != "contract" {
		t.Fatalf("fixture warnings/labels metadata not decoded: %+v", envelope)
	}
	if result.Provider != "pi" || result.ThreadID == "" || result.StopReason != "completed" || result.FinalTextSource != "provider_message" || result.Transcript == "" || result.Transcript == result.FinalText {
		t.Fatalf("fixture provider metadata not decoded: %+v", result)
	}
	gated := validation.Gate("event-triage", domain.ExecutionResult{Status: domain.RunStatusSucceeded, Result: domain.RunResult{RawOutput: []byte(result.FinalText)}}, "agentcompose-cli")
	if gated.Status != domain.RunStatusSucceeded || gated.Result.ErrorCode != "" {
		t.Fatalf("fixture finalText did not validate: %+v", gated)
	}
	encodedResult := `{"provider":"pi","finalText":"{}","finalTextSource":"provider_message"}`
	encoded := `{"status":"completed","exit_code":0,"error":"","output":{"protocol":"transcript"},"result_json":` + strconv.Quote(encodedResult) + `}`
	if _, result, err := ParseRuntimeEnvelope([]byte(encoded)); err != nil || result.FinalText != "{}" {
		t.Fatalf("encoded result parse: result=%+v err=%v", result, err)
	}
	object := `{"status":"completed","exit_code":0,"result_json":` + encodedResult + `}`
	if _, result, err := ParseRuntimeEnvelope([]byte(object)); err != nil || result.FinalText != "{}" {
		t.Fatalf("object result parse: result=%+v err=%v", result, err)
	}
	for _, raw := range []string{
		`{"status":"completed","exit_code":null,"error":"","result_json":{"finalText":"{}"}}`,
		`{"status":"completed","exit_code":0,"error":"","result_json":"not-json"}`,
		`{"status":"completed","exit_code":0,"error":"","result_json":{"finaltext":"{}"}}`,
		`{"status":"completed","exit_code":0,"error":"","result_json":{"finalText":"{}"}} trailing`,
	} {
		if _, _, err := ParseRuntimeEnvelope([]byte(raw)); err == nil {
			t.Fatalf("accepted malformed envelope: %s", raw)
		}
	}
}

const validEventOutput = `{"protocol":"security-agent-suite.event-triage.v1","status":"completed","summary":"ok","classification":"benign","severity":"informational","confidence":1,"hypotheses":[],"evidence":[],"findings":[],"recommended_actions":[],"limitations":[]}`

func providerResultJSON(provider, finalTextSource, finalText string) string {
	return `{"provider":` + strconv.Quote(provider) + `,"finalText":` + strconv.Quote(finalText) + `,"finalTextSource":` + strconv.Quote(finalTextSource) + `}`
}

func TestExecuteCapturesProviderFinalTextForApplicationGate(t *testing.T) {
	runtime := `{"status":"completed","id":"daemon-1","short_id":"d1","project_id":"project-1","project_name":"suite","agent_name":"event-triage","source":"manual","sandbox_id":"sandbox-1","sandbox_short_id":"s1","driver":"docker","image_ref":"guest:v1","started_at":"2026-09-04T00:00:00Z","completed_at":"2026-09-04T00:00:01Z","duration_ms":1000,"warnings":["warning"],"labels":{"suite":"test"},"exit_code":0,"output":"transcript","result_json":` + strconv.Quote(`{"provider":"pi","threadId":"thread-1","stopReason":"completed","finalText":`+strconv.Quote(validEventOutput)+`,"finalTextSource":"provider_message"}`) + `}`
	executor := testExecutor(t, runtime, 0)
	result, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-valid"}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err != nil || result.Status != domain.RunStatusSucceeded || string(result.Result.RawOutput) != validEventOutput {
		t.Fatalf("provider finalText was not selected: result=%+v err=%v", result, err)
	}
	if len(result.Result.Artifacts) != 3 || result.Result.Artifacts[0].Name != "agent-compose-runtime-envelope.json" {
		t.Fatalf("runtime artifacts missing: %+v", result.Result.Artifacts)
	}
	provenance := result.Result.Provenance
	if provenance == nil || provenance.DaemonRunID != "daemon-1" || provenance.SandboxID != "sandbox-1" || provenance.Provider != "pi" || provenance.ThreadID != "thread-1" || provenance.StopReason != "completed" || provenance.Labels["suite"] != "test" {
		t.Fatalf("provenance was not mapped: %+v", provenance)
	}
}

func TestRuntimeProviderOutputScenarios(t *testing.T) {
	validEnvelope := func(status, resultJSON string) string {
		return `{"status":` + strconv.Quote(status) + `,"id":"daemon-provider-scenarios","sandbox_id":"sandbox-provider-scenarios","exit_code":0,"error":"","output":"transcript secret prompt","result_json":` + strconv.Quote(resultJSON) + `}`
	}
	resultJSON := func(finalText string) string { return providerResultJSON("pi", "provider_message", finalText) }
	validLookingTranscript := strings.Replace(validEnvelope("completed", resultJSON("not-json")), `"output":"transcript secret prompt"`, `"output":`+strconv.Quote(validEventOutput), 1)
	cases := []struct {
		name      string
		raw       string
		want      domain.RunStatus
		rejectRaw bool
	}{
		{"valid provider_message", validEnvelope("completed", resultJSON(validEventOutput)), domain.RunStatusSucceeded, false},
		{"invalid finalText", validEnvelope("completed", resultJSON("not-json")), domain.RunStatusFailed, false},
		{"empty finalText", validEnvelope("completed", resultJSON("")), domain.RunStatusFailed, true},
		{"missing result_json", `{"status":"completed","exit_code":0,"error":"","output":"transcript secret prompt"}`, domain.RunStatusFailed, true},
		{"invalid result_json", validEnvelope("completed", `"not-json"`), domain.RunStatusFailed, true},
		{"runtime failed", validEnvelope("failed", resultJSON(validEventOutput)), domain.RunStatusFailed, false},
		{"markdown code block", validEnvelope("completed", resultJSON("```json\n"+validEventOutput+"\n```")), domain.RunStatusFailed, false},
		{"trailing finalText", validEnvelope("completed", resultJSON(validEventOutput+" trailing")), domain.RunStatusFailed, false},
		{"valid-looking transcript", validLookingTranscript, domain.RunStatusFailed, false},
		{"missing provider", validEnvelope("completed", `{"finalText":`+strconv.Quote(validEventOutput)+`,"finalTextSource":"provider_message"}`), domain.RunStatusFailed, true},
		{"empty provider", validEnvelope("completed", providerResultJSON("", "provider_message", validEventOutput)), domain.RunStatusFailed, true},
		{"unknown provider", validEnvelope("completed", providerResultJSON("foo", "provider_message", validEventOutput)), domain.RunStatusFailed, true},
		{"missing finalTextSource", validEnvelope("completed", `{"provider":"pi","finalText":`+strconv.Quote(validEventOutput)+`}`), domain.RunStatusFailed, true},
		{"unknown finalTextSource", validEnvelope("completed", providerResultJSON("pi", "unknown", validEventOutput)), domain.RunStatusFailed, true},
		{"transcript fallback", strings.Replace(validEnvelope("completed", providerResultJSON("pi", "transcript_fallback", validEventOutput)), `"output":"transcript secret prompt"`, `"output":`+strconv.Quote(validEventOutput), 1), domain.RunStatusFailed, true},
		{"none finalTextSource", validEnvelope("completed", providerResultJSON("pi", "none", validEventOutput)), domain.RunStatusFailed, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			executor := testExecutor(t, test.raw, 0)
			execution, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-case"}, Prompt: "secret prompt", Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
			if err != nil {
				t.Fatal(err)
			}
			got := validation.Gate("event-triage", execution, executor.Name())
			if got.Status != test.want {
				t.Fatalf("status=%q want=%q result=%+v", got.Status, test.want, got.Result)
			}
			if test.rejectRaw && (len(execution.Result.RawOutput) != 0 || got.Result.ErrorCode != validation.CodeEmpty) {
				t.Fatalf("untrusted finalText was promoted or bypassed the gate: execution=%+v gated=%+v", execution.Result, got.Result)
			}
			if test.name == "transcript fallback" {
				provenance := execution.Result.Provenance
				if provenance == nil || provenance.DaemonRunID != "daemon-provider-scenarios" || provenance.SandboxID != "sandbox-provider-scenarios" || provenance.FinalTextSource != "transcript_fallback" {
					t.Fatalf("transcript fallback provenance was not preserved: %+v", provenance)
				}
			}
			if test.name == "missing result_json" || test.name == "invalid result_json" {
				if len(execution.Result.Artifacts) != 2 || len(execution.Result.RawOutput) != 0 {
					t.Fatalf("diagnostic artifacts/business output mismatch: %+v", execution.Result)
				}
				file, _, openErr := executor.artifacts.Open(context.Background(), "run-case", execution.Result.Artifacts[0])
				if openErr != nil {
					t.Fatal(openErr)
				}
				captured, readErr := io.ReadAll(file)
				_ = file.Close()
				if readErr != nil || string(captured) != test.raw {
					t.Fatalf("envelope artifact changed: err=%v", readErr)
				}
				file, _, openErr = executor.artifacts.Open(context.Background(), "run-case", execution.Result.Artifacts[1])
				if openErr != nil {
					t.Fatal(openErr)
				}
				captured, readErr = io.ReadAll(file)
				_ = file.Close()
				if readErr != nil || string(captured) != "transcript <redacted-task-envelope>" {
					t.Fatalf("transcript artifact=%q err=%v", captured, readErr)
				}
			}
		})
	}
}

func TestExecuteAcceptsPinnedProviders(t *testing.T) {
	for _, provider := range []string{"codex", "claude", "gemini", "opencode", "pi", "dsh"} {
		t.Run(provider, func(t *testing.T) {
			raw := `{"status":"completed","exit_code":0,"result_json":` + strconv.Quote(providerResultJSON(provider, "provider_message", validEventOutput)) + `}`
			executor := testExecutor(t, raw, 0)
			result, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-provider-" + provider}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
			if err != nil || result.Status != domain.RunStatusSucceeded || string(result.Result.RawOutput) != validEventOutput {
				t.Fatalf("provider %q result=%+v err=%v", provider, result, err)
			}
		})
	}
}

func TestExecuteMapsCanceledRuntimeStatus(t *testing.T) {
	raw := `{"status":"canceled","exit_code":0,"error":"","output":"transcript","result_json":` + strconv.Quote(`{"finalText":`+strconv.Quote(validEventOutput)+`}`) + `}`
	executor := testExecutor(t, raw, 0)
	result, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-canceled"}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err != nil || result.Status != domain.RunStatusCancelled || result.Result.ErrorCode != "agent_compose_cancelled" {
		t.Fatalf("canceled runtime status=%+v err=%v", result, err)
	}
}

func TestExecuteMapsCanceledRuntimeStatusWithExitAndError(t *testing.T) {
	raw := `{"status":"canceled","exit_code":1,"error":"context canceled","output":"transcript","result_json":` + strconv.Quote(`{"finalText":`+strconv.Quote(validEventOutput)+`}`) + `}`
	executor := testExecutor(t, raw, 0)
	result, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-canceled-fields"}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err != nil || result.Status != domain.RunStatusCancelled || result.Result.ErrorCode != "agent_compose_cancelled" || result.Result.ErrorMessage != "context canceled" {
		t.Fatalf("canceled runtime fields status=%+v err=%v", result, err)
	}
}

func TestExecuteMapsCanceledRuntimeStatusWithNonzeroProcessExit(t *testing.T) {
	raw := `{"status":"canceled","exit_code":1,"error":"context canceled","output":"transcript","result_json":` + strconv.Quote(`{"finalText":`+strconv.Quote(validEventOutput)+`}`) + `}`
	executor := testExecutor(t, raw, 1)
	result, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-canceled-process-exit"}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err != nil || result.Status != domain.RunStatusCancelled || result.Result.ErrorCode != "agent_compose_cancelled" || result.Result.ErrorMessage != "context canceled" {
		t.Fatalf("canceled nonzero process status=%+v err=%v", result, err)
	}
}

func TestExecuteCanceledContextWinsOverCanceledRuntimeStatusWithNonzeroProcessExit(t *testing.T) {
	raw := `{"status":"cancelled","id":"daemon-canceled-context","sandbox_id":"sandbox-canceled-context","exit_code":1,"error":"context canceled","output":"transcript","result_json":` + strconv.Quote(`{"finalText":`+strconv.Quote(validEventOutput)+`}`) + `}`
	t.Setenv("SAS_AGENT_COMPOSE_OUTPUT", raw)
	result, err, interrupted := executeSignalHelper(t, false, false)
	if !errors.Is(err, context.Canceled) || result.Status != domain.RunStatusFailed || interrupted != "interrupted" {
		t.Fatalf("canceled context runtime status=%+v err=%v interrupted=%q", result, err, interrupted)
	}
	if result.Result.Provenance == nil || result.Result.Provenance.DaemonRunID != "daemon-canceled-context" || result.Result.Provenance.SandboxID != "sandbox-canceled-context" {
		t.Fatalf("canceled context runtime provenance=%+v", result.Result.Provenance)
	}
}

func TestExecuteRequestDeadlineWinsOverCanceledRuntimeStatus(t *testing.T) {
	raw := `{"status":"canceled","id":"daemon-timeout","sandbox_id":"sandbox-timeout","exit_code":1,"error":"context deadline exceeded","output":"transcript","result_json":` + strconv.Quote(`{"finalText":`+strconv.Quote(validEventOutput)+`}`) + `}`
	t.Setenv("SAS_AGENT_COMPOSE_OUTPUT", raw)
	result, err, interrupted := executeSignalHelper(t, false, true)
	if !errors.Is(err, context.DeadlineExceeded) || result.Status != domain.RunStatusFailed || interrupted != "interrupted" {
		t.Fatalf("deadline canceled envelope result=%+v err=%v interrupted=%q", result, err, interrupted)
	}
	if result.Result.Provenance == nil || result.Result.Provenance.DaemonRunID != "daemon-timeout" || result.Result.Provenance.SandboxID != "sandbox-timeout" {
		t.Fatalf("deadline canceled envelope provenance=%+v", result.Result.Provenance)
	}
}

func TestExecutePreservesCanceledRuntimeProvenanceWithoutResult(t *testing.T) {
	raw := `{"status":"canceled","id":"daemon-canceled","sandbox_id":"sandbox-canceled","driver":"docker","image_ref":"guest:canceled","exit_code":0,"error":""}`
	executor := testExecutor(t, raw, 0)
	result, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-canceled-provenance"}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err != nil || result.Status != domain.RunStatusCancelled {
		t.Fatalf("canceled envelope result=%+v err=%v", result, err)
	}
	if result.Result.Provenance == nil || result.Result.Provenance.DaemonRunID != "daemon-canceled" || result.Result.Provenance.SandboxID != "sandbox-canceled" || result.Result.Provenance.Driver != "docker" || result.Result.Provenance.ImageRef != "guest:canceled" {
		t.Fatalf("canceled envelope provenance=%+v", result.Result.Provenance)
	}
}

func TestExecutorRuntimeFailurePrecedesProviderParseFailure(t *testing.T) {
	raw := `{"status":"failed","id":"daemon-failed","sandbox_id":"sandbox-failed","exit_code":0,"error":"provider failed","driver":"docker","image_ref":"guest:v1"}`
	executor := testExecutor(t, raw, 0)
	got, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-runtime-failed"}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err != nil || got.Status != domain.RunStatusFailed || got.Result.ErrorCode != "agent_compose_runtime" {
		t.Fatalf("runtime failure was upgraded: result=%+v err=%v", got, err)
	}
	if got.Result.Provenance == nil || got.Result.Provenance.DaemonRunID != "daemon-failed" || got.Result.Provenance.SandboxID != "sandbox-failed" {
		t.Fatalf("runtime failure provenance missing: %+v", got.Result.Provenance)
	}
}
func TestExecutorPartialRuntimeStatusPrecedesProviderParseFailure(t *testing.T) {
	raw := `{"status":"partial","exit_code":0,"output":"transcript"}`
	executor := testExecutor(t, raw, 0)
	got, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-runtime-partial"}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err != nil || got.Status != domain.RunStatusPartial {
		t.Fatalf("partial runtime was upgraded: result=%+v err=%v", got, err)
	}
}

func TestExecutorTruncationDoesNotPublishBusinessArtifacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-compose")
	runtime := `{"status":"completed","exit_code":0,"output":"transcript","result_json":` + strconv.Quote(providerResultJSON("pi", "provider_message", validEventOutput)) + `}`
	script := "#!/bin/sh\nprintf '%s' '" + runtime + "'\ndd if=/dev/zero bs=1048576 count=9 2>/dev/null\n"
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	store, err := artifacts.New(filepath.Join(t.TempDir(), "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	executor := New(Config{Binary: path, Timeout: time.Second}, store)
	got, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-truncated-valid"}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err != nil || got.Status != domain.RunStatusFailed || got.Result.ErrorCode != outputTruncatedCode {
		t.Fatalf("truncation result=%+v err=%v", got, err)
	}
	if got.Result.Provenance != nil {
		t.Fatalf("truncated output produced provenance: %+v", got.Result.Provenance)
	}
	if len(got.Result.RawOutput) != 0 || len(got.Result.Artifacts) != 1 || got.Result.Artifacts[0].Name != "agent-compose-runtime-envelope.json" {
		t.Fatalf("business artifacts leaked: %+v", got.Result)
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
	execution, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-empty"}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err != nil || execution.Status != domain.RunStatusSucceeded {
		t.Fatalf("adapter execution=%+v err=%v", execution, err)
	}
	if len(execution.Result.Artifacts) != 1 || execution.Result.Artifacts[0].Name != "agent-compose-stderr.log" {
		t.Fatalf("stderr artifact missing: %+v", execution.Result.Artifacts)
	}
}

func TestMalformedStdoutFailsGate(t *testing.T) {
	executor := testExecutor(t, "not-json", 0)
	execution, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-malformed"}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err != nil || execution.Status != domain.RunStatusSucceeded {
		t.Fatalf("adapter execution=%+v err=%v", execution, err)
	}
	gated := validation.Gate("event-triage", execution, executor.Name())
	if gated.Status != domain.RunStatusFailed || gated.Result.ErrorCode != validation.CodeEmpty {
		t.Fatalf("gated result=%+v", gated)
	}
	if execution.Result.Provenance != nil {
		t.Fatalf("malformed output produced provenance: %+v", execution.Result.Provenance)
	}
	if len(gated.Result.Artifacts) != 1 || gated.Result.Artifacts[0].Name != "agent-compose-runtime-envelope.json" {
		t.Fatalf("diagnostic artifacts missing: %+v", gated.Result.Artifacts)
	}
}

func TestExecutePreservesControlledEnvelopeAndSeparateRawOutput(t *testing.T) {
	const (
		runID  = "run-raw"
		prompt = "secret prompt"
	)
	finalText := strings.Replace(validEventOutput, `"summary":"ok"`, `"summary":"`+prompt+`"`, 1)
	raw := `{"status":"completed","exit_code":0,"error":"","output":"transcript ` + prompt + `","result_json":` + strconv.Quote(providerResultJSON("pi", "provider_message", finalText)) + `}`
	executor := testExecutor(t, raw, 0)
	result, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: runID}, Prompt: prompt, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err != nil || result.Status != domain.RunStatusSucceeded || string(result.Result.RawOutput) != finalText {
		t.Fatalf("provider output changed: result=%+v err=%v", result, err)
	}
	if len(result.Result.Artifacts) != 3 {
		t.Fatalf("runtime artifacts missing: %+v", result.Result.Artifacts)
	}
	file, _, err := executor.artifacts.Open(context.Background(), runID, result.Result.Artifacts[0])
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	captured, err := io.ReadAll(file)
	if err != nil || string(captured) != raw {
		t.Fatalf("controlled envelope changed: err=%v", err)
	}
	redactedFinalText := strings.Replace(finalText, prompt, "<redacted-task-envelope>", 1)
	for i, want := range []string{"transcript <redacted-task-envelope>", redactedFinalText} {
		file, _, err := executor.artifacts.Open(context.Background(), runID, result.Result.Artifacts[i+1])
		if err != nil {
			t.Fatal(err)
		}
		captured, err := io.ReadAll(file)
		_ = file.Close()
		if err != nil || string(captured) != want {
			t.Fatalf("artifact %d content=%q want=%q", i+1, captured, want)
		}
		if i == 1 && strings.Contains(string(captured), prompt) {
			t.Fatalf("final-output artifact leaked prompt: %q", captured)
		}
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
	result, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-truncated"}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err != nil || result.Status != domain.RunStatusFailed || result.Result.ErrorCode != outputTruncatedCode {
		t.Fatalf("truncated result=%+v err=%v", result, err)
	}
	if result.Result.Provenance != nil {
		t.Fatalf("truncated output produced provenance: %+v", result.Result.Provenance)
	}
	if len(result.Result.RawOutput) != 0 || len(result.Result.Limitations) != 1 {
		t.Fatalf("business output leaked diagnostics: %+v", result.Result)
	}
	if len(result.Result.Artifacts) != 1 {
		t.Fatalf("diagnostic artifacts missing: %+v", result.Result.Artifacts)
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
	if len(result.Result.RawOutput) != 0 {
		t.Fatalf("diagnostic output leaked into business result: %+v", result)
	}
}

func TestExecuteMapsNonzeroExitCodes(t *testing.T) {
	for _, test := range []struct {
		name string
		exit int
		code string
	}{
		{name: "unavailable", exit: exitCodeUnavailable, code: "agent_compose_unavailable"},
		{name: "other", exit: 7, code: "agent_compose_exit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent-compose")
			script := "#!/bin/sh\nprintf '%s' 'diagnostic' >&2\nexit " + strconv.Itoa(test.exit) + "\n"
			if err := os.WriteFile(path, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			store, err := artifacts.New(filepath.Join(t.TempDir(), "artifacts"))
			if err != nil {
				t.Fatal(err)
			}
			executor := New(Config{Binary: path, Timeout: time.Second}, store)
			result, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-exit-" + test.name}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
			if err != nil || result.Status != domain.RunStatusFailed || result.Result.ErrorCode != test.code || result.Result.ErrorMessage != "diagnostic" {
				t.Fatalf("exit result=%+v err=%v", result, err)
			}
		})
	}
}

func TestExecutePreservesTimeoutFailure(t *testing.T) {
	executor := testExecutor(t, "", 0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	// A shell sleep makes cancellation deterministic without relying on agent-compose.
	executor.cfg.Binary = executor.cfg.Binary + "-sleep"
	if err := os.WriteFile(executor.cfg.Binary, []byte("#!/bin/sh\nsleep 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	result, err := executor.Execute(ctx, domain.ExecutionRequest{Run: domain.Run{ID: "run-timeout"}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
	if err == nil || result.Status != domain.RunStatusFailed {
		t.Fatalf("timeout result=%+v err=%v", result, err)
	}
}

func TestExecuteUsesGoContextAsTimeoutAuthority(t *testing.T) {
	runtime := `{"status":"completed","exit_code":0,"result_json":` + strconv.Quote(providerResultJSON("pi", "provider_message", validEventOutput)) + `}`
	for _, test := range []struct {
		name    string
		want    string
		request time.Duration
	}{
		{name: "request timeout", want: "0", request: 2 * time.Minute},
		{name: "configured fallback", want: "0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent-compose")
			script := "#!/bin/sh\nprintf '%s' \"$3\" >&2\nprintf '%s' '" + runtime + "'\n"
			if err := os.WriteFile(path, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			store, err := artifacts.New(filepath.Join(t.TempDir(), "artifacts"))
			if err != nil {
				t.Fatal(err)
			}
			executor := New(Config{Binary: path, Timeout: time.Second}, store)
			result, err := executor.Execute(context.Background(), domain.ExecutionRequest{Run: domain.Run{ID: "run-timeout-" + test.name}, Timeout: test.request, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}})
			if err != nil || result.Status != domain.RunStatusSucceeded {
				t.Fatalf("execution=%+v err=%v", result, err)
			}
			for _, artifact := range result.Result.Artifacts {
				if artifact.Name != "agent-compose-stderr.log" {
					continue
				}
				file, _, openErr := store.Open(context.Background(), "run-timeout-"+test.name, artifact)
				if openErr != nil {
					t.Fatal(openErr)
				}
				data, readErr := io.ReadAll(file)
				_ = file.Close()
				if readErr != nil {
					t.Fatal(readErr)
				}
				if string(data) != test.want {
					t.Fatalf("--timeout=%q want %q", data, test.want)
				}
				return
			}
			t.Fatal("timeout argument was not captured")
		})
	}
}

func TestAgentComposeSignalHelper(t *testing.T) {
	if os.Getenv("SAS_AGENT_COMPOSE_SIGNAL_HELPER") != "1" {
		return
	}
	readyPath := os.Getenv("SAS_AGENT_COMPOSE_READY")
	interruptedPath := os.Getenv("SAS_AGENT_COMPOSE_INTERRUPTED")
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	if err := os.WriteFile(readyPath, []byte("ready"), 0600); err != nil {
		os.Exit(2)
	}
	<-signals
	if err := os.WriteFile(interruptedPath, []byte("interrupted"), 0600); err != nil {
		os.Exit(3)
	}
	if output := os.Getenv("SAS_AGENT_COMPOSE_OUTPUT"); output != "" {
		if _, err := os.Stdout.WriteString(output); err != nil {
			os.Exit(4)
		}
		if os.Getenv("SAS_AGENT_COMPOSE_CLEAN_EXIT") == "1" {
			os.Exit(0)
		}
		os.Exit(1)
	}
	select {}
}

func TestExecuteCancellationSendsInterruptBeforeWaitDelay(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Interrupt process signaling is unsupported on Windows")
	}
	result, err, interrupted := executeSignalHelper(t, false, false)
	if !errors.Is(err, context.Canceled) || result.Status != domain.RunStatusFailed || interrupted != "interrupted" {
		t.Fatalf("cancel result=%+v err=%v interrupted=%q", result, err, interrupted)
	}
}

func TestExecuteCancellationWinsOverCleanChildExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Interrupt process signaling is unsupported on Windows")
	}
	raw := `{"status":"completed","id":"daemon-clean-exit","sandbox_id":"sandbox-clean-exit","exit_code":0,"error":"","output":"transcript","result_json":` + strconv.Quote(providerResultJSON("pi", "provider_message", validEventOutput)) + `}`
	t.Setenv("SAS_AGENT_COMPOSE_OUTPUT", raw)
	t.Setenv("SAS_AGENT_COMPOSE_CLEAN_EXIT", "1")
	result, err, interrupted := executeSignalHelper(t, false, false)
	if !errors.Is(err, context.Canceled) || result.Status != domain.RunStatusFailed || interrupted != "interrupted" {
		t.Fatalf("clean exit after cancel result=%+v err=%v interrupted=%q", result, err, interrupted)
	}
	if result.Result.Provenance == nil || result.Result.Provenance.DaemonRunID != "daemon-clean-exit" || result.Result.Provenance.SandboxID != "sandbox-clean-exit" {
		t.Fatalf("clean exit after cancel provenance=%+v", result.Result.Provenance)
	}
}

func TestExecuteTimeoutSendsInterruptBeforeWaitDelay(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Interrupt process signaling is unsupported on Windows")
	}
	result, err, interrupted := executeSignalHelper(t, true, false)
	if !errors.Is(err, context.DeadlineExceeded) || result.Status != domain.RunStatusFailed || interrupted != "interrupted" {
		t.Fatalf("timeout result=%+v err=%v interrupted=%q", result, err, interrupted)
	}
}

func TestExecuteRequestTimeoutSendsInterruptBeforeWaitDelay(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Interrupt process signaling is unsupported on Windows")
	}
	result, err, interrupted := executeSignalHelper(t, false, true)
	if !errors.Is(err, context.DeadlineExceeded) || result.Status != domain.RunStatusFailed || interrupted != "interrupted" {
		t.Fatalf("request timeout result=%+v err=%v interrupted=%q", result, err, interrupted)
	}
}

func executeSignalHelper(t *testing.T, timeout, requestTimeout bool) (domain.ExecutionResult, error, string) {
	t.Helper()
	dir := t.TempDir()
	readyPath := filepath.Join(dir, "ready")
	interruptedPath := filepath.Join(dir, "interrupted")
	helperPath := filepath.Join(dir, "agent-compose")
	script := "#!/bin/sh\nexec " + shellQuoteTestPath(os.Args[0]) + " -test.run=^TestAgentComposeSignalHelper$\n"
	if err := os.WriteFile(helperPath, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	store, err := artifacts.New(filepath.Join(dir, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	executor := New(Config{Binary: helperPath, Timeout: 10 * time.Second}, store)
	var ctx context.Context
	var cancel context.CancelFunc
	if timeout {
		ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()
	t.Setenv("SAS_AGENT_COMPOSE_SIGNAL_HELPER", "1")
	t.Setenv("SAS_AGENT_COMPOSE_READY", readyPath)
	t.Setenv("SAS_AGENT_COMPOSE_INTERRUPTED", interruptedPath)
	request := domain.ExecutionRequest{Run: domain.Run{ID: "run-signal"}, Agent: domain.AgentDefinition{ID: "event-triage", ExecutorAgent: "event-triage"}}
	if requestTimeout {
		request.Timeout = 2 * time.Second
	}
	type execution struct {
		result domain.ExecutionResult
		err    error
	}
	done := make(chan execution, 1)
	go func() {
		result, err := executor.Execute(ctx, request)
		done <- execution{result: result, err: err}
	}()
	waitForSignalMarker(t, readyPath)
	if !timeout && !requestTimeout {
		cancel()
	}
	var got execution
	select {
	case got = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("executor did not stop after graceful cancellation grace")
	}
	waitForSignalMarker(t, interruptedPath)
	return got.result, got.err, "interrupted"
}

func waitForSignalMarker(t *testing.T, path string) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("marker %q was not written", path)
		}
	}
}

func shellQuoteTestPath(path string) string {
	return "'" + strings.ReplaceAll(path, "'", "'\\''") + "'"
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
	return New(Config{Binary: path, Timeout: 10 * time.Second}, store)
}
