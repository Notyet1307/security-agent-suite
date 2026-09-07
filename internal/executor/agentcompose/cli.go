package agentcompose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/artifacts"
	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

const (
	maxCapturedOutput     = 8 << 20
	outputTruncatedCode   = "agent_compose_output_truncated"
	outputTruncatedMarker = "[agent-compose output truncated]"
	exitCodeUnavailable   = 3

	// agent-compose handles SIGINT with signal.NotifyContext and asks its daemon
	// to stop the observed run. Its deferred StopRun uses an unbounded background
	// context, so WaitDelay supplies a conservative local five-second bound; the
	// asserted runtime is Linux/arm64.
	agentComposeCancelGrace = 5 * time.Second
)

type Config struct {
	Binary        string
	ComposeFile   string
	Host          string
	Project       string
	Timeout       time.Duration
	RemoveSandbox bool
}

// AgentComposeRunEnvelope is the controlled v2609.1.0 CLI response. Output is
// transcript only; ResultJSON is the provider result container.
type AgentComposeRunEnvelope struct {
	ID             string            `json:"id"`
	ShortID        string            `json:"short_id"`
	ProjectID      string            `json:"project_id"`
	ProjectName    string            `json:"project_name"`
	AgentName      string            `json:"agent_name"`
	Source         string            `json:"source"`
	Status         string            `json:"status"`
	SandboxID      string            `json:"sandbox_id"`
	SandboxShortID string            `json:"sandbox_short_id"`
	ExitCode       int32             `json:"exit_code"`
	Error          string            `json:"error"`
	StartedAt      string            `json:"started_at"`
	CompletedAt    string            `json:"completed_at"`
	DurationMs     int64             `json:"duration_ms"`
	Prompt         string            `json:"prompt"`
	Output         string            `json:"output"`
	ResultJSON     string            `json:"result_json"`
	LogsPath       string            `json:"logs_path"`
	ArtifactsDir   string            `json:"artifacts_dir"`
	CleanupError   string            `json:"cleanup_error"`
	Driver         string            `json:"driver"`
	ImageRef       string            `json:"image_ref"`
	Warnings       []string          `json:"warnings"`
	Labels         map[string]string `json:"labels"`
	LogsCommand    string            `json:"logs_command"`
	JupyterURL     string            `json:"jupyter_url"`
	JupyterPath    string            `json:"jupyter_path"`
}

func (e *AgentComposeRunEnvelope) UnmarshalJSON(data []byte) error {
	type wire struct {
		ID             string            `json:"id"`
		ShortID        string            `json:"short_id"`
		ProjectID      string            `json:"project_id"`
		ProjectName    string            `json:"project_name"`
		AgentName      string            `json:"agent_name"`
		Source         string            `json:"source"`
		Status         string            `json:"status"`
		SandboxID      string            `json:"sandbox_id"`
		SandboxShortID string            `json:"sandbox_short_id"`
		ExitCode       int32             `json:"exit_code"`
		Error          string            `json:"error"`
		StartedAt      string            `json:"started_at"`
		CompletedAt    string            `json:"completed_at"`
		DurationMs     int64             `json:"duration_ms"`
		Prompt         string            `json:"prompt"`
		Output         json.RawMessage   `json:"output"`
		ResultJSON     json.RawMessage   `json:"result_json"`
		LogsPath       string            `json:"logs_path"`
		ArtifactsDir   string            `json:"artifacts_dir"`
		CleanupError   string            `json:"cleanup_error"`
		Driver         string            `json:"driver"`
		ImageRef       string            `json:"image_ref"`
		Warnings       []string          `json:"warnings"`
		Labels         map[string]string `json:"labels"`
		LogsCommand    string            `json:"logs_command"`
		JupyterURL     string            `json:"jupyter_url"`
		JupyterPath    string            `json:"jupyter_path"`
	}
	var value wire
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*e = AgentComposeRunEnvelope{ID: value.ID, ShortID: value.ShortID, ProjectID: value.ProjectID, ProjectName: value.ProjectName, AgentName: value.AgentName, Source: value.Source, Status: value.Status, SandboxID: value.SandboxID, SandboxShortID: value.SandboxShortID, ExitCode: value.ExitCode, Error: value.Error, StartedAt: value.StartedAt, CompletedAt: value.CompletedAt, DurationMs: value.DurationMs, Prompt: value.Prompt, Output: runtimeFieldText(value.Output), ResultJSON: runtimeFieldText(value.ResultJSON), LogsPath: value.LogsPath, ArtifactsDir: value.ArtifactsDir, CleanupError: value.CleanupError, Driver: value.Driver, ImageRef: value.ImageRef, Warnings: value.Warnings, Labels: value.Labels, LogsCommand: value.LogsCommand, JupyterURL: value.JupyterURL, JupyterPath: value.JupyterPath}
	return nil
}

func runtimeFieldText(raw json.RawMessage) string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	return string(raw)
}

type AgentComposeRuntimeResult struct {
	Provider        string `json:"provider"`
	ThreadID        string `json:"threadId"`
	StopReason      string `json:"stopReason"`
	FinalText       string `json:"finalText"`
	FinalTextSource string `json:"finalTextSource"`
	Transcript      string `json:"transcript"`
	Stderr          string `json:"stderr"`
}

func ParseRuntimeEnvelope(raw []byte) (AgentComposeRunEnvelope, AgentComposeRuntimeResult, error) {
	envelope, decodeErr := decodeRuntimeEnvelope(raw)
	if decodeErr != nil {
		return envelope, AgentComposeRuntimeResult{}, decodeErr
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return envelope, AgentComposeRuntimeResult{}, fmt.Errorf("runtime envelope is not an object: %w", err)
	}
	for _, field := range []string{"status", "exit_code", "result_json"} {
		if _, ok := fields[field]; !ok {
			return envelope, AgentComposeRuntimeResult{}, fmt.Errorf("runtime envelope %s is required", field)
		}
	}
	if rawExitCode := bytes.TrimSpace(fields["exit_code"]); len(rawExitCode) == 0 || bytes.Equal(rawExitCode, []byte("null")) {
		return envelope, AgentComposeRuntimeResult{}, errors.New("runtime envelope exit_code must be an integer")
	}
	var exitCode int32
	if err := json.Unmarshal(fields["exit_code"], &exitCode); err != nil {
		return envelope, AgentComposeRuntimeResult{}, errors.New("runtime envelope exit_code must be an integer")
	}
	if strings.TrimSpace(envelope.Status) == "" {
		return envelope, AgentComposeRuntimeResult{}, errors.New("runtime envelope status is required")
	}
	resultBytes := bytes.TrimSpace([]byte(envelope.ResultJSON))
	if len(resultBytes) == 0 || bytes.Equal(resultBytes, []byte("null")) {
		return envelope, AgentComposeRuntimeResult{}, errors.New("runtime envelope result_json is required")
	}
	var resultFields map[string]json.RawMessage
	if err := json.Unmarshal(resultBytes, &resultFields); err != nil || resultFields == nil {
		return envelope, AgentComposeRuntimeResult{}, errors.New("runtime result_json must be an object")
	}
	if _, ok := resultFields["finalText"]; !ok {
		return envelope, AgentComposeRuntimeResult{}, errors.New("runtime result_json.finalText is required")
	}
	var result AgentComposeRuntimeResult
	resultDecoder := json.NewDecoder(bytes.NewReader(resultBytes))
	if err := resultDecoder.Decode(&result); err != nil {
		return envelope, AgentComposeRuntimeResult{}, fmt.Errorf("runtime result_json is invalid: %w", err)
	}
	if err := ensureEOF(resultDecoder); err != nil {
		return envelope, AgentComposeRuntimeResult{}, errors.New("runtime result_json contains trailing text")
	}
	if strings.TrimSpace(result.FinalText) == "" {
		return envelope, AgentComposeRuntimeResult{}, errors.New("runtime result_json.finalText is required")
	}
	return envelope, result, nil
}
func decodeRuntimeEnvelope(raw []byte) (AgentComposeRunEnvelope, error) {
	var envelope AgentComposeRunEnvelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&envelope); err != nil {
		return envelope, fmt.Errorf("runtime envelope is not valid JSON: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return envelope, errors.New("runtime envelope contains trailing text")
	}
	return envelope, nil
}
func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing input")
	}
	return nil
}

type Executor struct {
	cfg       Config
	artifacts *artifacts.Store
}

func New(cfg Config, artifactStore *artifacts.Store) *Executor {
	return &Executor{cfg: cfg, artifacts: artifactStore}
}

func (e *Executor) Name() string { return "agentcompose-cli" }

func (e *Executor) Execute(ctx context.Context, request domain.ExecutionRequest) (domain.ExecutionResult, error) {
	if strings.TrimSpace(e.cfg.Binary) == "" {
		return domain.ExecutionResult{}, fmt.Errorf("agent-compose binary is not configured")
	}
	if e.artifacts == nil {
		return domain.ExecutionResult{}, errors.New("artifact store is not configured")
	}
	timeout := request.Timeout
	if timeout <= 0 {
		timeout = e.cfg.Timeout
	}
	execCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	// The Go context is the authoritative deadline. A nonzero CLI RPC timeout
	// can race that deadline and prevent agent-compose's cancellation defer from
	// requesting RunService.StopRun.
	args := []string{"--json", "--timeout", "0"}
	if e.cfg.Host != "" {
		args = append(args, "--host", e.cfg.Host)
	}
	if e.cfg.ComposeFile != "" {
		args = append(args, "-f", e.cfg.ComposeFile)
	} else if e.cfg.Project != "" {
		args = append(args, "--project-name", e.cfg.Project)
	}
	args = append(args, "run", request.Agent.ExecutorAgent, "--prompt", request.Prompt)
	if e.cfg.RemoveSandbox {
		args = append(args, "--rm")
	}

	cmd := exec.CommandContext(execCtx, e.cfg.Binary, args...)
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		if err := cmd.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		return nil
	}
	cmd.WaitDelay = agentComposeCancelGrace
	var stdout, stderr cappedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	finished := time.Now()
	result := domain.RunResult{Executor: e.Name(), Summary: "agent-compose run completed"}
	envelope, runtimeResult, parseErr := ParseRuntimeEnvelope(stdout.Bytes())
	envelopeParseErr := parseErr
	if parseErr != nil {
		envelope, envelopeParseErr = decodeRuntimeEnvelope(stdout.Bytes())
	}
	truncated := stdout.truncated || stderr.truncated
	trustedProviderOutput := parseErr == nil && knownProvider(runtimeResult.Provider) && runtimeResult.FinalTextSource == "provider_message"
	if !truncated && envelopeParseErr == nil && (parseErr == nil || runtimeFailureEnvelope(envelope)) {
		result.Provenance = executionProvenance(envelope, runtimeResult)
	}
	artifactsOut := make([]domain.ArtifactRef, 0, 3)
	if stdout.Len() > 0 {
		// Keep the exact daemon response in a controlled artifact for review.
		envelopeArtifact, putErr := e.artifacts.Put(context.WithoutCancel(ctx), request.Run.ID, "agent-compose-runtime-envelope.json", "application/json", stdout.Bytes(), finished)
		if putErr != nil {
			return domain.ExecutionResult{}, putErr
		}
		artifactsOut = append(artifactsOut, envelopeArtifact)
		if !truncated && envelopeParseErr == nil {
			transcript := redactPrompt(runtimeTranscript(envelope.Output), request.Prompt)
			if len(transcript) > 0 {
				artifact, putErr := e.artifacts.Put(context.WithoutCancel(ctx), request.Run.ID, "agent-compose-stdout.json", "text/plain", transcript, finished)
				if putErr != nil {
					return domain.ExecutionResult{}, putErr
				}
				artifactsOut = append(artifactsOut, artifact)
			}
		}
	}
	if stderr.Len() > 0 {
		artifact, putErr := e.artifacts.Put(context.WithoutCancel(ctx), request.Run.ID, "agent-compose-stderr.log", "text/plain", redactPrompt(stderr.Bytes(), request.Prompt), finished)
		if putErr != nil {
			return domain.ExecutionResult{}, putErr
		}
		artifactsOut = append(artifactsOut, artifact)
	}
	if !truncated && trustedProviderOutput {
		result.RawOutput = json.RawMessage(runtimeResult.FinalText)
		// Controlled provider result: exact finalText is also the business RawOutput.
		finalArtifact, putErr := e.artifacts.Put(context.WithoutCancel(ctx), request.Run.ID, "agent-compose-final-output.json", "application/json", redactPrompt([]byte(runtimeResult.FinalText), request.Prompt), finished)
		if putErr != nil {
			return domain.ExecutionResult{}, putErr
		}
		artifactsOut = append(artifactsOut, finalArtifact)
	}
	result.Artifacts = artifactsOut
	if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
		return domain.ExecutionResult{Status: domain.RunStatusFailed, Result: result}, execCtx.Err()
	}
	if errors.Is(execCtx.Err(), context.Canceled) {
		return domain.ExecutionResult{Status: domain.RunStatusFailed, Result: result}, execCtx.Err()
	}
	if err != nil && !truncated && envelopeParseErr == nil && runtimeStatus(envelope) == domain.RunStatusCancelled {
		result.ErrorCode = "agent_compose_cancelled"
		result.ErrorMessage = domain.BoundedText(envelope.Error, domain.MaxErrorMessageBytes)
		if result.ErrorMessage == "" {
			result.ErrorMessage = "agent-compose runtime canceled"
		}
		return domain.ExecutionResult{Status: domain.RunStatusCancelled, Result: result}, nil
	}
	if truncated {
		result.ErrorCode = outputTruncatedCode
		result.ErrorMessage = domain.BoundedText("agent-compose output exceeded the capture limit", domain.MaxErrorMessageBytes)
		result.Limitations = []string{outputTruncatedMarker}
		return domain.ExecutionResult{Status: domain.RunStatusFailed, Result: result}, nil
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ErrorCode = "agent_compose_exit"
			if exitErr.ExitCode() == exitCodeUnavailable {
				result.ErrorCode = "agent_compose_unavailable"
			}
			result.ErrorMessage = domain.BoundedText(strings.TrimSpace(stderr.String()), domain.MaxErrorMessageBytes)
			if result.ErrorMessage == "" {
				result.ErrorMessage = domain.BoundedText(exitErr.Error(), domain.MaxErrorMessageBytes)
			}
			return domain.ExecutionResult{Status: domain.RunStatusFailed, Result: result}, nil
		}
		return domain.ExecutionResult{}, fmt.Errorf("start agent-compose: %w", err)
	}
	if parseErr != nil {
		if envelopeParseErr == nil {
			runtime := runtimeStatus(envelope)
			if runtime == domain.RunStatusFailed {
				result.ErrorCode = "agent_compose_runtime"
				result.ErrorMessage = domain.BoundedText(envelope.Error, domain.MaxErrorMessageBytes)
				if result.ErrorMessage == "" {
					result.ErrorMessage = "agent-compose runtime failed"
				}
				return domain.ExecutionResult{Status: domain.RunStatusFailed, Result: result}, nil
			}
			if runtime == domain.RunStatusPartial {
				return domain.ExecutionResult{Status: domain.RunStatusPartial, Result: result}, nil
			}
			if runtime == domain.RunStatusCancelled {
				result.ErrorCode = "agent_compose_cancelled"
				result.ErrorMessage = domain.BoundedText(envelope.Error, domain.MaxErrorMessageBytes)
				if result.ErrorMessage == "" {
					result.ErrorMessage = "agent-compose runtime canceled"
				}
				return domain.ExecutionResult{Status: domain.RunStatusCancelled, Result: result}, nil
			}
		}
		// Let the existing validation Gate classify malformed/missing provider output.
		return domain.ExecutionResult{Status: domain.RunStatusSucceeded, Result: result}, nil
	}
	status := runtimeStatus(envelope)
	if status == domain.RunStatusFailed {
		result.ErrorCode = "agent_compose_runtime"
		result.ErrorMessage = domain.BoundedText(envelope.Error, domain.MaxErrorMessageBytes)
		if result.ErrorMessage == "" {
			result.ErrorMessage = "agent-compose runtime failed"
		}
	}
	if status == domain.RunStatusCancelled {
		result.ErrorCode = "agent_compose_cancelled"
		result.ErrorMessage = domain.BoundedText(envelope.Error, domain.MaxErrorMessageBytes)
		if result.ErrorMessage == "" {
			result.ErrorMessage = "agent-compose runtime canceled"
		}
	}
	return domain.ExecutionResult{Status: status, Result: result}, nil

}

func knownProvider(provider string) bool {
	switch provider {
	case "codex", "claude", "gemini", "opencode", "pi", "dsh":
		return true
	default:
		return false
	}
}

func runtimeStatus(envelope AgentComposeRunEnvelope) domain.RunStatus {
	status := strings.ToLower(strings.TrimSpace(envelope.Status))
	// A canceled upstream run can retain the cell's nonzero exit code and the
	// cancellation cause in error; its terminal status is authoritative.
	if status == "canceled" || status == "cancelled" {
		return domain.RunStatusCancelled
	}
	if envelope.ExitCode != 0 || strings.TrimSpace(envelope.Error) != "" {
		return domain.RunStatusFailed
	}
	switch status {
	case "completed", "succeeded", "success":
		return domain.RunStatusSucceeded
	case "partial":
		return domain.RunStatusPartial
	default:
		return domain.RunStatusFailed
	}
}

func runtimeFailureEnvelope(envelope AgentComposeRunEnvelope) bool {
	status := strings.ToLower(strings.TrimSpace(envelope.Status))
	if status == "partial" || status == "canceled" || status == "cancelled" {
		return true
	}
	return status == "failed" || status == "failure" || status == "error" || envelope.ExitCode != 0 || strings.TrimSpace(envelope.Error) != ""
}

func executionProvenance(envelope AgentComposeRunEnvelope, runtime AgentComposeRuntimeResult) *domain.ExecutionProvenance {
	if strings.TrimSpace(envelope.Status) == "" {
		return nil
	}
	labels := make(map[string]string, len(envelope.Labels))
	for key, value := range envelope.Labels {
		labels[key] = value
	}
	provenance := &domain.ExecutionProvenance{
		DaemonRunID:      envelope.ID,
		DaemonRunShortID: envelope.ShortID,
		ProjectID:        envelope.ProjectID,
		ProjectName:      envelope.ProjectName,
		AgentName:        envelope.AgentName,
		Source:           envelope.Source,
		SandboxID:        envelope.SandboxID,
		SandboxShortID:   envelope.SandboxShortID,
		Status:           envelope.Status,
		StopReason:       runtime.StopReason,
		FinalTextSource:  runtime.FinalTextSource,
		Driver:           envelope.Driver,
		ImageRef:         envelope.ImageRef,
		StartedAt:        envelope.StartedAt,
		CompletedAt:      envelope.CompletedAt,
		DurationMs:       envelope.DurationMs,
		Warnings:         append([]string(nil), envelope.Warnings...),
		Labels:           labels,
		CleanupError:     envelope.CleanupError,
		Provider:         runtime.Provider,
		ThreadID:         runtime.ThreadID,
	}
	return provenance
}

func redactPrompt(data []byte, prompt string) []byte {
	if prompt == "" {
		return append([]byte(nil), data...)
	}
	redacted := bytes.ReplaceAll(data, []byte(prompt), []byte("<redacted-task-envelope>"))
	if encoded, err := json.Marshal(prompt); err == nil && len(encoded) > 1 {
		redacted = bytes.ReplaceAll(redacted, encoded[1:len(encoded)-1], []byte("<redacted-task-envelope>"))
	}
	return redacted
}
func runtimeTranscript(output string) []byte {
	if strings.TrimSpace(output) == "" || strings.TrimSpace(output) == "null" {
		return nil
	}
	return []byte(output)
}

type cappedBuffer struct {
	buf       bytes.Buffer
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	original := len(p)
	remaining := maxCapturedOutput - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return original, nil
	}
	if len(p) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	_, _ = b.buf.Write(p)
	return original, nil
}

func (b *cappedBuffer) Bytes() []byte  { return b.buf.Bytes() }
func (b *cappedBuffer) String() string { return b.buf.String() }
func (b *cappedBuffer) Len() int       { return b.buf.Len() }
