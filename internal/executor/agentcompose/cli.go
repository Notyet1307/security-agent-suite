package agentcompose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
)

type Config struct {
	Binary        string
	ComposeFile   string
	Host          string
	Project       string
	Timeout       time.Duration
	RemoveSandbox bool
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
	args := []string{"--json", "--timeout", e.cfg.Timeout.String()}
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

	cmd := exec.CommandContext(ctx, e.cfg.Binary, args...)
	var stdout, stderr cappedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	started := time.Now()
	err := cmd.Run()
	finished := time.Now()

	artifactsOut := make([]domain.ArtifactRef, 0, 2)
	if stdout.Len() > 0 {
		artifact, putErr := e.artifacts.Put(context.WithoutCancel(ctx), request.Run.ID, "agent-compose-stdout.json", "application/json", stdout.Bytes(), finished)
		if putErr != nil {
			return domain.ExecutionResult{}, putErr
		}
		artifactsOut = append(artifactsOut, artifact)
	}
	if stderr.Len() > 0 {
		artifact, putErr := e.artifacts.Put(context.WithoutCancel(ctx), request.Run.ID, "agent-compose-stderr.log", "text/plain", stderr.Bytes(), finished)
		if putErr != nil {
			return domain.ExecutionResult{}, putErr
		}
		artifactsOut = append(artifactsOut, artifact)
	}

	truncated := stdout.truncated || stderr.truncated
	raw := normalizeRawCapture(stdout.Bytes(), stderr.Bytes(), args, started, finished, stdout.truncated, stderr.truncated)
	result := domain.RunResult{
		Executor:  e.Name(),
		Summary:   extractSummary(stdout.Bytes()),
		Artifacts: artifactsOut,
		RawOutput: raw,
	}
	if result.Summary == "" {
		result.Summary = "agent-compose run completed"
	}
	if err != nil && (errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded)) {
		return domain.ExecutionResult{Status: domain.RunStatusFailed, Result: result}, ctx.Err()
	}
	if truncated {
		result.ErrorCode = outputTruncatedCode
		result.ErrorMessage = "agent-compose output exceeded the capture limit"
		result.Limitations = []string{outputTruncatedMarker}
		return domain.ExecutionResult{Status: domain.RunStatusFailed, Result: result}, nil
	}

	if err == nil {
		return domain.ExecutionResult{Status: domain.RunStatusSucceeded, Result: result}, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ErrorCode = "agent_compose_exit"
		result.ErrorMessage = strings.TrimSpace(stderr.String())
		if result.ErrorMessage == "" {
			result.ErrorMessage = exitErr.Error()
		}
		return domain.ExecutionResult{Status: domain.RunStatusFailed, Result: result}, nil
	}
	return domain.ExecutionResult{}, fmt.Errorf("start agent-compose: %w", err)
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

func extractSummary(stdout []byte) string {
	var payload map[string]any
	if json.Unmarshal(stdout, &payload) != nil {
		return strings.TrimSpace(string(stdout))
	}
	for _, key := range []string{"output", "summary", "message"} {
		if value, ok := payload[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	if result, ok := payload["result"].(map[string]any); ok {
		for _, key := range []string{"output", "summary", "message"} {
			if value, ok := result[key].(string); ok && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		}
	}
	return ""
}

func normalizeRaw(stdout, stderr []byte, args []string, started, finished time.Time) json.RawMessage {
	return normalizeRawCapture(stdout, stderr, args, started, finished, false, false)
}

func normalizeRawCapture(stdout, stderr []byte, args []string, started, finished time.Time, stdoutTruncated, stderrTruncated bool) json.RawMessage {
	truncated := stdoutTruncated || stderrTruncated
	if !truncated && json.Valid(stdout) && len(stdout) > 0 {
		return append(json.RawMessage(nil), stdout...)
	}
	payload := map[string]any{
		"stdout":            string(stdout),
		"stdout_empty":      len(stdout) == 0,
		"stdout_valid_json": json.Valid(stdout),
		"stderr":            string(stderr),
		"arguments":         redactArguments(args),
		"started_at":        started.UTC(),
		"finished_at":       finished.UTC(),
		"truncated":         truncated,
		"stdout_truncated":  stdoutTruncated,
		"stderr_truncated":  stderrTruncated,
	}
	if truncated {
		payload["truncation_marker"] = outputTruncatedMarker
	}
	data, _ := json.Marshal(payload)
	return data
}

func redactArguments(args []string) []string {
	result := append([]string(nil), args...)
	for i := 0; i < len(result); i++ {
		if result[i] == "--prompt" && i+1 < len(result) {
			result[i+1] = "<redacted-task-envelope>"
			i++
		}
	}
	return result
}
