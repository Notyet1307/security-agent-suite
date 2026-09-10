package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Notyet1307/security-agent-suite/internal/doctor"
	"github.com/Notyet1307/security-agent-suite/internal/validation"
)

func TestRunDoctorSuccess(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var gotConfig doctor.Config
	called := false
	runDoctor := func(ctx context.Context, cfg doctor.Config) doctor.Report {
		called = true
		gotConfig = cfg
		if ctx == nil {
			t.Fatal("doctor runner received nil context")
		}
		return doctor.Report{
			Overall: doctor.OverallPassed,
			Checks:  []doctor.Check{{Name: "configuration", Status: doctor.StatusPassed, Required: true}},
		}
	}

	code := run([]string{
		"--base-url", "http://api.test///",
		"--api-key", "test-key",
		"--tenant", "tenant-a",
		"doctor",
	}, &stdout, &stderr, runDoctor)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !called {
		t.Fatal("doctor runner was not called")
	}
	if gotConfig.APIBaseURL != "http://api.test" || gotConfig.APIKey != "test-key" || gotConfig.TenantID != "tenant-a" {
		t.Fatalf("doctor config = %+v", gotConfig)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}

	var report doctor.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("doctor output is not JSON: %v", err)
	}
	if report.Overall != doctor.OverallPassed || len(report.Checks) != 1 || report.Checks[0].Status != doctor.StatusPassed {
		t.Fatalf("doctor output = %+v", report)
	}
}

func TestRunDoctorRequiredFailure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	runDoctor := func(context.Context, doctor.Config) doctor.Report {
		return doctor.Report{
			Overall: doctor.OverallFailed,
			Checks:  []doctor.Check{{Name: "api_readiness", Status: doctor.StatusFailed, Required: true}},
		}
	}

	code := run([]string{"doctor"}, &stdout, &stderr, runDoctor)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if stderr.Len() == 0 {
		t.Fatal("required failure did not report an error")
	}

	var report doctor.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("doctor output is not JSON: %v", err)
	}
	if !report.RequiredFailures() {
		t.Fatalf("doctor output lost required failure: %+v", report)
	}
}

func TestValidateOutput(t *testing.T) {
	valid := readFixtureOutput(t)
	validPath := filepath.Join(t.TempDir(), "output.json")
	if err := os.WriteFile(validPath, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"validate-output", "--agent", "event-triage", "--file", validPath}, &stdout, &stderr, doctor.Run)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("validate-output code=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "Observed a benign contract-smoke event.") {
		t.Fatalf("validation output echoed agent content: %q", stdout.String())
	}
	var acknowledgement struct {
		AgentID string `json:"agent_id"`
		Valid   bool   `json:"valid"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &acknowledgement); err != nil || acknowledgement.AgentID != "event-triage" || !acknowledgement.Valid {
		t.Fatalf("acknowledgement=%+v err=%v", acknowledgement, err)
	}

	for _, test := range []struct {
		name  string
		agent string
		data  string
	}{
		{name: "malformed output", agent: "event-triage", data: `{}`},
		{name: "wrong contract", agent: "event-triage", data: `{"protocol":"security-agent-suite.security-report.v1"}`},
		{name: "unknown agent", agent: "unknown", data: valid},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "output.json")
			if err := os.WriteFile(path, []byte(test.data), 0600); err != nil {
				t.Fatal(err)
			}
			stdout.Reset()
			stderr.Reset()
			if code := run([]string{"validate-output", "--agent", test.agent, "--file", path}, &stdout, &stderr, doctor.Run); code == 0 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func readFixtureOutput(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	fixture, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "internal", "executor", "agentcompose", "testdata", "fixtures", "agent-compose-v2609.1.0-pi-runtime-envelope.json"))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		ResultJSON string `json:"result_json"`
	}
	if err := json.Unmarshal(fixture, &envelope); err != nil {
		t.Fatalf("decode runtime fixture: %v", err)
	}
	var result struct {
		FinalText string `json:"finalText"`
	}
	if err := json.Unmarshal([]byte(envelope.ResultJSON), &result); err != nil {
		t.Fatalf("decode fixture result_json: %v", err)
	}
	if result.FinalText == "" {
		t.Fatal("fixture finalText is empty")
	}
	if _, err := validation.Parse("event-triage", []byte(result.FinalText)); err != nil {
		t.Fatalf("fixture output failed schema validation: %v", err)
	}
	return result.FinalText
}

func TestValidateOutputRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(readFixtureOutput(t)), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "output.json")
	if err := os.Symlink(target, path); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatalf("create symlink: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"validate-output", "--agent", "event-triage", "--file", path}, &stdout, &stderr, doctor.Run)
	if code == 0 || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestValidateOutputRejectsNonRegularFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"validate-output", "--agent", "event-triage", "--file", t.TempDir()}, &stdout, &stderr, doctor.Run)
	if code == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "regular file") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestValidateOutputRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.json")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxValidationOutputBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"validate-output", "--agent", "event-triage", "--file", path}, &stdout, &stderr, doctor.Run)
	if code == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "exceeds") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunCommandExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "no command", want: 2},
		{name: "unknown command", args: []string{"unknown"}, want: 1},
		{name: "doctor arguments", args: []string{"doctor", "extra"}, want: 1},
		{name: "global flag error", args: []string{"--unknown"}, want: 2},
		{name: "command flag error", args: []string{"list", "--unknown"}, want: 1},
		{name: "help", args: []string{"-h"}, want: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			called := false
			code := run(tc.args, &stdout, &stderr, func(context.Context, doctor.Config) doctor.Report {
				called = true
				return doctor.Report{Overall: doctor.OverallPassed}
			})
			if code != tc.want {
				t.Fatalf("exit code = %d, want %d", code, tc.want)
			}
			if called {
				t.Fatal("doctor runner called for non-executing command path")
			}
			if stdout.Len() != 0 {
				t.Fatalf("unexpected stdout: %q", stdout.String())
			}
			if stderr.Len() == 0 {
				t.Fatal("expected command diagnostic on stderr")
			}
		})
	}
}

func TestManualUploadSubmitAndWaitCLI(t *testing.T) {
	raw := []byte("{\"synthetic\":true}\n")
	path := filepath.Join(t.TempDir(), "alert.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("X-Tenant-ID") != "t" || r.Header.Get("X-API-Key") != "key" {
			t.Error("missing authentication")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/runs/run-one/artifacts":
			body, _ := io.ReadAll(r.Body)
			if !bytes.Equal(body, raw) || r.Header.Get("X-Artifact-SHA256") != strings.Repeat("a", 64) || r.URL.Query().Get("name") != "alert.json" {
				t.Error("changed upload bytes or headers")
			}
			w.WriteHeader(201)
			fmt.Fprint(w, `{"id":"art-one"}`)
		case "/v1/runs/run-one/submit":
			body, _ := io.ReadAll(r.Body)
			if string(body) != `{"artifact_id":"art-one"}` {
				t.Errorf("submit body %s", body)
			}
			w.WriteHeader(202)
			fmt.Fprint(w, `{"status":"queued"}`)
		case "/v1/runs/run-one":
			fmt.Fprint(w, `{"status":"preparing"}`)
		case "/v1/runs/unknown":
			fmt.Fprint(w, `{"status":"future-state"}`)
		default:
			t.Error("unexpected request", r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer server.Close()
	for _, args := range [][]string{{"upload", "run-one", "--file", path, "--sha256", strings.Repeat("a", 64)}, {"submit", "run-one", "--artifact-id", "art-one"}, {"wait", "run-one"}} {
		var out, errout bytes.Buffer
		code := run(append([]string{"--base-url", server.URL, "--tenant", "t", "--api-key", "key"}, args...), &out, &errout, nil)
		if code != 0 {
			t.Fatalf("%v failed: %s", args, errout.String())
		}
		if args[0] == "wait" && !strings.Contains(errout.String(), "submit") {
			t.Fatal("missing preparation hint")
		}
	}
	var out, errout bytes.Buffer
	if code := run([]string{"--base-url", server.URL, "--tenant", "t", "--api-key", "key", "wait", "unknown"}, &out, &errout, nil); code == 0 {
		t.Fatal("unknown status accepted")
	}
	if calls != 4 {
		t.Fatalf("automatic extra calls %d", calls)
	}
}
