package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/Notyet1307/security-agent-suite/internal/doctor"
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
