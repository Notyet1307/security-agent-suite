package doctor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const composeFixture = `name: test
agents:
  demo:
    provider: pi
    model: ${SAS_AGENT_MODEL}
    image: ${AGENT_COMPOSE_GUEST_IMAGE}
    driver:
      docker: {}
`

func testConfig(executor string) Config {
	return Config{
		APIBaseURL:       "http://api.test",
		APIKey:           "secret-api-key",
		TenantID:         "tenant-a",
		Executor:         executor,
		AgentComposeBin:  "agent-compose",
		AgentComposeFile: "agent-compose.yml",
		DockerBin:        "docker",
		GuestImage:       "guest:v1",
		Models: map[string]string{
			"SAS_AGENT_MODEL":        "provider/model",
			"SAS_REPORT_MODEL":       "provider/report",
			"SAS_STRONG_AGENT_MODEL": "provider/strong",
		},
		Providers: map[string]string{"SAS_PROVIDER": "pi"},
		Timeout:   time.Second,
	}
}

type fakeHTTP struct {
	readiness int
	err       error
	calls     []string
	nilBody   bool
}

func (f *fakeHTTP) Do(req *http.Request) (*http.Response, error) {
	f.calls = append(f.calls, req.URL.Path)
	if f.err != nil {
		return nil, f.err
	}
	status := http.StatusOK
	if req.URL.Path == "/readyz" && f.readiness != 0 {
		status = f.readiness
	}
	response := &http.Response{StatusCode: status, Header: make(http.Header), Request: req}
	if !f.nilBody {
		response.Body = io.NopCloser(strings.NewReader(`{"status":"ok"}`))
	}
	return response, nil
}

func fakeDependencies(httpClient HTTPDoer, compose string) Dependencies {
	return Dependencies{
		HTTPClient: httpClient,
		LookPath: func(name string) (string, error) {
			return "/fake/" + name, nil
		},
		RunCommand: func(context.Context, string, ...string) error { return nil },
		ReadFile:   func(string) ([]byte, error) { return []byte(compose), nil },
	}
}

func checkByName(report Report, name string) Check {
	for _, check := range report.Checks {
		if check.Name == name {
			return check
		}
	}
	return Check{Name: name, Status: StatusUnknown}
}

func TestRunSuccessfulAgentComposeChecks(t *testing.T) {
	report := RunWithDependencies(context.Background(), testConfig("agentcompose-cli"), fakeDependencies(&fakeHTTP{}, composeFixture))
	if report.Overall != OverallPassed || report.ExitCode() != 0 {
		t.Fatalf("report=%+v", report)
	}
	for _, name := range []string{"configuration", "api_health", "api_readiness", "compose_file", "agent_compose_binary", "agent_compose_version", "model_settings", "guest_image", "provider_settings", "docker"} {
		if check := checkByName(report, name); check.Status != StatusPassed {
			t.Fatalf("%s=%+v", name, check)
		}
	}
}

func TestRunSkipsOptionalAgentComposeInMockMode(t *testing.T) {
	client := &fakeHTTP{}
	called := false
	deps := fakeDependencies(client, composeFixture)
	deps.LookPath = func(string) (string, error) { called = true; return "", errors.New("must not run") }
	deps.RunCommand = func(context.Context, string, ...string) error { called = true; return errors.New("must not run") }
	deps.ReadFile = func(string) ([]byte, error) { called = true; return nil, errors.New("must not read") }
	cfg := testConfig("mock")
	report := RunWithDependencies(context.Background(), cfg, deps)
	check := checkByName(report, "agent_compose_binary")
	if report.Overall != OverallPassed || check.Status != StatusSkipped || check.Required || called {
		t.Fatalf("report=%+v called=%v", report, called)
	}
}

func TestRunReportsFailedAPIReadiness(t *testing.T) {
	client := &fakeHTTP{readiness: http.StatusServiceUnavailable}
	report := RunWithDependencies(context.Background(), testConfig("mock"), fakeDependencies(client, composeFixture))
	check := checkByName(report, "api_readiness")
	if report.Overall != OverallFailed || report.ExitCode() == 0 || check.Status != StatusFailed {
		t.Fatalf("report=%+v", report)
	}
	if strings.Join(client.calls, ",") != "/healthz,/readyz" {
		t.Fatalf("calls=%v", client.calls)
	}
}

func TestRunRejectsUnsafeConfigurationWithoutProbes(t *testing.T) {
	client := &fakeHTTP{}
	called := false
	deps := fakeDependencies(client, composeFixture)
	deps.LookPath = func(string) (string, error) { called = true; return "", nil }
	deps.RunCommand = func(context.Context, string, ...string) error { called = true; return nil }
	deps.ReadFile = func(string) ([]byte, error) { called = true; return []byte(composeFixture), nil }
	cfg := testConfig("agentcompose-cli")
	cfg.AgentComposeBin = "agent-compose;touch /tmp/doctor"
	cfg.APIBaseURL = "file:///tmp/private"
	report := RunWithDependencies(context.Background(), cfg, deps)
	if report.ExitCode() == 0 || checkByName(report, "configuration").Status != StatusFailed || called {
		t.Fatalf("report=%+v called=%v", report, called)
	}
}

func TestWorkspaceProviderDoesNotSatisfyAgentProvider(t *testing.T) {
	compose := `name: test
agents:
  demo:
    model: ${SAS_AGENT_MODEL}
workspaces:
  suite:
    provider: file
`
	cfg := testConfig("agentcompose-cli")
	cfg.Providers = nil
	report := RunWithDependencies(context.Background(), cfg, fakeDependencies(&fakeHTTP{}, compose))
	if checkByName(report, "provider_settings").Status != StatusFailed {
		t.Fatalf("provider check=%+v report=%+v", checkByName(report, "provider_settings"), report)
	}
}

func TestComposePlaceholdersNeedEnvironmentValues(t *testing.T) {
	cfg := testConfig("agentcompose-cli")
	cfg.Models = map[string]string{}
	cfg.GuestImage = ""
	cfg.Providers = nil
	report := RunWithDependencies(context.Background(), cfg, fakeDependencies(&fakeHTTP{}, composeFixture))
	if checkByName(report, "model_settings").Status != StatusFailed || checkByName(report, "guest_image").Status != StatusFailed {
		t.Fatalf("unresolved placeholders unexpectedly passed: %+v", report)
	}
	if checkByName(report, "provider_settings").Status != StatusPassed {
		t.Fatalf("literal agent provider unexpectedly failed: %+v", checkByName(report, "provider_settings"))
	}

	cfg.Models = map[string]string{
		"SAS_AGENT_MODEL":        "provider/model",
		"SAS_REPORT_MODEL":       "provider/report",
		"SAS_STRONG_AGENT_MODEL": "provider/strong",
	}
	cfg.GuestImage = "guest:v1"
	report = RunWithDependencies(context.Background(), cfg, fakeDependencies(&fakeHTTP{}, composeFixture))
	if checkByName(report, "model_settings").Status != StatusPassed || checkByName(report, "guest_image").Status != StatusPassed {
		t.Fatalf("resolved placeholders failed: %+v", report)
	}
}

func TestNilHTTPBodyAndJSONDoNotExposeSecrets(t *testing.T) {
	client := &fakeHTTP{nilBody: true}
	cfg := testConfig("mock")
	report := RunWithDependencies(context.Background(), cfg, fakeDependencies(client, composeFixture))
	if checkByName(report, "api_health").Status != StatusPassed || checkByName(report, "api_readiness").Status != StatusPassed {
		t.Fatalf("report=%+v", report)
	}
	var output strings.Builder
	if err := report.WriteJSON(&output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), cfg.APIKey) || strings.Contains(output.String(), cfg.APIBaseURL) {
		t.Fatalf("unsafe report output: %s", output.String())
	}
	if !strings.Contains(output.String(), `"checks"`) || !strings.Contains(output.String(), `"overall"`) {
		t.Fatalf("not structured JSON: %s", output.String())
	}
}
