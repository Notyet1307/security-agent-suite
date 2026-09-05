package doctor

import (
	"context"
	"errors"
	"io"
	"net"
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

const normalizedComposeFixture = `{"name":"test","agents":[{"name":"demo","enabled":true,"provider":"pi","image":"guest:v1","driver":{"name":"docker","docker":{}}}]}`

func testConfig(executor string) Config {
	return Config{
		APIBaseURL: "http://api.test", APIKey: "secret-api-key", TenantID: "tenant-a",
		Executor: executor, AgentComposeBin: "agent-compose", AgentComposeFile: "agent-compose.yml",
		AgentComposeHost: "http://compose.test:7410", OctoBusHost: "http://octobus.test:7420",
		DockerBin: "docker", GuestImage: "guest:v1",
		Models:    map[string]string{"SAS_AGENT_MODEL": "provider/model", "SAS_REPORT_MODEL": "provider/report", "SAS_STRONG_AGENT_MODEL": "provider/strong"},
		Providers: map[string]string{"SAS_PROVIDER": "pi"}, Timeout: time.Second,
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

type httpDoerFunc func(*http.Request) (*http.Response, error)

func (f httpDoerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

type fakeConn struct{}

func (fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (fakeConn) Write(p []byte) (int, error)      { return len(p), nil }
func (fakeConn) Close() error                     { return nil }
func (fakeConn) LocalAddr() net.Addr              { return fakeAddr("local") }
func (fakeConn) RemoteAddr() net.Addr             { return fakeAddr("remote") }
func (fakeConn) SetDeadline(time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr string

func (a fakeAddr) Network() string { return "fake" }
func (a fakeAddr) String() string  { return string(a) }

func fakeDependencies(httpClient HTTPDoer, compose string) Dependencies {
	return Dependencies{
		HTTPClient: httpClient,
		LookPath:   func(name string) (string, error) { return "/fake/" + name, nil },
		RunCommand: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			switch strings.Join(args, " ") {
			case "--json version":
				return []byte(`{"version":"v2609.1.0","os":"test","arch":"test","compiled_drivers":["docker"]}`), nil
			case "--json --file agent-compose.yml config":
				return []byte(normalizedComposeFixture), nil
			default:
				return nil, nil
			}
		},
		ReadFile:             func(string) ([]byte, error) { return []byte(compose), nil },
		DialContext:          func(context.Context, string, string) (net.Conn, error) { return fakeConn{}, nil },
		AgentComposeProtocol: func(context.Context, string, string) error { return nil },
		OctoBusProtocol:      func(context.Context, string) error { return nil },
		ProviderProbe:        func(context.Context, map[string]string) error { return nil },
		DockerInspect:        func(context.Context, string, string) error { return nil },
		ValidateCompose: func(context.Context, string, string) (ComposeValidation, error) {
			return ComposeValidation{Complete: true, ProviderConfigured: true, UsesDocker: true}, nil
		},
		DNSProbe:          func(context.Context, string) error { return nil },
		OctoBusProxyProbe: func(context.Context, string, string) error { return nil },
	}
}

func checkByName(report Report, name string) Check {
	for _, check := range report.Checks {
		if check.Name == name {
			return check
		}
	}
	panic("missing doctor check: " + name)
}

func hasCheck(report Report, name string) bool {
	for _, check := range report.Checks {
		if check.Name == name {
			return true
		}
	}
	return false
}

func TestRunSuccessfulAgentComposeChecks(t *testing.T) {
	report := RunWithDependencies(context.Background(), testConfig("agentcompose-cli"), fakeDependencies(&fakeHTTP{}, composeFixture))
	if report.Overall != OverallPassed || report.ExitCode() != 0 {
		t.Fatalf("report=%+v", report)
	}
	for _, name := range []string{"configuration", "api_health", "api_readiness", "compose_file", "agent_compose_protocol", "octobus_protocol", "provider_connectivity", "docker", "octobus_proxy", "network_dns"} {
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
	deps.RunCommand = func(context.Context, string, ...string) ([]byte, error) {
		called = true
		return nil, errors.New("must not run")
	}
	deps.ReadFile = func(string) ([]byte, error) { called = true; return nil, errors.New("must not read") }
	deps.DialContext = func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, errors.New("must not dial")
	}
	deps.AgentComposeProtocol = func(context.Context, string, string) error { called = true; return errors.New("must not probe") }
	deps.OctoBusProtocol = func(context.Context, string) error { called = true; return errors.New("must not probe") }
	deps.ProviderProbe = func(context.Context, map[string]string) error { called = true; return errors.New("must not probe") }
	deps.DockerInspect = func(context.Context, string, string) error { called = true; return errors.New("must not inspect") }
	deps.ValidateCompose = func(context.Context, string, string) (ComposeValidation, error) {
		called = true
		return ComposeValidation{}, errors.New("must not validate")
	}
	deps.DNSProbe = func(context.Context, string) error { called = true; return errors.New("must not probe") }
	deps.OctoBusProxyProbe = func(context.Context, string, string) error { called = true; return errors.New("must not probe") }
	report := RunWithDependencies(context.Background(), testConfig("mock"), deps)
	for _, name := range []string{"agent_compose_binary", "agent_compose_version", "compose_file", "docker", "model_settings", "guest_image", "provider_settings", "provider_connectivity", "agent_compose_host", "octobus_host"} {
		check := checkByName(report, name)
		if check.Status != StatusSkipped || check.Required {
			t.Fatalf("%s=%+v", name, check)
		}
	}
	for _, name := range []string{"agent_compose_protocol", "octobus_protocol", "octobus_proxy", "network_dns"} {
		if hasCheck(report, name) {
			t.Fatalf("mock report unexpectedly contains %s: %+v", name, report)
		}
	}
	if report.Overall != OverallPassed || report.ExitCode() != 0 || called {
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

func TestAgentComposeHostsAreRequired(t *testing.T) {
	cfg := testConfig("agentcompose-cli")
	cfg.AgentComposeHost, cfg.OctoBusHost = "", ""
	report := RunWithDependencies(context.Background(), cfg, fakeDependencies(&fakeHTTP{}, composeFixture))
	for _, name := range []string{"agent_compose_host", "octobus_host"} {
		if check := checkByName(report, name); !check.Required || check.Status != StatusFailed {
			t.Fatalf("%s=%+v", name, check)
		}
	}
	if report.ExitCode() == 0 {
		t.Fatalf("missing hosts unexpectedly passed: %+v", report)
	}
	cfg.AgentComposeHost = "file:///not-a-daemon"
	cfg.OctoBusHost = "file:///not-octobus"
	called := false
	deps := fakeDependencies(&fakeHTTP{}, composeFixture)
	deps.DialContext = func(context.Context, string, string) (net.Conn, error) { called = true; return nil, nil }
	deps.AgentComposeProtocol = func(context.Context, string, string) error { called = true; return nil }
	deps.OctoBusProtocol = func(context.Context, string) error { called = true; return nil }
	deps.DNSProbe = func(context.Context, string) error { called = true; return nil }
	deps.OctoBusProxyProbe = func(context.Context, string, string) error { called = true; return nil }
	report = RunWithDependencies(context.Background(), cfg, deps)
	for _, name := range []string{"agent_compose_host", "octobus_host"} {
		if check := checkByName(report, name); !check.Required || check.Status != StatusFailed {
			t.Fatalf("%s=%+v", name, check)
		}
	}
	if called {
		t.Fatal("malformed hosts reached a network or protocol probe")
	}
}

func TestMalformedAPIURLBlocksAllProbes(t *testing.T) {
	client := &fakeHTTP{}
	called := false
	deps := fakeDependencies(client, composeFixture)
	deps.LookPath = func(string) (string, error) { called = true; return "", nil }
	deps.RunCommand = func(context.Context, string, ...string) ([]byte, error) { called = true; return nil, nil }
	deps.ReadFile = func(string) ([]byte, error) { called = true; return []byte(composeFixture), nil }
	deps.DialContext = func(context.Context, string, string) (net.Conn, error) { called = true; return fakeConn{}, nil }
	deps.AgentComposeProtocol = func(context.Context, string, string) error { called = true; return nil }
	deps.OctoBusProtocol = func(context.Context, string) error { called = true; return nil }
	deps.ProviderProbe = func(context.Context, map[string]string) error { called = true; return nil }
	deps.DockerInspect = func(context.Context, string, string) error { called = true; return nil }
	deps.ValidateCompose = func(context.Context, string, string) (ComposeValidation, error) {
		called = true
		return ComposeValidation{}, nil
	}
	deps.DNSProbe = func(context.Context, string) error { called = true; return nil }
	deps.OctoBusProxyProbe = func(context.Context, string, string) error { called = true; return nil }
	cfg := testConfig("agentcompose-cli")
	cfg.APIBaseURL = "file:///private/secret"
	report := RunWithDependencies(context.Background(), cfg, deps)
	if report.ExitCode() == 0 || checkByName(report, "configuration").Status != StatusFailed || called || len(client.calls) != 0 {
		t.Fatalf("report=%+v called=%v api_calls=%v", report, called, client.calls)
	}
	for _, name := range []string{"api_health", "api_readiness", "compose_file", "provider_connectivity", "agent_compose_protocol", "octobus_protocol", "octobus_proxy", "network_dns"} {
		if check := checkByName(report, name); check.Status != StatusUnknown {
			t.Fatalf("%s=%+v", name, check)
		}
	}
}

func TestRunRejectsUnsafeConfigurationWithoutProbes(t *testing.T) {
	client := &fakeHTTP{}
	called := false
	deps := fakeDependencies(client, composeFixture)
	deps.LookPath = func(string) (string, error) { called = true; return "", nil }
	deps.RunCommand = func(context.Context, string, ...string) ([]byte, error) { called = true; return nil, nil }
	deps.ReadFile = func(string) ([]byte, error) { called = true; return []byte(composeFixture), nil }
	deps.DialContext = func(context.Context, string, string) (net.Conn, error) { called = true; return nil, nil }
	cfg := testConfig("agentcompose-cli")
	cfg.AgentComposeBin = "agent-compose;touch /tmp/doctor"
	report := RunWithDependencies(context.Background(), cfg, deps)
	if report.ExitCode() == 0 || checkByName(report, "configuration").Status != StatusFailed || called || len(client.calls) != 0 {
		t.Fatalf("report=%+v called=%v api_calls=%v", report, called, client.calls)
	}
}

func TestUnverifiedIntegrationsRemainUnknown(t *testing.T) {
	deps := fakeDependencies(&fakeHTTP{}, composeFixture)
	deps.OctoBusProtocol = nil
	deps.ProviderProbe = nil
	deps.OctoBusProxyProbe = nil
	report := RunWithDependencies(context.Background(), testConfig("agentcompose-cli"), deps)
	for _, name := range []string{"octobus_protocol", "provider_connectivity", "octobus_proxy"} {
		if check := checkByName(report, name); !check.Required || check.Status != StatusUnknown {
			t.Fatalf("%s=%+v", name, check)
		}
	}
	if report.ExitCode() == 0 {
		t.Fatalf("unverified checks unexpectedly passed: %+v", report)
	}
	defaults := DefaultDependencies()
	if defaults.AgentComposeProtocol == nil || defaults.DockerInspect == nil || defaults.DNSProbe == nil {
		t.Fatal("safe default dependencies are missing")
	}
	if defaults.OctoBusProtocol != nil || defaults.ProviderProbe != nil || defaults.OctoBusProxyProbe != nil || defaults.ValidateCompose != nil {
		t.Fatal("default dependencies invented an unsupported active validation")
	}
}

func TestDefaultAdaptersUseInjectedRunCommand(t *testing.T) {
	const statusJSON = `{"err":null,"msg":"OK","data":{"version":"v2609.1.0","os":"linux","arch":"arm64","compiled_drivers":["docker"],"timestamp":1783501631.25,"timezone":"UTC","timezone_offset":0}}`
	const imageID = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	var calls []string
	deps := fillDefaults(Dependencies{RunCommand: func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if args[len(args)-1] == "status" {
			return []byte(statusJSON), nil
		}
		return []byte(imageID), nil
	}})

	if err := deps.AgentComposeProtocol(context.Background(), "/resolved/agent-compose", "http://daemon.test"); err != nil {
		t.Fatal(err)
	}
	if err := deps.DockerInspect(context.Background(), "/resolved/docker", "guest:v1"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/resolved/agent-compose --json --host http://daemon.test status",
		"/resolved/docker image inspect --format {{.Id}} guest:v1",
	}
	if len(calls) != len(want) {
		t.Fatalf("calls=%q", calls)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("calls[%d]=%q, want %q", i, calls[i], want[i])
		}
	}
}

func TestAgentComposeProtocolUsesResolvedBinary(t *testing.T) {
	deps := fakeDependencies(&fakeHTTP{}, composeFixture)
	deps.AgentComposeProtocol = nil
	var versionBinary, statusBinary string
	deps.RunCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "--json version":
			versionBinary = name
			return []byte(`{"version":"v2609.1.0","os":"test","arch":"test","compiled_drivers":["docker"]}`), nil
		case "--json --host http://compose.test:7410 status":
			statusBinary = name
			return []byte(`{"err":null,"msg":"OK","data":{"version":"v2609.1.0","os":"test","arch":"test","compiled_drivers":["docker"],"timestamp":1783501631.25,"timezone":"UTC","timezone_offset":0}}`), nil
		default:
			return nil, nil
		}
	}
	report := RunWithDependencies(context.Background(), testConfig("agentcompose-cli"), deps)
	if check := checkByName(report, "agent_compose_protocol"); check.Status != StatusPassed {
		t.Fatalf("protocol check=%+v", check)
	}
	if versionBinary != "/fake/agent-compose" || statusBinary != versionBinary {
		t.Fatalf("version binary=%q status binary=%q", versionBinary, statusBinary)
	}
}

func TestComposeInterpolationAndDockerInspectFailClosed(t *testing.T) {
	cfg := testConfig("agentcompose-cli")
	badCompose := strings.Replace(composeFixture, "${SAS_AGENT_MODEL}", "${MISSING_MODEL}", 1)
	deps := fakeDependencies(&fakeHTTP{}, badCompose)
	report := RunWithDependencies(context.Background(), cfg, deps)
	if checkByName(report, "compose_file").Status != StatusFailed {
		t.Fatalf("unresolved interpolation unexpectedly passed: %+v", report)
	}
	deps = fakeDependencies(&fakeHTTP{}, composeFixture)
	deps.ValidateCompose = func(context.Context, string, string) (ComposeValidation, error) {
		return ComposeValidation{}, errors.New("schema failed")
	}
	report = RunWithDependencies(context.Background(), cfg, deps)
	if checkByName(report, "compose_file").Status != StatusFailed {
		t.Fatalf("validator failure unexpectedly passed: %+v", report)
	}
	deps = fakeDependencies(&fakeHTTP{}, composeFixture)
	deps.DockerInspect = func(context.Context, string, string) error { return errors.New("inspect failed") }
	report = RunWithDependencies(context.Background(), cfg, deps)
	if checkByName(report, "docker").Status != StatusFailed {
		t.Fatalf("inspect failure unexpectedly passed: %+v", report)
	}
}

func TestInvalidGuestImageSkipsDockerProbes(t *testing.T) {
	for _, image := range []string{"", "bad image"} {
		t.Run(image, func(t *testing.T) {
			cfg := testConfig("agentcompose-cli")
			cfg.GuestImage = image
			deps := fakeDependencies(&fakeHTTP{}, composeFixture)
			dockerCommandCalled, inspectCalled := false, false
			deps.RunCommand = func(_ context.Context, name string, _ ...string) ([]byte, error) {
				if name == "/fake/docker" {
					dockerCommandCalled = true
				}
				return nil, nil
			}
			deps.DockerInspect = func(context.Context, string, string) error {
				inspectCalled = true
				return nil
			}
			report := RunWithDependencies(context.Background(), cfg, deps)
			if check := checkByName(report, "guest_image"); check.Status != StatusFailed {
				t.Fatalf("guest_image=%+v", check)
			}
			if check := checkByName(report, "docker"); !check.Required || check.Status != StatusUnknown {
				t.Fatalf("docker=%+v", check)
			}
			if dockerCommandCalled || inspectCalled {
				t.Fatalf("invalid image reached Docker: command=%v inspect=%v", dockerCommandCalled, inspectCalled)
			}
		})
	}
}

func TestCheckImageRequiresPinnedReferenceShape(t *testing.T) {
	tests := []struct {
		name  string
		image string
		want  CheckStatus
	}{
		{name: "current version tag", image: "chaitin/agent-compose-guest:v2609.1.0", want: StatusPassed},
		{name: "registry port and tag", image: "registry.example:5000/team/guest:v1", want: StatusPassed},
		{name: "sha256 digest", image: "registry.example/team/guest@sha256:" + strings.Repeat("a", 64), want: StatusPassed},
		{name: "untagged", image: "registry.example/team/guest", want: StatusFailed},
		{name: "latest", image: "registry.example/team/guest:latest", want: StatusFailed},
		{name: "malformed digest", image: "registry.example/team/guest@sha512:" + strings.Repeat("a", 64), want: StatusFailed},
		{name: "uppercase digest", image: "registry.example/team/guest@sha256:" + strings.Repeat("A", 64), want: StatusFailed},
		{name: "short digest", image: "registry.example/team/guest@sha256:" + strings.Repeat("a", 63), want: StatusFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, _ := checkImage(tc.image)
			if status != tc.want {
				t.Fatalf("checkImage(%q)=%s, want %s", tc.image, status, tc.want)
			}
		})
	}
}

func TestComposePlaceholdersNeedEnvironmentValues(t *testing.T) {
	cfg := testConfig("agentcompose-cli")
	cfg.Models = map[string]string{}
	cfg.GuestImage = ""
	cfg.Providers = nil
	report := RunWithDependencies(context.Background(), cfg, fakeDependencies(&fakeHTTP{}, composeFixture))
	if checkByName(report, "compose_file").Status != StatusFailed || checkByName(report, "model_settings").Status != StatusFailed || checkByName(report, "guest_image").Status != StatusFailed {
		t.Fatalf("unresolved placeholders unexpectedly passed: %+v", report)
	}
	if checkByName(report, "provider_settings").Status != StatusUnknown {
		t.Fatalf("provider applicability unexpectedly inferred: %+v", checkByName(report, "provider_settings"))
	}

	cfg.Models = map[string]string{
		"SAS_AGENT_MODEL":        "provider/model",
		"SAS_REPORT_MODEL":       "provider/report",
		"SAS_STRONG_AGENT_MODEL": "provider/strong",
	}
	cfg.GuestImage = "guest:v1"
	report = RunWithDependencies(context.Background(), cfg, fakeDependencies(&fakeHTTP{}, composeFixture))
	if checkByName(report, "compose_file").Status != StatusPassed || checkByName(report, "model_settings").Status != StatusPassed || checkByName(report, "guest_image").Status != StatusPassed {
		t.Fatalf("resolved placeholders failed: %+v", report)
	}
}

func TestComposeValidationUsesDocumentedCommand(t *testing.T) {
	deps := fakeDependencies(&fakeHTTP{}, composeFixture)
	deps.ValidateCompose = nil
	configCommand := false
	deps.RunCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "/fake/agent-compose" && strings.Join(args, " ") == "--json --file agent-compose.yml config" {
			configCommand = true
			return []byte(normalizedComposeFixture), nil
		}
		if strings.Join(args, " ") == "--json version" {
			return []byte(`{"version":"v2609.1.0","os":"test","arch":"test","compiled_drivers":["docker"]}`), nil
		}
		return nil, nil
	}
	report := RunWithDependencies(context.Background(), testConfig("agentcompose-cli"), deps)
	if check := checkByName(report, "compose_file"); !configCommand || !check.Required || check.Status != StatusPassed {
		t.Fatalf("fixed validator failed: command=%v check=%+v", configCommand, check)
	}

	deps = fakeDependencies(&fakeHTTP{}, composeFixture)
	deps.ValidateCompose = func(context.Context, string, string) (ComposeValidation, error) {
		return ComposeValidation{}, nil
	}
	report = RunWithDependencies(context.Background(), testConfig("agentcompose-cli"), deps)
	if check := checkByName(report, "compose_file"); !check.Required || check.Status != StatusUnknown {
		t.Fatalf("incomplete injected validation unexpectedly passed: %+v", check)
	}
}

func TestDefaultComposeValidationDeterminesDockerApplicability(t *testing.T) {
	deps := fakeDependencies(&fakeHTTP{}, composeFixture)
	deps.ValidateCompose = nil
	inspectedImage := ""
	deps.DockerInspect = func(_ context.Context, _ string, image string) error {
		inspectedImage = image
		return nil
	}
	report := RunWithDependencies(context.Background(), testConfig("agentcompose-cli"), deps)
	if check := checkByName(report, "compose_file"); check.Status != StatusPassed {
		t.Fatalf("compose check=%+v", check)
	}
	if check := checkByName(report, "docker"); !check.Required || check.Status != StatusPassed || inspectedImage != "guest:v1" {
		t.Fatalf("Docker applicability/image was not determined: check=%+v image=%q", check, inspectedImage)
	}
}

func TestParseNormalizedCompose(t *testing.T) {
	valid := normalizedComposeFixture
	tests := []struct {
		name string
		data string
		want ComposeValidation
		fail bool
	}{
		{name: "valid", data: valid, want: ComposeValidation{Complete: true, ProviderConfigured: true, UsesDocker: true}},
		{name: "explicit false disabled", data: `{"name":"test","agents":[{"name":"off","enabled":false,"driver":{"name":"boxlite","boxlite":{}}},{"name":"demo","enabled":true,"provider":"pi","image":"guest:v1","driver":{"name":"docker","docker":{}}}]}`, want: ComposeValidation{Complete: true, ProviderConfigured: true, UsesDocker: true}},
		{name: "future fields ignored", data: `{"name":"test","future":true,"agents":[{"name":"demo","enabled":true,"provider":"pi","image":"guest:v1","future":{},"driver":{"name":"docker","docker":{},"future":true}}]}`, want: ComposeValidation{Complete: true, ProviderConfigured: true, UsesDocker: true}},
		{name: "missing provider", data: strings.Replace(valid, `"provider":"pi",`, "", 1), want: ComposeValidation{Complete: true, UsesDocker: true}},
		{name: "empty", data: "", fail: true},
		{name: "trailing value", data: valid + " {}", fail: true},
		{name: "null", data: "null", fail: true},
		{name: "missing top-level name", data: strings.Replace(valid, `"name":"test",`, "", 1), fail: true},
		{name: "missing agents", data: `{"name":"test"}`, fail: true},
		{name: "duplicate name", data: `{"name":"test","agents":[{"name":"demo","enabled":true,"provider":"pi","image":"guest:v1","driver":{"name":"docker","docker":{}}},{"name":"demo","enabled":false,"provider":"pi","image":"guest:v1","driver":{"name":"docker","docker":{}}}]}`, fail: true},
		{name: "empty name", data: strings.Replace(valid, `"name":"demo"`, `"name":""`, 1), fail: true},
		{name: "missing enabled", data: strings.Replace(valid, `"enabled":true,`, "", 1), fail: true},
		{name: "null enabled", data: strings.Replace(valid, `"enabled":true`, `"enabled":null`, 1), fail: true},
		{name: "no enabled agent", data: strings.Replace(valid, `"enabled":true`, `"enabled":false`, 1), fail: true},
		{name: "disabled missing driver", data: `{"name":"test","agents":[{"name":"off","enabled":false},{"name":"demo","enabled":true,"provider":"pi","image":"guest:v1","driver":{"name":"docker","docker":{}}}]}`, fail: true},
		{name: "missing image", data: strings.Replace(valid, `"image":"guest:v1",`, "", 1), fail: true},
		{name: "divergent image", data: strings.Replace(valid, `"image":"guest:v1"`, `"image":"other:v1"`, 1), fail: true},
		{name: "build only", data: strings.Replace(valid, `"image":"guest:v1",`, `"build":{"context":".","dockerfile":"Dockerfile"},`, 1), fail: true},
		{name: "missing driver name", data: strings.Replace(valid, `"name":"docker"`, `"name":""`, 1), fail: true},
		{name: "selected driver subobject missing", data: strings.Replace(valid, `"driver":{"name":"docker","docker":{}}`, `"driver":{"name":"docker"}`, 1), fail: true},
		{name: "unknown driver", data: strings.Replace(valid, `"driver":{"name":"docker","docker":{}}`, `"driver":{"name":"firecracker","firecracker":{}}`, 1), fail: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseNormalizedCompose([]byte(tc.data), "guest:v1")
			if tc.fail {
				if err == nil {
					t.Fatalf("parse unexpectedly succeeded: %+v", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("parse=(%+v,%v), want (%+v,nil)", got, err, tc.want)
			}
		})
	}
}

func TestDefaultComposeValidationUsesInjectedRunCommand(t *testing.T) {
	called := false
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		called = true
		if name != "agent-compose" || strings.Join(args, " ") != "--json --file compose.yml config" {
			t.Fatalf("unexpected command: %q %q", name, args)
		}
		return []byte(normalizedComposeFixture), nil
	}
	validation, err := validateNormalizedCompose(context.Background(), "agent-compose", "compose.yml", "guest:v1", run)
	if err != nil || !called || validation != (ComposeValidation{Complete: true, ProviderConfigured: true, UsesDocker: true}) {
		t.Fatalf("validation=(%+v,%v), called=%v", validation, err, called)
	}
}

func TestMissingComposeProviderFailsEvenWithSASProvider(t *testing.T) {
	cfg := testConfig("agentcompose-cli")
	deps := fakeDependencies(&fakeHTTP{}, composeFixture)
	deps.ValidateCompose = nil
	deps.ProviderProbe = nil
	deps.RunCommand = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "--json version":
			return []byte(`{"version":"v2609.1.0","os":"test","arch":"test","compiled_drivers":["docker"]}`), nil
		case "--json --file agent-compose.yml config":
			return []byte(strings.Replace(normalizedComposeFixture, `"provider":"pi",`, "", 1)), nil
		default:
			return nil, nil
		}
	}

	report := RunWithDependencies(context.Background(), cfg, deps)
	if check := checkByName(report, "compose_file"); check.Status != StatusPassed {
		t.Fatalf("compose check=%+v", check)
	}
	if check := checkByName(report, "provider_settings"); check.Status != StatusFailed || check.Message != "enabled compose agent provider declaration is missing" {
		t.Fatalf("provider check=%+v", check)
	}
	if check := checkByName(report, "provider_connectivity"); check.Status != StatusUnknown {
		t.Fatalf("provider connectivity=%+v", check)
	}
}

func TestCompleteComposeValidationDeterminesApplicability(t *testing.T) {
	compose := "name: test\nagents: {demo: {provider: pi}}\n"
	deps := fakeDependencies(&fakeHTTP{}, compose)
	deps.ValidateCompose = func(context.Context, string, string) (ComposeValidation, error) {
		return ComposeValidation{Complete: true, ProviderConfigured: true}, nil
	}
	report := RunWithDependencies(context.Background(), testConfig("agentcompose-cli"), deps)
	if checkByName(report, "compose_file").Status != StatusPassed {
		t.Fatalf("complete validator did not determine compose status: %+v", report)
	}
	if check := checkByName(report, "docker"); check.Required || check.Status != StatusSkipped {
		t.Fatalf("authoritative Docker applicability was ignored: %+v", check)
	}
}

func TestProviderDeclarationMessageDoesNotClaimConnectivity(t *testing.T) {
	status, message := checkProviders(nil, true, true)
	if status != StatusPassed || message != "provider declarations present; connectivity not verified" {
		t.Fatalf("provider declaration check=(%s,%q)", status, message)
	}
}

func TestComposeInputSizeLimitPreventsValidation(t *testing.T) {
	deps := fakeDependencies(&fakeHTTP{}, strings.Repeat("x", maxComposeBytes+1))
	called := false
	deps.ValidateCompose = func(context.Context, string, string) (ComposeValidation, error) {
		called = true
		return ComposeValidation{}, nil
	}
	report := RunWithDependencies(context.Background(), testConfig("agentcompose-cli"), deps)
	if called || checkByName(report, "compose_file").Status != StatusFailed {
		t.Fatalf("oversized compose was validated: called=%v report=%+v", called, report)
	}
}

func TestParseURLRejectsUnsafeValues(t *testing.T) {
	for _, raw := range []string{
		"", " http://api.test", "file:///tmp/private", "http://user:secret@api.test",
		"http://api.test?key=secret", "http://api.test#fragment", "http://api.test:70000", "http://api.test/%0a",
	} {
		if _, err := parseURL(raw, true); err == nil {
			t.Errorf("parseURL(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestRequiredProbeFailuresAndTimeouts(t *testing.T) {
	cfg := testConfig("agentcompose-cli")
	deps := fakeDependencies(&fakeHTTP{}, composeFixture)
	deps.AgentComposeProtocol = func(context.Context, string, string) error { return errors.New("protocol failed") }
	deps.ProviderProbe = func(context.Context, map[string]string) error { return errors.New("provider failed") }
	report := RunWithDependencies(context.Background(), cfg, deps)
	for _, name := range []string{"agent_compose_protocol", "provider_connectivity"} {
		if check := checkByName(report, name); !check.Required || check.Status != StatusFailed {
			t.Fatalf("%s=%+v", name, check)
		}
	}

	cfg.Timeout = 5 * time.Millisecond
	deps = fakeDependencies(&fakeHTTP{}, composeFixture)
	deps.AgentComposeProtocol = func(ctx context.Context, _, _ string) error { <-ctx.Done(); return ctx.Err() }
	deps.ProviderProbe = func(ctx context.Context, _ map[string]string) error { <-ctx.Done(); return ctx.Err() }
	report = RunWithDependencies(context.Background(), cfg, deps)
	for _, name := range []string{"agent_compose_protocol", "provider_connectivity"} {
		if check := checkByName(report, name); !check.Required || check.Status != StatusUnknown {
			t.Fatalf("%s=%+v", name, check)
		}
	}
	if report.ExitCode() == 0 {
		t.Fatalf("timed out required probes unexpectedly passed: %+v", report)
	}
}

func TestCanceledSuccessfulCallbacksAreUnknown(t *testing.T) {
	assertUnknown := func(t *testing.T, status CheckStatus) {
		t.Helper()
		if status != StatusUnknown {
			t.Fatalf("status=%s", status)
		}
	}

	t.Run("API", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		base, err := parseURL("http://api.test", true)
		if err != nil {
			t.Fatal(err)
		}
		client := httpDoerFunc(func(req *http.Request) (*http.Response, error) {
			cancel()
			return &http.Response{StatusCode: http.StatusOK, Request: req}, nil
		})
		status, _ := probeAPI(ctx, testConfig("mock"), client, base, "/healthz", "health")
		assertUnknown(t, status)
	})

	t.Run("agent-compose", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		status, _ := probeAgentCompose(ctx, time.Second, "agent-compose", func(context.Context, string, ...string) ([]byte, error) {
			calls++
			cancel()
			return []byte(`{"version":"v2609.1.0","os":"darwin","arch":"arm64","compiled_drivers":["docker"]}`), nil
		})
		assertUnknown(t, status)
		if calls != 1 {
			t.Fatalf("calls=%d", calls)
		}
	})

	t.Run("compose validator", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		deps := Dependencies{ValidateCompose: func(context.Context, string, string) (ComposeValidation, error) {
			cancel()
			return ComposeValidation{Complete: true}, nil
		}}
		status, _, _ := validateCompose(ctx, time.Second, "agent-compose", "agent-compose.yml", []byte(composeFixture), testConfig("agentcompose-cli"), deps)
		assertUnknown(t, status)
	})

	t.Run("compose command", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		deps := Dependencies{RunCommand: func(context.Context, string, ...string) ([]byte, error) {
			cancel()
			return nil, nil
		}}
		status, _, _ := validateCompose(ctx, time.Second, "agent-compose", "agent-compose.yml", []byte(composeFixture), testConfig("agentcompose-cli"), deps)
		assertUnknown(t, status)
	})

	t.Run("provider", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		status, _ := probeProvider(ctx, time.Second, func(context.Context, map[string]string) error {
			cancel()
			return nil
		}, map[string]string{"SAS_PROVIDER": "pi"})
		assertUnknown(t, status)
	})

	for _, tc := range []struct{ name, label string }{{"agent_compose_protocol", "agent-compose"}, {"octobus_protocol", "OctoBus"}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			var got Check
			addProtocolCheck(func(name string, required bool, status CheckStatus, message string) {
				got = Check{Name: name, Required: required, Status: status, Message: message}
			}, tc.name, tc.label, "http://host.test", true, func(context.Context, string) error {
				cancel()
				return nil
			}, time.Second, ctx)
			assertUnknown(t, got.Status)
		})
	}

	t.Run("DNS", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		status, _ := probeDNS(ctx, time.Second, []string{"http://one.test", "http://two.test"}, func(context.Context, string) error {
			calls++
			cancel()
			return nil
		})
		assertUnknown(t, status)
		if calls != 1 {
			t.Fatalf("calls=%d", calls)
		}
	})

	t.Run("proxy", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		status, _ := probeProxy(ctx, time.Second, "http://compose.test", "http://octobus.test", func(context.Context, string, string) error {
			cancel()
			return nil
		})
		assertUnknown(t, status)
	})

	t.Run("TCP", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		status, _ := probeHost(ctx, time.Second, "http://host.test", func(context.Context, string, string) (net.Conn, error) {
			cancel()
			return fakeConn{}, nil
		}, "host")
		assertUnknown(t, status)
		status, _ = probeHost(context.Background(), time.Second, "http://host.test", func(context.Context, string, string) (net.Conn, error) {
			return nil, nil
		}, "host")
		assertUnknown(t, status)
	})

	t.Run("Docker command", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		inspectCalled := false
		deps := Dependencies{
			LookPath: func(string) (string, error) { return "/fake/docker", nil },
			RunCommand: func(context.Context, string, ...string) ([]byte, error) {
				cancel()
				return nil, nil
			},
			DockerInspect: func(context.Context, string, string) error { inspectCalled = true; return nil },
		}
		status, _ := probeDocker(ctx, time.Second, "docker", "guest:v1", deps)
		assertUnknown(t, status)
		if inspectCalled {
			t.Fatal("inspect called after canceled Docker command")
		}
	})

	t.Run("Docker inspect", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		deps := Dependencies{
			LookPath:   func(string) (string, error) { return "/fake/docker", nil },
			RunCommand: func(context.Context, string, ...string) ([]byte, error) { return nil, nil },
			DockerInspect: func(context.Context, string, string) error {
				cancel()
				return nil
			},
		}
		status, _ := probeDocker(ctx, time.Second, "docker", "guest:v1", deps)
		assertUnknown(t, status)
	})
}

func TestCanceledContextSkipsExternalCallbacks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	deps := fakeDependencies(httpDoerFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	}), composeFixture)
	deps.RunCommand = func(context.Context, string, ...string) ([]byte, error) { called = true; return nil, nil }
	deps.DialContext = func(context.Context, string, string) (net.Conn, error) { called = true; return nil, nil }
	deps.AgentComposeProtocol = func(context.Context, string, string) error { called = true; return nil }
	deps.OctoBusProtocol = func(context.Context, string) error { called = true; return nil }
	deps.ProviderProbe = func(context.Context, map[string]string) error { called = true; return nil }
	deps.DockerInspect = func(context.Context, string, string) error { called = true; return nil }
	deps.ValidateCompose = func(context.Context, string, string) (ComposeValidation, error) {
		called = true
		return ComposeValidation{Complete: true}, nil
	}
	deps.DNSProbe = func(context.Context, string) error { called = true; return nil }
	deps.OctoBusProxyProbe = func(context.Context, string, string) error { called = true; return nil }
	report := RunWithDependencies(ctx, testConfig("agentcompose-cli"), deps)
	if called || report.ExitCode() == 0 {
		t.Fatalf("called=%v report=%+v", called, report)
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
	deps := fakeDependencies(&fakeHTTP{}, compose)
	deps.ValidateCompose = func(context.Context, string, string) (ComposeValidation, error) {
		return ComposeValidation{Complete: true}, nil
	}
	report := RunWithDependencies(context.Background(), cfg, deps)
	if checkByName(report, "provider_settings").Status != StatusFailed {
		t.Fatalf("provider check=%+v report=%+v", checkByName(report, "provider_settings"), report)
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

func TestAgentComposeVersionUsesFixedJSONContract(t *testing.T) {
	calls := 0
	status, _ := probeAgentCompose(context.Background(), time.Second, "/fake/agent-compose", func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls++
		if name != "/fake/agent-compose" || strings.Join(args, " ") != "--json version" {
			t.Fatalf("command = %q %q", name, args)
		}
		return []byte(`{"version":"v2609.1.0","os":"darwin","arch":"arm64","compiled_drivers":["docker"]}`), nil
	})
	if status != StatusPassed || calls != 1 {
		t.Fatalf("status=%s calls=%d", status, calls)
	}

	for _, output := range []string{
		`{"version":"v2608.5.0","os":"darwin","arch":"arm64","compiled_drivers":["docker"]}`,
		`{"version":"v2609.1.0"}`,
		`not json`,
	} {
		status, _ = probeAgentCompose(context.Background(), time.Second, "/fake/agent-compose", func(context.Context, string, ...string) ([]byte, error) {
			return []byte(output), nil
		})
		if status != StatusFailed {
			t.Fatalf("output=%q status=%s, want failed", output, status)
		}
	}
}

func TestRunRuntimeSkipsAPIProbe(t *testing.T) {
	called := false
	deps := fakeDependencies(httpDoerFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("must not call API")
	}), composeFixture)
	report := RunRuntimeWithDependencies(context.Background(), testConfig("agentcompose-cli"), deps)
	if called || hasCheck(report, "api_health") || hasCheck(report, "api_readiness") {
		t.Fatalf("API called=%v report=%+v", called, report)
	}
	if report.Overall != OverallPassed {
		t.Fatalf("runtime report=%+v", report)
	}
}

func TestAgentComposeDaemonStatusUsesFixedJSONContract(t *testing.T) {
	valid := `{"err":null,"msg":"OK","data":{"version":"v2609.1.0","os":"linux","arch":"arm64","compiled_drivers":["docker"],"timestamp":1783501631.25,"timezone":"UTC","timezone_offset":0}}`
	calls := 0
	err := validateAgentComposeDaemon(context.Background(), "/fake/agent-compose", "http://daemon.test", func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls++
		if name != "/fake/agent-compose" || strings.Join(args, " ") != "--json --host http://daemon.test status" {
			t.Fatalf("command = %q %q", name, args)
		}
		return []byte(valid), nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
	for _, output := range []string{
		strings.Replace(valid, "v2609.1.0", "v2608.5.0", 1),
		strings.Replace(valid, `"msg":"OK"`, `"msg":"unhealthy"`, 1),
		strings.TrimSuffix(valid, "}") + `,"extra":true}`,
	} {
		if err := validateAgentComposeDaemon(context.Background(), "agent-compose", "http://daemon.test", func(context.Context, string, ...string) ([]byte, error) {
			return []byte(output), nil
		}); err == nil {
			t.Fatalf("status %q unexpectedly passed", output)
		}
	}
}

func TestAgentComposeDaemonStatusRequiresTimezoneOffset(t *testing.T) {
	valid := `{"err":null,"msg":"OK","data":{"version":"v2609.1.0","os":"linux","arch":"arm64","compiled_drivers":["docker"],"timestamp":1783501631.25,"timezone":"UTC","timezone_offset":0}}`
	run := func(output string) error {
		return validateAgentComposeDaemon(context.Background(), "/fake/agent-compose", "http://daemon.test", func(context.Context, string, ...string) ([]byte, error) {
			return []byte(output), nil
		})
	}
	if err := run(valid); err != nil {
		t.Fatalf("explicit zero offset failed: %v", err)
	}
	missing := strings.Replace(valid, `,"timezone_offset":0`, "", 1)
	if err := run(missing); err == nil {
		t.Fatal("missing timezone_offset unexpectedly passed")
	}
}

func TestDockerImageInspectUsesImageIDContract(t *testing.T) {
	const imageID = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	err := inspectDockerImage(context.Background(), "/fake/docker", "guest:v1", func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "/fake/docker" || strings.Join(args, " ") != "image inspect --format {{.Id}} guest:v1" {
			t.Fatalf("command = %q %q", name, args)
		}
		return []byte(imageID + "\n"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := inspectDockerImage(context.Background(), "docker", "missing:v1", func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("not found")
	}); err == nil {
		t.Fatal("missing image unexpectedly passed")
	}
	if err := inspectDockerImage(context.Background(), "docker", "bad:v1", func(context.Context, string, ...string) ([]byte, error) {
		return []byte("not-an-image-id"), nil
	}); err == nil {
		t.Fatal("malformed image id unexpectedly passed")
	}
}

func TestCappedCommandOutput(t *testing.T) {
	var output cappedOutput
	data := strings.Repeat("x", maxCommandOutputBytes+1)
	if n, err := output.Write([]byte(data)); err != nil || n != len(data) {
		t.Fatalf("write n=%d err=%v", n, err)
	}
	if !output.overflow || output.Len() != maxCommandOutputBytes {
		t.Fatalf("overflow=%v length=%d", output.overflow, output.Len())
	}
}
