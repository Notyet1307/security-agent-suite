package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type CheckStatus string

const (
	StatusPassed  CheckStatus = "passed"
	StatusFailed  CheckStatus = "failed"
	StatusSkipped CheckStatus = "skipped"
	StatusUnknown CheckStatus = "unknown"
)

type OverallStatus string

const (
	OverallPassed   OverallStatus = "passed"
	OverallDegraded OverallStatus = "degraded"
	OverallFailed   OverallStatus = "failed"
)

type Check struct {
	Name     string      `json:"name"`
	Status   CheckStatus `json:"status"`
	Message  string      `json:"message"`
	Required bool        `json:"required"`
}

type Report struct {
	Checks  []Check       `json:"checks"`
	Overall OverallStatus `json:"overall"`
}

func (r Report) RequiredFailures() bool {
	for _, c := range r.Checks {
		if c.Required && c.Status != StatusPassed {
			return true
		}
	}
	return false
}

func (r Report) ExitCode() int {
	if r.RequiredFailures() {
		return 1
	}
	return 0
}

func (r Report) WriteJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

type Config struct {
	APIBaseURL            string
	APIKey                string
	TenantID              string
	Executor              string
	AgentComposeBin       string
	AgentComposeFile      string
	AgentComposeHost      string
	DockerBin             string
	OctoBusHost           string
	GuestImage            string
	OctoBusProxySandboxID string
	LLMAPIEndpoint        string
	LLMAPIProtocol        string
	LLMAPIKey             string
	LLMModel              string
	Models                map[string]string
	Providers             map[string]string
	Timeout               time.Duration
}

const (
	defaultTimeout        = 5 * time.Second
	maxTimeout            = 30 * time.Second
	maxComposeBytes       = 1 << 20
	maxCommandOutputBytes = 64 << 10
	agentComposeVersion   = "v2609.1.0"
	proxyProbeCommand     = `grpcurl -plaintext -H "x-capability-sandbox-token: $CAP_TOKEN" -H "x-octobus-capset: dev" -H "x-octobus-instance: calculator-test" -d '{"left":20,"right":22}' "$CAP_GRPC_TARGET" calculator.v1.CalculatorService/Add`
	proxyProbeProject     = "sas101-doctor-probe"
)

func FromEnvironment(baseURL, apiKey, tenantID string) Config {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = envOr("SAS_BASE_URL", "http://127.0.0.1:8080")
	}
	if strings.TrimSpace(apiKey) == "" {
		apiKey = os.Getenv("SAS_API_KEY")
	}
	if strings.TrimSpace(tenantID) == "" {
		tenantID = envOr("SAS_TENANT_ID", "default")
	}
	providers := map[string]string{}
	for _, key := range []string{"SAS_PROVIDER", "SAS_AGENT_PROVIDER", "SAS_REPORT_PROVIDER", "SAS_STRONG_AGENT_PROVIDER"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			providers[key] = value
		}
	}
	return Config{
		APIBaseURL: baseURL, APIKey: apiKey, TenantID: tenantID,
		Executor:              envOr("SAS_EXECUTOR", "mock"),
		AgentComposeBin:       envOr("SAS_AGENT_COMPOSE_BIN", "agent-compose"),
		AgentComposeFile:      envOr("SAS_AGENT_COMPOSE_FILE", "./agent-compose.yml"),
		AgentComposeHost:      strings.TrimSpace(os.Getenv("SAS_AGENT_COMPOSE_HOST")),
		DockerBin:             envOr("SAS_DOCKER_BIN", "docker"),
		OctoBusHost:           firstEnv("SAS_OCTOBUS_HOST", "SAS_OCTOBUS_URL", "OCTOBUS_HOST", "OCTOBUS_URL", "AGENT_COMPOSE_OCTOBUS_HOST"),
		GuestImage:            strings.TrimSpace(os.Getenv("AGENT_COMPOSE_GUEST_IMAGE")),
		OctoBusProxySandboxID: strings.TrimSpace(os.Getenv("SAS_OCTOBUS_PROXY_SANDBOX_ID")),
		LLMAPIEndpoint:        strings.TrimSpace(os.Getenv("LLM_API_ENDPOINT")),
		LLMAPIProtocol:        strings.TrimSpace(os.Getenv("LLM_API_PROTOCOL")),
		LLMAPIKey:             firstEnv("LLM_API_KEY", "OPENAI_API_KEY"),
		LLMModel:              strings.TrimSpace(os.Getenv("LLM_MODEL")),
		Models: map[string]string{
			"SAS_AGENT_MODEL":        strings.TrimSpace(os.Getenv("SAS_AGENT_MODEL")),
			"SAS_REPORT_MODEL":       strings.TrimSpace(os.Getenv("SAS_REPORT_MODEL")),
			"SAS_STRONG_AGENT_MODEL": strings.TrimSpace(os.Getenv("SAS_STRONG_AGENT_MODEL")),
		},
		Providers: providers, Timeout: defaultTimeout,
	}
}

func providerProbeSettings(cfg Config) map[string]string {
	return map[string]string{
		"LLM_API_ENDPOINT":       cfg.LLMAPIEndpoint,
		"LLM_API_PROTOCOL":       cfg.LLMAPIProtocol,
		"LLM_API_KEY":            cfg.LLMAPIKey,
		"LLM_MODEL":              cfg.LLMModel,
		"SAS_AGENT_MODEL":        cfg.Models["SAS_AGENT_MODEL"],
		"SAS_REPORT_MODEL":       cfg.Models["SAS_REPORT_MODEL"],
		"SAS_STRONG_AGENT_MODEL": cfg.Models["SAS_STRONG_AGENT_MODEL"],
	}
}

type providerModelsResponse struct {
	Data *[]struct {
		ID string `json:"id"`
	} `json:"data"`
}

func providerProbeHTTP(client HTTPDoer) func(context.Context, map[string]string) error {
	return func(ctx context.Context, settings map[string]string) error {
		endpoint := strings.TrimSpace(settings["LLM_API_ENDPOINT"])
		protocol := strings.TrimSpace(settings["LLM_API_PROTOCOL"])
		key := strings.TrimSpace(settings["LLM_API_KEY"])
		model := strings.TrimSpace(settings["LLM_MODEL"])
		if endpoint == "" || key == "" || model == "" {
			return errors.New("provider configuration is incomplete")
		}
		if protocol != "responses" && protocol != "chat_completions" {
			return errors.New("provider protocol is unsupported")
		}
		u, err := parseURL(endpoint, true)
		if err != nil {
			return errors.New("provider endpoint is invalid")
		}
		if !providerEndpointAllowed(u) {
			return errors.New("provider endpoint must use HTTPS unless it is loopback")
		}
		u.Path = providerModelsPath(u.Path)
		u.RawPath = ""
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return errors.New("could not create provider models request")
		}
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := client.Do(req)
		if err != nil {
			return errors.New("provider models request failed")
		}
		if resp == nil || resp.Body == nil {
			return errors.New("provider models response was unhealthy")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return errors.New("provider models response was unhealthy")
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxOctoBusStatusBodyBytes))
		if err != nil || len(body) >= maxOctoBusStatusBodyBytes {
			return errors.New("provider models response was invalid")
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		var response providerModelsResponse
		if err := decoder.Decode(&response); err != nil {
			return errors.New("provider models response was invalid")
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF || response.Data == nil {
			return errors.New("provider models response was invalid")
		}
		wanted := []string{model, strings.TrimSpace(settings["SAS_AGENT_MODEL"]), strings.TrimSpace(settings["SAS_REPORT_MODEL"]), strings.TrimSpace(settings["SAS_STRONG_AGENT_MODEL"])}
		available := make(map[string]struct{}, len(*response.Data))
		for _, item := range *response.Data {
			available[item.ID] = struct{}{}
		}
		for _, configured := range wanted {
			if configured == "" {
				continue
			}
			matched := false
			for _, candidate := range providerModelCandidates(configured) {
				if _, ok := available[candidate]; ok {
					matched = true
					break
				}
			}
			if !matched {
				return errors.New("configured provider model was not found")
			}
		}
		return nil
	}
}

func providerModelCandidates(configured string) []string {
	configured = strings.TrimSpace(configured)
	if configured == "" {
		return nil
	}
	candidates := []string{configured}
	if slash := strings.IndexByte(configured, '/'); slash >= 0 && slash+1 < len(configured) {
		candidates = append(candidates, configured[slash+1:])
	}
	return candidates
}

func providerEndpointAllowed(u *url.URL) bool {
	if u == nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := strings.TrimSpace(strings.ToLower(u.Hostname()))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type ComposeValidation struct {
	Complete           bool
	ProviderConfigured bool
	UsesDocker         bool
}

type ProxyProbeConfig struct {
	Binary           string
	AgentComposeHost string
	SandboxID        string
	GuestImage       string
}

type Dependencies struct {
	HTTPClient  HTTPDoer
	LookPath    func(string) (string, error)
	RunCommand  func(context.Context, string, ...string) ([]byte, error)
	ReadFile    func(string) ([]byte, error)
	DialContext func(context.Context, string, string) (net.Conn, error)

	AgentComposeProtocol func(context.Context, string, string) error
	OctoBusProtocol      func(context.Context, string) error
	ProviderProbe        func(context.Context, map[string]string) error
	DockerInspect        func(context.Context, string, string) error
	ValidateCompose      func(context.Context, string, string) (ComposeValidation, error)
	DNSProbe             func(context.Context, string) error
	OctoBusProxyProbe    func(context.Context, ProxyProbeConfig) error
}

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func Run(ctx context.Context, cfg Config) Report {
	return run(ctx, cfg, Dependencies{}, true)
}

func RunWithDependencies(ctx context.Context, cfg Config, deps Dependencies) Report {
	return run(ctx, cfg, deps, true)
}

func RunRuntime(ctx context.Context, cfg Config) Report {
	return run(ctx, cfg, Dependencies{}, false)
}

func RunRuntimeWithDependencies(ctx context.Context, cfg Config, deps Dependencies) Report {
	return run(ctx, cfg, deps, false)
}

func run(ctx context.Context, cfg Config, deps Dependencies, includeAPI bool) Report {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg = normalize(cfg)
	deps = fillDefaults(deps)
	report := Report{Checks: make([]Check, 0, 20)}
	add := func(name string, required bool, status CheckStatus, message string) {
		report.Checks = append(report.Checks, Check{Name: name, Status: status, Message: message, Required: required})
	}
	runtimeConfigOK := validateRuntimeConfig(cfg) == nil
	var base *url.URL
	var baseErr error
	if includeAPI {
		base, baseErr = parseURL(cfg.APIBaseURL, true)
	}
	configOK := runtimeConfigOK && (!includeAPI || baseErr == nil)
	if !configOK {
		add("configuration", true, StatusFailed, "configuration is malformed or contains unsafe characters")
	} else {
		add("configuration", true, StatusPassed, "configuration is valid")
	}
	if includeAPI {
		if baseErr != nil {
			add("api_base_url", true, StatusFailed, "API base URL is malformed or uses an unsupported scheme")
			add("api_health", true, StatusUnknown, "API health probe could not be verified")
			add("api_readiness", true, StatusUnknown, "API readiness probe could not be verified")
		} else {
			add("api_base_url", true, StatusPassed, "API base URL is valid")
			for _, p := range []struct{ name, path, label string }{{"api_health", "/healthz", "health"}, {"api_readiness", "/readyz", "readiness"}} {
				if !configOK {
					add(p.name, true, StatusUnknown, "API "+p.label+" probe could not be verified")
					continue
				}
				status, message := probeAPI(ctx, cfg, deps.HTTPClient, base, p.path, p.label)
				add(p.name, true, status, message)
			}
		}
	}
	var binary string
	var binaryErr error
	switch {
	case !configOK:
		addIntegration(add, cfg.Executor == "agentcompose-cli", StatusUnknown, "integration checks could not be verified because configuration is invalid")
	case cfg.Executor == "mock":
		addIntegration(add, false, StatusSkipped, "integration is optional in mock executor mode")
	case cfg.Executor == "agentcompose-cli" && ctx.Err() != nil:
		addIntegration(add, true, StatusUnknown, "integration checks could not be verified because the doctor context was canceled")
	case cfg.Executor == "agentcompose-cli":
		composeData, composeErr := inspectCompose(cfg.AgentComposeFile, deps.ReadFile)
		binary, binaryErr = findBinary(cfg.AgentComposeBin, deps.LookPath)
		composeStatus := StatusUnknown
		validation := ComposeValidation{}
		if composeErr != nil {
			composeStatus = StatusFailed
			add("compose_file", true, composeStatus, "configured compose file is missing, unreadable, or unsafe")
		} else if binaryErr != nil || binary == "" {
			add("compose_file", true, composeStatus, "compose configuration could not be validated without agent-compose")
		} else {
			var message string
			composeStatus, message, validation = validateCompose(ctx, cfg.Timeout, binary, cfg.AgentComposeFile, composeData, cfg, deps)
			add("compose_file", true, composeStatus, message)
		}
		if binaryErr != nil || binary == "" {
			add("agent_compose_binary", true, StatusFailed, "agent-compose binary was not found")
			add("agent_compose_version", true, StatusUnknown, "agent-compose version probe could not be verified")
		} else {
			add("agent_compose_binary", true, StatusPassed, "agent-compose binary is available")
			status, message := probeAgentCompose(ctx, cfg.Timeout, binary, deps.RunCommand)
			add("agent_compose_version", true, status, message)
		}
		status, message := checkModels(cfg.Models)
		add("model_settings", true, status, message)
		imageStatus, message := checkImage(cfg.GuestImage)
		add("guest_image", true, imageStatus, message)
		composeComplete := composeStatus == StatusPassed && validation.Complete
		status, message = checkProviders(cfg.Providers, composeComplete, composeComplete && validation.ProviderConfigured)
		add("provider_settings", true, status, message)
		if composeComplete && status == StatusPassed {
			status, message = probeProvider(ctx, cfg.Timeout, deps.ProviderProbe, providerProbeSettings(cfg))
			add("provider_connectivity", true, status, message)
		} else {
			add("provider_connectivity", true, StatusUnknown, "provider connectivity could not be verified")
		}
		switch {
		case imageStatus != StatusPassed:
			add("docker", true, StatusUnknown, "Docker guest image could not be probed because its configuration is invalid")
		case !composeComplete:
			add("docker", true, StatusUnknown, "Docker applicability could not be confirmed without complete compose validation")
		case !validation.UsesDocker:
			add("docker", false, StatusSkipped, "Docker check skipped because the validated compose configuration does not use Docker")
		default:
			status, message = probeDocker(ctx, cfg.Timeout, cfg.DockerBin, cfg.GuestImage, deps)
			add("docker", true, status, message)
		}
	default:
		addIntegration(add, false, StatusSkipped, "integration checks skipped because the executor is invalid")
	}
	for _, h := range []struct {
		name, raw, label string
		required         bool
	}{
		{"agent_compose_host", cfg.AgentComposeHost, "agent-compose", cfg.Executor == "agentcompose-cli"},
		{"octobus_host", cfg.OctoBusHost, "OctoBus", cfg.Executor == "agentcompose-cli"},
	} {
		if cfg.Executor == "mock" {
			add(h.name, false, StatusSkipped, h.label+" host check is optional in mock executor mode")
			continue
		}
		if strings.TrimSpace(h.raw) == "" {
			if h.required {
				add(h.name, true, StatusFailed, h.label+" host is not configured")
			} else {
				add(h.name, false, StatusSkipped, h.label+" host is not configured")
			}
		} else if !configOK {
			add(h.name, h.required, StatusUnknown, h.label+" host probe could not be verified")
		} else {
			status, message := probeHost(ctx, cfg.Timeout, h.raw, deps.DialContext, h.label)
			add(h.name, h.required, status, message)
		}
	}
	if cfg.Executor == "agentcompose-cli" {
		var agentComposeProtocol func(context.Context, string) error
		if deps.AgentComposeProtocol != nil && binaryErr == nil && binary != "" {
			agentComposeProtocol = func(probeCtx context.Context, host string) error {
				return deps.AgentComposeProtocol(probeCtx, binary, host)
			}
		}
		addProtocolCheck(add, "agent_compose_protocol", "agent-compose", cfg.AgentComposeHost, configOK, agentComposeProtocol, cfg.Timeout, ctx)
		addProtocolCheck(add, "octobus_protocol", "OctoBus", cfg.OctoBusHost, configOK, deps.OctoBusProtocol, cfg.Timeout, ctx)
		switch {
		case cfg.OctoBusProxySandboxID == "":
			add("octobus_proxy", true, StatusUnknown, "live Sandbox to OctoBus proxy could not be verified because the probe sandbox is not configured")
		case !validSandboxID(cfg.OctoBusProxySandboxID):
			add("octobus_proxy", true, StatusFailed, "live Sandbox to OctoBus proxy probe sandbox ID is invalid")
		case deps.OctoBusProxyProbe == nil || !configOK || binaryErr != nil || binary == "" || !validHost(cfg.AgentComposeHost):
			add("octobus_proxy", true, StatusUnknown, "live Sandbox to OctoBus proxy could not be verified")
		default:
			status, message := probeProxy(ctx, cfg.Timeout, ProxyProbeConfig{
				Binary: binary, AgentComposeHost: cfg.AgentComposeHost,
				SandboxID: cfg.OctoBusProxySandboxID, GuestImage: cfg.GuestImage,
			}, deps.OctoBusProxyProbe)
			add("octobus_proxy", true, status, message)
		}
		if deps.DNSProbe == nil || !configOK {
			add("network_dns", true, StatusUnknown, "network DNS could not be verified")
		} else {
			status, message := probeDNS(ctx, cfg.Timeout, []string{cfg.AgentComposeHost, cfg.OctoBusHost}, deps.DNSProbe)
			add("network_dns", true, status, message)
		}
	}
	report.Overall = aggregate(report.Checks)
	return report
}

func addIntegration(add func(string, bool, CheckStatus, string), required bool, status CheckStatus, message string) {
	for _, name := range []string{"agent_compose_binary", "agent_compose_version", "compose_file", "docker", "model_settings", "guest_image", "provider_settings", "provider_connectivity"} {
		add(name, required, status, message)
	}
}

func normalize(cfg Config) Config {
	if strings.TrimSpace(cfg.Executor) == "" {
		cfg.Executor = "mock"
	}
	if strings.TrimSpace(cfg.AgentComposeBin) == "" {
		cfg.AgentComposeBin = "agent-compose"
	}
	if strings.TrimSpace(cfg.AgentComposeFile) == "" {
		cfg.AgentComposeFile = "./agent-compose.yml"
	}
	if strings.TrimSpace(cfg.DockerBin) == "" {
		cfg.DockerBin = "docker"
	}
	if cfg.Models == nil {
		cfg.Models = map[string]string{}
	}
	if cfg.Providers == nil {
		cfg.Providers = map[string]string{}
	}
	if cfg.Timeout <= 0 || cfg.Timeout > maxTimeout {
		cfg.Timeout = defaultTimeout
	}
	return cfg
}

func fillDefaults(deps Dependencies) Dependencies {
	d := DefaultDependencies()
	if deps.HTTPClient == nil {
		deps.HTTPClient = d.HTTPClient
	}
	if deps.LookPath == nil {
		deps.LookPath = d.LookPath
	}
	if deps.RunCommand == nil {
		deps.RunCommand = d.RunCommand
	}
	if deps.ReadFile == nil {
		deps.ReadFile = d.ReadFile
	}
	if deps.DialContext == nil {
		deps.DialContext = d.DialContext
	}
	if deps.AgentComposeProtocol == nil {
		run := deps.RunCommand
		deps.AgentComposeProtocol = func(ctx context.Context, binary, host string) error {
			return validateAgentComposeDaemon(ctx, binary, host, run)
		}
	}
	if deps.OctoBusProtocol == nil {
		deps.OctoBusProtocol = octoBusProtocol(deps.HTTPClient)
	}
	if deps.ProviderProbe == nil {
		deps.ProviderProbe = providerProbeHTTP(deps.HTTPClient)
	}
	if deps.DockerInspect == nil {
		run := deps.RunCommand
		deps.DockerInspect = func(ctx context.Context, binary, image string) error {
			return inspectDockerImage(ctx, binary, image, run)
		}
	}
	if deps.DNSProbe == nil {
		deps.DNSProbe = d.DNSProbe
	}
	if deps.OctoBusProxyProbe == nil {
		deps.OctoBusProxyProbe = octoBusProxyProbe(deps.RunCommand)
	}
	return deps
}

func octoBusProtocol(client HTTPDoer) func(context.Context, string) error {
	return func(ctx context.Context, host string) error {
		return probeOctoBusStatus(ctx, host, client)
	}
}

func DefaultDependencies() Dependencies {
	run := runCommand
	httpClient := &http.Client{
		Timeout: defaultTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return Dependencies{
		HTTPClient: httpClient,
		LookPath:   exec.LookPath,
		RunCommand: run,
		ReadFile:   readFile,
		DialContext: (&net.Dialer{
			Timeout: defaultTimeout,
		}).DialContext,
		AgentComposeProtocol: func(ctx context.Context, binary, host string) error {
			return validateAgentComposeDaemon(ctx, binary, host, run)
		},
		OctoBusProtocol: octoBusProtocol(httpClient),
		ProviderProbe:   providerProbeHTTP(httpClient),
		DockerInspect: func(ctx context.Context, binary, image string) error {
			return inspectDockerImage(ctx, binary, image, run)
		},
		DNSProbe: func(ctx context.Context, host string) error {
			_, err := net.DefaultResolver.LookupHost(ctx, host)
			return err
		},
		OctoBusProxyProbe: octoBusProxyProbe(run),
	}
}

func validateRuntimeConfig(cfg Config) error {
	if cfg.Executor != "mock" && cfg.Executor != "agentcompose-cli" {
		return errors.New("unsupported executor")
	}
	if unsafeCommand(cfg.AgentComposeBin) || unsafeCommand(cfg.DockerBin) {
		return errors.New("unsafe command")
	}
	for _, value := range []string{cfg.APIKey, cfg.TenantID, cfg.AgentComposeFile, cfg.AgentComposeHost, cfg.OctoBusHost, cfg.GuestImage, cfg.LLMAPIEndpoint, cfg.LLMAPIProtocol, cfg.LLMAPIKey, cfg.LLMModel} {
		if unsafeText(value) {
			return errors.New("unsafe text")
		}
	}
	if cfg.Executor == "agentcompose-cli" && cfg.OctoBusProxySandboxID != "" && !validSandboxID(cfg.OctoBusProxySandboxID) {
		return errors.New("invalid OctoBus proxy sandbox ID")
	}
	for key, value := range cfg.Models {
		if unsafeText(key) || unsafeText(value) {
			return errors.New("unsafe model setting")
		}
	}
	for key, value := range cfg.Providers {
		if unsafeText(key) || unsafeText(value) {
			return errors.New("unsafe provider setting")
		}
	}
	return nil
}

func unsafeText(value string) bool {
	if !utf8.ValidString(value) {
		return true
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func validSandboxID(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func unsafeCommand(value string) bool {
	return unsafeText(value) || strings.ContainsAny(value, ";|&$`()<>")
}

func parseURL(raw string, requireScheme bool) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if raw != trimmed || trimmed == "" || unsafeText(trimmed) || strings.ContainsAny(trimmed, " \\") {
		return nil, errors.New("empty or unsafe URL")
	}
	if !requireScheme && !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" || u.Hostname() == "" || (requireScheme && u.Scheme == "") {
		return nil, errors.New("malformed URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("unsupported URL scheme")
	}
	if u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(u.Host, ":") || unsafeText(u.Path) {
		return nil, errors.New("unsafe URL components")
	}
	if port := u.Port(); port != "" {
		n, portErr := strconv.Atoi(port)
		if portErr != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid port")
		}
	}
	return u, nil
}

func probeAPI(ctx context.Context, cfg Config, client HTTPDoer, base *url.URL, suffix, label string) (CheckStatus, string) {
	probeCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if probeCtx.Err() != nil {
		return StatusUnknown, "API " + label + " probe could not be verified"
	}
	u := *base
	u.Path = strings.TrimRight(u.Path, "/") + suffix
	u.RawPath = ""
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return StatusUnknown, "API " + label + " probe could not be constructed"
	}
	if cfg.APIKey != "" {
		req.Header.Set("X-API-Key", cfg.APIKey)
	}
	if cfg.TenantID != "" {
		req.Header.Set("X-Tenant-ID", cfg.TenantID)
	}
	resp, err := client.Do(req)
	if probeCtx.Err() != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return StatusUnknown, "API " + label + " probe could not be verified"
	}
	if err != nil {
		return StatusFailed, "API " + label + " endpoint is unreachable"
	}
	if resp == nil {
		return StatusUnknown, "API " + label + " probe returned no response"
	}
	if resp.Body != nil {
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	}
	if probeCtx.Err() != nil {
		return StatusUnknown, "API " + label + " probe could not be verified"
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return StatusFailed, "API " + label + " endpoint returned a non-success status"
	}
	return StatusPassed, "API " + label + " endpoint is healthy"
}

func findBinary(binary string, lookPath func(string) (string, error)) (string, error) {
	if strings.TrimSpace(binary) == "" || unsafeCommand(binary) {
		return "", errors.New("invalid binary")
	}
	return lookPath(binary)
}

type agentComposeBuildInfo struct {
	Version         string   `json:"version"`
	OS              string   `json:"os"`
	Arch            string   `json:"arch"`
	CompiledDrivers []string `json:"compiled_drivers"`
}

type agentComposeStatus struct {
	Err  json.RawMessage `json:"err"`
	Msg  string          `json:"msg"`
	Data struct {
		Version         string   `json:"version"`
		OS              string   `json:"os"`
		Arch            string   `json:"arch"`
		CompiledDrivers []string `json:"compiled_drivers"`
		Timestamp       float64  `json:"timestamp"`
		Timezone        string   `json:"timezone"`
		TimezoneOffset  *int     `json:"timezone_offset"`
	} `json:"data"`
}

func probeAgentCompose(ctx context.Context, timeout time.Duration, binary string, run func(context.Context, string, ...string) ([]byte, error)) (CheckStatus, string) {
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if probeCtx.Err() != nil {
		return StatusUnknown, "agent-compose version probe could not be verified"
	}
	output, err := run(probeCtx, binary, "--json", "version")
	if probeCtx.Err() != nil {
		return StatusUnknown, "agent-compose version probe could not be verified"
	}
	if err != nil {
		return StatusFailed, "agent-compose version probe failed"
	}
	var info agentComposeBuildInfo
	if err := decodeStrictJSON(output, &info); err != nil || info.Version != agentComposeVersion || info.OS == "" || info.Arch == "" || info.CompiledDrivers == nil {
		return StatusFailed, "agent-compose version response did not match the supported contract"
	}
	for _, driver := range info.CompiledDrivers {
		if strings.TrimSpace(driver) == "" {
			return StatusFailed, "agent-compose version response did not match the supported contract"
		}
	}
	return StatusPassed, "agent-compose version matches the supported contract"
}

func validateAgentComposeDaemon(ctx context.Context, binary, host string, run func(context.Context, string, ...string) ([]byte, error)) error {
	output, err := run(ctx, binary, "--json", "--host", host, "status")
	if err != nil {
		return errors.New("agent-compose daemon status failed")
	}
	var status agentComposeStatus
	if err := decodeStrictJSON(output, &status); err != nil {
		return errors.New("invalid agent-compose daemon status")
	}
	if !bytes.Equal(bytes.TrimSpace(status.Err), []byte("null")) || status.Msg != "OK" || status.Data.Version != agentComposeVersion || status.Data.OS == "" || status.Data.Arch == "" || status.Data.CompiledDrivers == nil || status.Data.Timestamp <= 0 || status.Data.Timezone == "" || status.Data.TimezoneOffset == nil {
		return errors.New("unhealthy agent-compose daemon status")
	}
	return nil
}

const maxOctoBusStatusBodyBytes = 64 << 10

type octoBusStatus struct {
	Status   string `json:"status"`
	Services *int   `json:"services"`
}

func probeOctoBusStatus(ctx context.Context, host string, client HTTPDoer) error {
	u, err := parseURL(host, false)
	if err != nil || (u.Path != "" && u.Path != "/") {
		return errors.New("invalid OctoBus host")
	}
	u.Path = "/admin/v1/status"
	u.RawPath = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return errors.New("could not create OctoBus status request")
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("OctoBus status request failed")
	}
	if resp == nil || resp.Body == nil || resp.StatusCode != http.StatusOK {
		return errors.New("OctoBus status response was unhealthy")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOctoBusStatusBodyBytes))
	if err != nil || len(body) >= maxOctoBusStatusBodyBytes {
		return errors.New("OctoBus status response was invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	delimiter, ok := token.(json.Delim)
	if err != nil || !ok || delimiter != '{' {
		return errors.New("OctoBus status response was invalid")
	}
	var status octoBusStatus
	seen := make(map[string]bool, 2)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return errors.New("OctoBus status response was invalid")
		}
		seen[key] = true
		switch key {
		case "status":
			if err := decoder.Decode(&status.Status); err != nil {
				return errors.New("OctoBus status response was invalid")
			}
		case "services":
			var services int
			if err := decoder.Decode(&services); err != nil {
				return errors.New("OctoBus status response was invalid")
			}
			status.Services = &services
		default:
			return errors.New("OctoBus status response was invalid")
		}
	}

	token, err = decoder.Token()
	delimiter, ok = token.(json.Delim)
	if err != nil || !ok || delimiter != '}' {
		return errors.New("OctoBus status response was invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("OctoBus status response was invalid")
	}
	if status.Status != "ok" || status.Services == nil || *status.Services < 0 {
		return errors.New("OctoBus status response was unhealthy")
	}
	return nil
}

func providerModelsPath(path string) string {
	path = strings.TrimRight(path, "/")
	for _, suffix := range []string{"/responses", "/chat/completions"} {
		if strings.HasSuffix(path, suffix) {
			path = strings.TrimSuffix(path, suffix)
			break
		}
	}
	switch {
	case path == "", path == "/":
		return "/v1/models"
	case path == "/v1":
		return "/v1/models"
	case strings.HasSuffix(path, "/openai"):
		return path + "/v1/models"
	default:
		return path + "/models"
	}
}

type normalizedComposeProbe struct {
	Name   string                 `json:"name"`
	Agents []normalizedAgentProbe `json:"agents"`
}

type normalizedAgentProbe struct {
	Name     string                 `json:"name"`
	Enabled  json.RawMessage        `json:"enabled"`
	Provider string                 `json:"provider"`
	Image    string                 `json:"image"`
	Driver   *normalizedDriverProbe `json:"driver"`
}

type normalizedDriverProbe struct {
	Name         string          `json:"name"`
	Boxlite      json.RawMessage `json:"boxlite"`
	Docker       json.RawMessage `json:"docker"`
	Microsandbox json.RawMessage `json:"microsandbox"`
	K8s          json.RawMessage `json:"k8s"`
}

func validateNormalizedCompose(ctx context.Context, binary, path, expectedGuestImage string, run func(context.Context, string, ...string) ([]byte, error)) (ComposeValidation, error) {
	output, err := run(ctx, binary, "--json", "--file", path, "config")
	if err != nil {
		return ComposeValidation{}, errors.New("agent-compose config validation failed")
	}
	return parseNormalizedCompose(output, expectedGuestImage)
}

func parseNormalizedCompose(data []byte, expectedGuestImage string) (ComposeValidation, error) {
	if len(data) == 0 || len(data) > maxCommandOutputBytes {
		return ComposeValidation{}, errors.New("invalid normalized compose JSON size")
	}
	var compose normalizedComposeProbe
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&compose); err != nil {
		return ComposeValidation{}, errors.New("invalid normalized compose JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ComposeValidation{}, errors.New("multiple normalized compose JSON values")
	}
	if strings.TrimSpace(compose.Name) == "" {
		return ComposeValidation{}, errors.New("normalized compose has no name")
	}
	if len(compose.Agents) == 0 {
		return ComposeValidation{}, errors.New("normalized compose has no agents")
	}
	seen := make(map[string]struct{}, len(compose.Agents))
	validation := ComposeValidation{Complete: true, ProviderConfigured: true}
	expectedImage := strings.TrimSpace(expectedGuestImage)
	enabled := 0
	for _, agent := range compose.Agents {
		name := strings.TrimSpace(agent.Name)
		if name == "" {
			return ComposeValidation{}, errors.New("normalized compose has an empty agent name")
		}
		if _, exists := seen[name]; exists {
			return ComposeValidation{}, errors.New("normalized compose has duplicate agent names")
		}
		seen[name] = struct{}{}
		if agent.Driver == nil || strings.TrimSpace(agent.Driver.Name) == "" {
			return ComposeValidation{}, errors.New("normalized compose agent has no driver name")
		}
		if err := validateNormalizedDriver(agent.Driver); err != nil {
			return ComposeValidation{}, err
		}
		enabledValue, err := normalizedBool(agent.Enabled)
		if err != nil {
			return ComposeValidation{}, err
		}
		if !enabledValue {
			continue
		}
		enabled++
		if strings.TrimSpace(agent.Provider) == "" {
			validation.ProviderConfigured = false
		}
		if !normalizedImageMatchesConfigured(agent.Image, expectedImage) {
			return ComposeValidation{}, errors.New("enabled normalized compose agent image does not match configured guest image")
		}
		if agent.Driver.Name == "docker" {
			validation.UsesDocker = true
		}
	}
	if enabled == 0 {
		return ComposeValidation{}, errors.New("normalized compose has no enabled agents")
	}
	return validation, nil
}

func validateNormalizedDriver(driver *normalizedDriverProbe) error {
	known := []struct {
		name string
		raw  json.RawMessage
	}{
		{"boxlite", driver.Boxlite},
		{"docker", driver.Docker},
		{"microsandbox", driver.Microsandbox},
		{"k8s", driver.K8s},
	}
	found := false
	for _, item := range known {
		if item.name == driver.Name {
			if !jsonObject(item.raw) {
				return errors.New("normalized compose driver subobject does not match driver name")
			}
			found = true
			continue
		}
		if !jsonAbsentOrNull(item.raw) {
			return errors.New("normalized compose has mismatched driver subobject")
		}
	}
	if !found {
		return errors.New("normalized compose has an unsupported driver")
	}
	return nil
}

func normalizedBool(raw json.RawMessage) (bool, error) {
	if len(raw) == 0 {
		return false, errors.New("normalized compose agent is missing enabled")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false, errors.New("normalized compose agent enabled is null")
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, errors.New("normalized compose agent enabled is not boolean")
	}
	return value, nil
}

func jsonObject(raw json.RawMessage) bool {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return false
	}
	return object != nil
}

func normalizedImageMatchesConfigured(normalized, expected string) bool {
	normalized = strings.TrimSpace(normalized)
	expected = strings.TrimSpace(expected)
	return expected != "" && (normalized == expected || normalized == "${AGENT_COMPOSE_GUEST_IMAGE}")
}

func jsonAbsentOrNull(raw json.RawMessage) bool {
	return len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func validateCompose(ctx context.Context, timeout time.Duration, binary, path string, data []byte, cfg Config, deps Dependencies) (CheckStatus, string, ComposeValidation) {
	if err := unresolvedInterpolation(data, cfg); err != nil {
		return StatusFailed, "compose interpolation could not be resolved", ComposeValidation{}
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if probeCtx.Err() != nil {
		return StatusUnknown, "compose configuration validation could not be completed", ComposeValidation{}
	}
	var validation ComposeValidation
	var err error
	if deps.ValidateCompose != nil {
		validation, err = deps.ValidateCompose(probeCtx, binary, path)
	} else {
		validation, err = validateNormalizedCompose(probeCtx, binary, path, cfg.GuestImage, deps.RunCommand)
	}
	if probeCtx.Err() != nil {
		return StatusUnknown, "compose configuration validation could not be completed", ComposeValidation{}
	}
	if err != nil {
		return StatusFailed, "compose configuration validation failed", ComposeValidation{}
	}
	if !validation.Complete {
		return StatusUnknown, "complete compose configuration validation was not available", ComposeValidation{}
	}
	return StatusPassed, "compose configuration was validated", validation
}

type cappedOutput struct {
	bytes.Buffer
	overflow bool
}

func (b *cappedOutput) Write(p []byte) (int, error) {
	written := len(p)
	remaining := maxCommandOutputBytes - b.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.Buffer.Write(p[:remaining])
		} else {
			_, _ = b.Buffer.Write(p)
		}
	}
	if len(p) > remaining {
		b.overflow = true
	}
	return written, nil
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var output cappedOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	if output.overflow {
		return nil, errors.New("command output exceeded diagnostic limit")
	}
	return output.Bytes(), nil
}

func decodeStrictJSON(data []byte, target any) error {
	if len(data) == 0 || len(data) > maxCommandOutputBytes {
		return errors.New("invalid JSON size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

type proxySandboxOutput struct {
	SandboxID                string                           `json:"sandbox_id"`
	SandboxShortID           string                           `json:"sandbox_short_id,omitempty"`
	Title                    string                           `json:"title,omitempty"`
	Driver                   string                           `json:"driver,omitempty"`
	VMStatus                 string                           `json:"vm_status,omitempty"`
	WorkspacePath            string                           `json:"workspace_path,omitempty"`
	ProxyPath                string                           `json:"proxy_path,omitempty"`
	GuestImage               string                           `json:"guest_image,omitempty"`
	TriggerSource            string                           `json:"trigger_source,omitempty"`
	CreatedAt                string                           `json:"created_at,omitempty"`
	UpdatedAt                string                           `json:"updated_at,omitempty"`
	CellCount                uint32                           `json:"cell_count"`
	EventCount               uint32                           `json:"event_count"`
	Tags                     map[string]string                `json:"tags,omitempty"`
	WorkspaceReclamation     *proxyWorkspaceReclamationOutput `json:"workspace_reclamation,omitempty"`
	StoppedRuntimePolicy     string                           `json:"stopped_runtime_policy"`
	StoppedRuntimeState      string                           `json:"stopped_runtime_state"`
	StoppedRuntimeError      string                           `json:"stopped_runtime_last_error,omitempty"`
	StoppedRuntimeReleasedAt string                           `json:"stopped_runtime_released_at,omitempty"`
}

type proxyWorkspaceReclamationOutput struct {
	State       string `json:"state"`
	StartedAt   string `json:"started_at,omitempty"`
	CompletedAt string `json:"completed_at,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}

type proxyExecOutput struct {
	ExecID    string   `json:"exec_id"`
	SandboxID string   `json:"sandbox_id"`
	RunID     string   `json:"run_id,omitempty"`
	Command   string   `json:"command"`
	Args      []string `json:"args,omitempty"`
	Cwd       string   `json:"cwd,omitempty"`
	ExitCode  *int32   `json:"exit_code"`
	Success   *bool    `json:"success"`
	Stdout    string   `json:"stdout,omitempty"`
	Stderr    string   `json:"stderr,omitempty"`
	Output    string   `json:"output,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type proxyCalculatorResponse struct {
	Result     *float64 `json:"result"`
	ServiceID  string   `json:"serviceId"`
	InstanceID string   `json:"instanceId"`
	Label      string   `json:"label"`
}

type proxySandboxListOutput struct {
	Project   json.RawMessage        `json:"project"`
	Sandboxes []proxySandboxListItem `json:"sandboxes"`
}

type proxySandboxListItem struct {
	SandboxID            string `json:"sandbox_id"`
	SandboxShortID       string `json:"sandbox_short_id"`
	Agent                string `json:"agent"`
	Status               string `json:"status"`
	RunID                string `json:"run_id,omitempty"`
	RunShortID           string `json:"run_short_id,omitempty"`
	CreatedAt            string `json:"created_at,omitempty"`
	UpdatedAt            string `json:"updated_at,omitempty"`
	Driver               string `json:"driver,omitempty"`
	Image                string `json:"image,omitempty"`
	Workspace            string `json:"workspace,omitempty"`
	StoppedRuntimePolicy string `json:"stopped_runtime_policy,omitempty"`
	StoppedRuntimeState  string `json:"stopped_runtime_state,omitempty"`
}

type proxyProjectOutput struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	ShortID         string `json:"short_id"`
	SourcePath      string `json:"source_path"`
	CurrentRevision uint64 `json:"current_revision"`
	SpecHash        string `json:"spec_hash"`
	AgentCount      uint32 `json:"agent_count"`
	SchedulerCount  uint32 `json:"scheduler_count"`
}

func inspectProxyAgent(ctx context.Context, cfg ProxyProbeConfig, run func(context.Context, string, ...string) ([]byte, error)) error {
	args := []string{"--json", "--host", cfg.AgentComposeHost, "--project-name", proxyProbeProject, "sandbox", "ls"}
	data, err := run(ctx, cfg.Binary, args...)
	if err != nil {
		return errors.New("agent-compose probe sandbox listing failed")
	}
	var output proxySandboxListOutput
	if err := decodeStrictJSON(data, &output); err != nil {
		return errors.New("agent-compose probe sandbox listing returned invalid JSON")
	}
	var project proxyProjectOutput
	if err := decodeStrictJSON(output.Project, &project); err != nil || project.Name != proxyProbeProject || strings.TrimSpace(project.ID) == "" {
		return errors.New("agent-compose probe sandbox listing returned the wrong project")
	}
	if len(output.Sandboxes) != 1 {
		return errors.New("agent-compose probe sandbox listing returned the wrong sandbox set")
	}
	sandbox := output.Sandboxes[0]
	if sandbox.SandboxID != cfg.SandboxID || sandbox.Agent != "probe" || sandbox.Status != "running" || sandbox.Driver != "docker" || sandbox.Image != cfg.GuestImage || sandbox.StoppedRuntimeState != "retained" {
		return errors.New("agent-compose probe sandbox listing did not match the fixed project binding")
	}
	return nil
}

func octoBusProxyProbe(run func(context.Context, string, ...string) ([]byte, error)) func(context.Context, ProxyProbeConfig) error {
	return func(ctx context.Context, cfg ProxyProbeConfig) error {
		common := []string{"--json", "--host", cfg.AgentComposeHost, "--project-name", proxyProbeProject}
		if err := inspectProxyAgent(ctx, cfg, run); err != nil {
			return err
		}
		inspectArgs := append(append([]string(nil), common...), "inspect", "sandbox", cfg.SandboxID)
		data, err := run(ctx, cfg.Binary, inspectArgs...)
		if err != nil {
			return errors.New("agent-compose sandbox inspection failed")
		}
		var sandbox proxySandboxOutput
		if err := decodeStrictJSON(data, &sandbox); err != nil {
			return errors.New("agent-compose sandbox inspection returned invalid JSON")
		}
		if sandbox.SandboxID != cfg.SandboxID || sandbox.VMStatus != "running" || sandbox.Driver != "docker" || sandbox.GuestImage != cfg.GuestImage || sandbox.Tags["capset"] != "dev" || sandbox.StoppedRuntimeState != "retained" {
			return errors.New("agent-compose sandbox does not match the fixed live probe contract")
		}
		execArgs := append(append([]string(nil), common...), "exec", cfg.SandboxID, "--command", proxyProbeCommand)
		data, err = run(ctx, cfg.Binary, execArgs...)
		if err != nil {
			return errors.New("agent-compose live proxy execution failed")
		}
		var result proxyExecOutput
		if err := decodeStrictJSON(data, &result); err != nil {
			return errors.New("agent-compose live proxy execution returned invalid JSON")
		}
		if strings.TrimSpace(result.ExecID) == "" || result.SandboxID != cfg.SandboxID || result.Success == nil || !*result.Success || result.ExitCode == nil || *result.ExitCode != 0 || result.Command != "bash" || len(result.Args) != 2 || result.Args[0] != "-lc" || result.Args[1] != proxyProbeCommand || result.Stderr != "" || result.Error != "" {
			return errors.New("agent-compose live proxy execution did not satisfy the fixed command contract")
		}
		for _, output := range []string{result.Stdout, result.Output} {
			var response proxyCalculatorResponse
			if err := decodeStrictJSON([]byte(output), &response); err != nil || response.Result == nil || *response.Result != 42 || response.ServiceID != "sas101-calculator" || response.InstanceID != "calculator-test" || response.Label != "sas101" {
				return errors.New("agent-compose live proxy response was invalid")
			}
		}
		return nil
	}
}

func inspectDockerImage(ctx context.Context, binary, image string, run func(context.Context, string, ...string) ([]byte, error)) error {
	output, err := run(ctx, binary, "image", "inspect", "--format", "{{.Id}}", image)
	if err != nil {
		return errors.New("Docker image inspect failed")
	}
	id := strings.TrimSpace(string(output))
	if len(id) != len("sha256:")+64 || !strings.HasPrefix(id, "sha256:") {
		return errors.New("Docker image inspect returned an invalid image ID")
	}
	for _, c := range id[len("sha256:"):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return errors.New("Docker image inspect returned an invalid image ID")
		}
	}
	return nil
}

func unresolvedInterpolation(data []byte, cfg Config) error {
	text := string(data)
	for from := 0; ; {
		start := strings.Index(text[from:], "${")
		if start < 0 {
			return nil
		}
		start += from
		end := strings.IndexByte(text[start+2:], '}')
		if end < 0 {
			return errors.New("unterminated interpolation")
		}
		end += start + 2
		expr := text[start+2 : end]
		nameEnd := strings.IndexAny(expr, ":+-?")
		name := expr
		operator := ""
		if nameEnd >= 0 {
			name, operator = expr[:nameEnd], expr[nameEnd:]
		}
		name = strings.TrimSpace(name)
		if !validEnvName(name) || strings.TrimSpace(composeValue(cfg, name)) == "" {
			fallback := ""
			switch {
			case strings.HasPrefix(operator, ":-"):
				fallback = operator[2:]
			case strings.HasPrefix(operator, "-"):
				fallback = operator[1:]
			}
			if strings.TrimSpace(fallback) == "" || strings.Contains(fallback, "${") {
				return errors.New("unresolved interpolation")
			}
		}
		from = end + 1
	}
}

func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i := range name {
		if c := name[i]; (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9' || i == 0) && c != '_' {
			return false
		}
	}
	return true
}

func composeValue(cfg Config, name string) string {
	switch name {
	case "AGENT_COMPOSE_GUEST_IMAGE":
		return cfg.GuestImage
	case "SAS_AGENT_MODEL", "SAS_REPORT_MODEL", "SAS_STRONG_AGENT_MODEL":
		return cfg.Models[name]
	default:
		return cfg.Providers[name]
	}
}

func probeProvider(ctx context.Context, timeout time.Duration, probe func(context.Context, map[string]string) error, providers map[string]string) (CheckStatus, string) {
	if probe == nil {
		return StatusUnknown, "provider connectivity could not be verified"
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if probeCtx.Err() != nil {
		return StatusUnknown, "provider connectivity could not be verified"
	}
	err := probe(probeCtx, providers)
	if probeCtx.Err() != nil {
		return StatusUnknown, "provider connectivity could not be verified"
	}
	if err != nil {
		return StatusFailed, "provider connectivity probe failed"
	}
	return StatusPassed, "provider connectivity was verified"
}
func addProtocolCheck(add func(string, bool, CheckStatus, string), name, label, raw string, configOK bool, probe func(context.Context, string) error, timeout time.Duration, ctx context.Context) {
	if !configOK || !validHost(raw) || probe == nil {
		add(name, true, StatusUnknown, label+" protocol health could not be verified")
		return
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if probeCtx.Err() != nil {
		add(name, true, StatusUnknown, label+" protocol health could not be verified")
		return
	}
	err := probe(probeCtx, raw)
	if probeCtx.Err() != nil {
		add(name, true, StatusUnknown, label+" protocol health could not be verified")
		return
	}
	if err != nil {
		add(name, true, StatusFailed, label+" protocol health probe failed")
		return
	}
	add(name, true, StatusPassed, label+" protocol health was verified")
}

func validHost(raw string) bool {
	_, err := parseURL(raw, false)
	return err == nil
}

func probeDNS(ctx context.Context, timeout time.Duration, hosts []string, probe func(context.Context, string) error) (CheckStatus, string) {
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if probeCtx.Err() != nil {
		return StatusUnknown, "network DNS could not be verified"
	}
	for _, host := range hosts {
		if _, err := parseURL(host, false); err != nil {
			return StatusFailed, "network DNS configuration is malformed"
		}
	}
	for _, host := range hosts {
		if probeCtx.Err() != nil {
			return StatusUnknown, "network DNS could not be verified"
		}
		u, _ := parseURL(host, false)
		err := probe(probeCtx, u.Hostname())
		if probeCtx.Err() != nil {
			return StatusUnknown, "network DNS could not be verified"
		}
		if err != nil {
			return StatusFailed, "network DNS probe failed"
		}
	}
	return StatusPassed, "network DNS was verified"
}

func probeProxy(ctx context.Context, timeout time.Duration, cfg ProxyProbeConfig, probe func(context.Context, ProxyProbeConfig) error) (CheckStatus, string) {
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if probeCtx.Err() != nil {
		return StatusUnknown, "live Sandbox to OctoBus proxy synthetic Add could not be verified"
	}
	err := probe(probeCtx, cfg)
	if probeCtx.Err() != nil {
		return StatusUnknown, "live Sandbox to OctoBus proxy synthetic Add could not be verified"
	}
	if err != nil {
		return StatusFailed, "live Sandbox to OctoBus proxy synthetic Add probe failed"
	}
	return StatusPassed, "live Sandbox to OctoBus proxy synthetic Add returned 42"
}

func probeHost(ctx context.Context, timeout time.Duration, raw string, dial func(context.Context, string, string) (net.Conn, error), label string) (CheckStatus, string) {
	u, err := parseURL(raw, false)
	if err != nil {
		return StatusFailed, label + " host configuration is malformed"
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if probeCtx.Err() != nil {
		return StatusUnknown, label + " TCP endpoint could not be verified"
	}
	conn, err := dial(probeCtx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if probeCtx.Err() != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return StatusUnknown, label + " TCP endpoint could not be verified"
	}
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return StatusFailed, label + " TCP endpoint is unreachable"
	}
	if conn == nil {
		return StatusUnknown, label + " TCP probe returned no connection"
	}
	_ = conn.Close()
	if probeCtx.Err() != nil {
		return StatusUnknown, label + " TCP endpoint could not be verified"
	}
	return StatusPassed, label + " TCP endpoint is reachable"
}

func probeDocker(ctx context.Context, timeout time.Duration, binary, image string, deps Dependencies) (CheckStatus, string) {
	resolved, err := findBinary(binary, deps.LookPath)
	if err != nil || resolved == "" {
		return StatusFailed, "Docker binary was not found"
	}
	if deps.DockerInspect == nil {
		return StatusUnknown, "Docker guest image could not be inspected"
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if probeCtx.Err() != nil {
		return StatusUnknown, "Docker daemon and guest image could not be verified"
	}
	_, err = deps.RunCommand(probeCtx, resolved, "version")
	if probeCtx.Err() != nil {
		return StatusUnknown, "Docker daemon and guest image could not be verified"
	}
	if err != nil {
		return StatusFailed, "Docker is unavailable or its daemon is not reachable"
	}
	err = deps.DockerInspect(probeCtx, resolved, image)
	if probeCtx.Err() != nil {
		return StatusUnknown, "Docker daemon and guest image could not be verified"
	}
	if err != nil {
		return StatusFailed, "Docker guest image could not be inspected"
	}
	return StatusPassed, "Docker daemon and guest image are verifiable"
}

func inspectCompose(path string, read func(string) ([]byte, error)) ([]byte, error) {
	if strings.TrimSpace(path) == "" || unsafeText(path) {
		return nil, errors.New("invalid compose path")
	}
	data, err := read(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maxComposeBytes || !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
		return nil, errors.New("invalid compose contents")
	}
	return data, nil
}

func readFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("compose path is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxComposeBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxComposeBytes {
		return nil, errors.New("compose file exceeds diagnostic limit")
	}
	return data, nil
}

func checkModels(models map[string]string) (CheckStatus, string) {
	for _, name := range []string{"SAS_AGENT_MODEL", "SAS_REPORT_MODEL", "SAS_STRONG_AGENT_MODEL"} {
		value := strings.TrimSpace(models[name])
		if value == "" {
			return StatusFailed, "one or more required model settings are missing"
		}
		if unsafeText(value) || strings.Contains(value, "${") {
			return StatusFailed, "one or more configured model settings are unsafe"
		}
	}
	return StatusPassed, "required model settings are configured"
}

func checkImage(image string) (CheckStatus, string) {
	value := strings.TrimSpace(image)
	if value == "" {
		return StatusFailed, "guest image is not configured"
	}
	if len(value) > 512 || unsafeCommand(value) || strings.ContainsAny(value, " \t") {
		return StatusFailed, "guest image configuration is malformed or unsafe"
	}
	if strings.Contains(value, "@") {
		if !validSHA256ImageDigest(value) {
			return StatusFailed, "guest image digest is malformed or unsupported"
		}
		return StatusPassed, "guest image uses an explicit sha256 digest"
	}
	lastSegment := value[strings.LastIndex(value, "/")+1:]
	tagSeparator := strings.LastIndex(lastSegment, ":")
	if tagSeparator <= 0 || tagSeparator == len(lastSegment)-1 || lastSegment[tagSeparator+1:] == "latest" {
		return StatusFailed, "guest image must use an explicit non-latest tag or sha256 digest"
	}
	return StatusPassed, "guest image uses an explicit non-latest tag"
}

func validSHA256ImageDigest(value string) bool {
	name, digest, found := strings.Cut(value, "@")
	if !found || name == "" || strings.Contains(digest, "@") || !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
		return false
	}
	for _, char := range digest[len("sha256:"):] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func checkProviders(providers map[string]string, composeKnown, composeProvider bool) (CheckStatus, string) {
	for _, value := range providers {
		if strings.TrimSpace(value) == "" || unsafeText(value) || len(value) > 128 || strings.Contains(value, "${") {
			return StatusFailed, "provider setting is malformed or unsafe"
		}
	}
	if composeKnown && !composeProvider {
		return StatusFailed, "enabled compose agent provider declaration is missing"
	}
	if len(providers) == 0 && !composeProvider {
		return StatusUnknown, "provider declarations could not be confirmed"
	}
	return StatusPassed, "provider declarations present; connectivity not verified"
}

func aggregate(checks []Check) OverallStatus {
	degraded := false
	for _, c := range checks {
		if c.Required && c.Status != StatusPassed {
			return OverallFailed
		}
		if !c.Required && (c.Status == StatusFailed || c.Status == StatusUnknown) {
			degraded = true
		}
	}
	if degraded {
		return OverallDegraded
	}
	return OverallPassed
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}
