package doctor

import (
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
	APIBaseURL       string
	APIKey           string
	TenantID         string
	Executor         string
	AgentComposeBin  string
	AgentComposeFile string
	AgentComposeHost string
	DockerBin        string
	OctoBusHost      string
	GuestImage       string
	Models           map[string]string
	Providers        map[string]string
	Timeout          time.Duration
}

const (
	defaultTimeout  = 5 * time.Second
	maxTimeout      = 30 * time.Second
	maxComposeBytes = 1 << 20
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
		Executor:         envOr("SAS_EXECUTOR", "mock"),
		AgentComposeBin:  envOr("SAS_AGENT_COMPOSE_BIN", "agent-compose"),
		AgentComposeFile: envOr("SAS_AGENT_COMPOSE_FILE", "./agent-compose.yml"),
		AgentComposeHost: strings.TrimSpace(os.Getenv("SAS_AGENT_COMPOSE_HOST")),
		DockerBin:        envOr("SAS_DOCKER_BIN", "docker"),
		OctoBusHost:      firstEnv("SAS_OCTOBUS_HOST", "SAS_OCTOBUS_URL", "OCTOBUS_HOST", "OCTOBUS_URL", "AGENT_COMPOSE_OCTOBUS_HOST"),
		GuestImage:       strings.TrimSpace(os.Getenv("AGENT_COMPOSE_GUEST_IMAGE")),
		Models: map[string]string{
			"SAS_AGENT_MODEL":        strings.TrimSpace(os.Getenv("SAS_AGENT_MODEL")),
			"SAS_REPORT_MODEL":       strings.TrimSpace(os.Getenv("SAS_REPORT_MODEL")),
			"SAS_STRONG_AGENT_MODEL": strings.TrimSpace(os.Getenv("SAS_STRONG_AGENT_MODEL")),
		},
		Providers: providers, Timeout: defaultTimeout,
	}
}

type Dependencies struct {
	HTTPClient  HTTPDoer
	LookPath    func(string) (string, error)
	RunCommand  func(context.Context, string, ...string) error
	ReadFile    func(string) ([]byte, error)
	DialContext func(context.Context, string, string) (net.Conn, error)
}

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func Run(ctx context.Context, cfg Config) Report {
	return RunWithDependencies(ctx, cfg, Dependencies{})
}

func RunWithDependencies(ctx context.Context, cfg Config, deps Dependencies) Report {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg = normalize(cfg)
	deps = fillDefaults(deps)
	report := Report{Checks: make([]Check, 0, 13)}
	add := func(name string, required bool, status CheckStatus, message string) {
		report.Checks = append(report.Checks, Check{Name: name, Status: status, Message: message, Required: required})
	}

	configOK := validateConfig(cfg) == nil
	if configOK {
		add("configuration", true, StatusPassed, "configuration is valid")
	} else {
		add("configuration", true, StatusFailed, "configuration is malformed or contains unsafe characters")
	}

	base, baseErr := parseURL(cfg.APIBaseURL, true)
	if baseErr != nil {
		add("api_base_url", true, StatusFailed, "API base URL is malformed or uses an unsupported scheme")
		add("api_health", true, StatusSkipped, "API health probe skipped because the base URL is invalid")
		add("api_readiness", true, StatusSkipped, "API readiness probe skipped because the base URL is invalid")
	} else {
		add("api_base_url", true, StatusPassed, "API base URL is valid")
		for _, p := range []struct{ name, path, label string }{{"api_health", "/healthz", "health"}, {"api_readiness", "/readyz", "readiness"}} {
			if !configOK {
				add(p.name, true, StatusUnknown, "API "+p.label+" probe skipped because configuration is unsafe")
				continue
			}
			status, message := probeAPI(ctx, cfg, deps.HTTPClient, base, p.path, p.label)
			add(p.name, true, status, message)
		}
	}

	switch {
	case !configOK:
		addIntegration(add, cfg.Executor == "agentcompose-cli", StatusUnknown, "integration checks skipped because configuration is unsafe")
	case cfg.Executor == "mock":
		addIntegration(add, false, StatusSkipped, "integration is optional in mock executor mode")
	case cfg.Executor == "agentcompose-cli":
		compose, composeErr := inspectCompose(cfg.AgentComposeFile, deps.ReadFile)
		if composeErr != nil {
			add("compose_file", true, StatusFailed, "configured compose file is missing, unreadable, or malformed")
		} else {
			add("compose_file", true, StatusPassed, "configured compose file exists and is readable")
		}

		binary, binaryErr := findBinary(cfg.AgentComposeBin, deps.LookPath)
		if binaryErr != nil {
			add("agent_compose_binary", true, StatusFailed, "agent-compose binary was not found")
			add("agent_compose_version", true, StatusSkipped, "agent-compose version/help probe skipped because the binary is unavailable")
		} else {
			add("agent_compose_binary", true, StatusPassed, "agent-compose binary is available")
			status, message := probeAgentCompose(ctx, cfg.Timeout, binary, deps.RunCommand)
			add("agent_compose_version", true, status, message)
		}
		status, message := checkModels(cfg.Models)
		add("model_settings", true, status, message)
		status, message = checkImage(cfg.GuestImage)
		add("guest_image", true, status, message)
		status, message = checkProviders(cfg.Providers, compose.provider)
		add("provider_settings", true, status, message)
		switch {
		case composeErr != nil:
			add("docker", true, StatusUnknown, "Docker applicability could not be determined from the compose file")
		case !compose.docker:
			add("docker", false, StatusSkipped, "Docker check skipped because the compose file does not declare a Docker driver")
		default:
			status, message = probeDocker(ctx, cfg.Timeout, cfg.DockerBin, deps)
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
		if strings.TrimSpace(h.raw) == "" {
			message := h.label + " host is not configured"
			if h.name == "agent_compose_host" {
				message += "; local mode assumed"
			}
			add(h.name, false, StatusSkipped, message)
		} else if !configOK {
			add(h.name, h.required, StatusUnknown, h.label+" host probe skipped because configuration is unsafe")
		} else {
			status, message := probeHost(ctx, cfg.Timeout, h.raw, deps.DialContext, h.label)
			add(h.name, h.required, status, message)
		}
	}
	report.Overall = aggregate(report.Checks)
	return report
}

func addIntegration(add func(string, bool, CheckStatus, string), required bool, status CheckStatus, message string) {
	for _, name := range []string{"agent_compose_binary", "agent_compose_version", "compose_file", "docker", "model_settings", "guest_image", "provider_settings"} {
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
	return deps
}

func DefaultDependencies() Dependencies {
	return Dependencies{
		HTTPClient: &http.Client{Timeout: defaultTimeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }},
		LookPath:   exec.LookPath,
		RunCommand: func(ctx context.Context, name string, args ...string) error {
			cmd := exec.CommandContext(ctx, name, args...)
			cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
			return cmd.Run()
		},
		ReadFile:    readFile,
		DialContext: (&net.Dialer{Timeout: defaultTimeout}).DialContext,
	}
}

func validateConfig(cfg Config) error {
	if cfg.Executor != "mock" && cfg.Executor != "agentcompose-cli" {
		return errors.New("unsupported executor")
	}
	if unsafeCommand(cfg.AgentComposeBin) || unsafeCommand(cfg.DockerBin) {
		return errors.New("unsafe command")
	}
	for _, value := range []string{cfg.APIKey, cfg.TenantID, cfg.AgentComposeFile, cfg.AgentComposeHost, cfg.OctoBusHost, cfg.GuestImage} {
		if unsafeText(value) {
			return errors.New("unsafe text")
		}
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

func unsafeCommand(value string) bool {
	return unsafeText(value) || strings.ContainsAny(value, ";|&$`()<>")
}

func parseURL(raw string, requireScheme bool) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || unsafeText(raw) {
		return nil, errors.New("empty or unsafe URL")
	}
	if !requireScheme && !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" || (requireScheme && u.Scheme == "") {
		return nil, errors.New("malformed URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("unsupported URL scheme")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(u.Host, ":") {
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
	if err != nil {
		return probeError(probeCtx, "API "+label+" endpoint is unreachable")
	}
	if resp == nil {
		return StatusUnknown, "API " + label + " probe returned no response"
	}
	if resp.Body != nil {
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
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

func probeAgentCompose(ctx context.Context, timeout time.Duration, binary string, run func(context.Context, string, ...string) error) (CheckStatus, string) {
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if run(probeCtx, binary, "--version") == nil {
		return StatusPassed, "agent-compose version probe succeeded"
	}
	if probeCtx.Err() != nil {
		return probeError(probeCtx, "agent-compose version/help probe timed out")
	}
	if run(probeCtx, binary, "--help") == nil {
		return StatusPassed, "agent-compose help probe succeeded"
	}
	if probeCtx.Err() != nil {
		return probeError(probeCtx, "agent-compose version/help probe timed out")
	}
	return StatusFailed, "agent-compose did not respond to a version or help probe"
}

func probeDocker(ctx context.Context, timeout time.Duration, binary string, deps Dependencies) (CheckStatus, string) {
	resolved, err := findBinary(binary, deps.LookPath)
	if err != nil || resolved == "" {
		return StatusFailed, "Docker binary was not found"
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := deps.RunCommand(probeCtx, resolved, "version"); err != nil {
		if probeCtx.Err() != nil {
			return probeError(probeCtx, "Docker daemon probe timed out")
		}
		return StatusFailed, "Docker is unavailable or its daemon is not reachable"
	}
	return StatusPassed, "Docker client and daemon are available"
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
	conn, err := dial(probeCtx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return probeError(probeCtx, label+" host is unreachable")
	}
	_ = conn.Close()
	return StatusPassed, label + " host is reachable"
}

func probeError(ctx context.Context, message string) (CheckStatus, string) {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
		return StatusUnknown, message
	}
	return StatusFailed, message
}

type composeInfo struct {
	docker   bool
	provider bool
}

func inspectCompose(path string, read func(string) ([]byte, error)) (composeInfo, error) {
	if strings.TrimSpace(path) == "" || unsafeText(path) {
		return composeInfo{}, errors.New("invalid compose path")
	}
	data, err := read(path)
	if err != nil {
		return composeInfo{}, err
	}
	if len(data) == 0 || len(data) > maxComposeBytes || !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
		return composeInfo{}, errors.New("invalid compose contents")
	}
	var info composeInfo
	inAgents, sawAgents := false, false
	agentsIndent, agentIndent := -1, -1
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		if line == "agents:" {
			inAgents, sawAgents, agentsIndent = true, true, indent
			continue
		}
		if inAgents && indent <= agentsIndent {
			inAgents = false
		}
		if !inAgents {
			continue
		}
		if agentIndent < 0 {
			agentIndent = indent
			continue
		}
		if indent == agentIndent+2 && strings.HasPrefix(line, "provider:") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "provider:"))
			info.provider = info.provider || (value != "" && !strings.Contains(value, "${"))
		}
		if indent > agentIndent && strings.HasPrefix(line, "docker:") {
			info.docker = true
		}
	}
	if !sawAgents || !info.provider {
		return composeInfo{}, errors.New("compose does not declare an agent provider")
	}
	return info, nil
}

func readFile(path string) ([]byte, error) {
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
	return StatusPassed, "guest image is configured"
}

func checkProviders(providers map[string]string, composeProvider bool) (CheckStatus, string) {
	if !composeProvider && len(providers) == 0 {
		return StatusFailed, "no provider setting is configured"
	}
	for _, value := range providers {
		if strings.TrimSpace(value) == "" || unsafeText(value) || len(value) > 128 || strings.Contains(value, "${") {
			return StatusFailed, "provider setting is malformed or unsafe"
		}
	}
	return StatusPassed, "provider settings are configured; provider connectivity was not probed"
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
