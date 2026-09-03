package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr                string
	APIKey              string
	Executor            string
	StateDir            string
	ArtifactDir         string
	AgentCatalogPath    string
	Workers             int
	QueueSize           int
	RunTimeout          time.Duration
	ShutdownTimeout     time.Duration
	MaxBodyBytes        int64
	RateLimitPerMinute  int
	LogLevel            slog.Level
	AgentComposeBin     string
	AgentComposeFile    string
	AgentComposeHost    string
	AgentComposeProject string
	AgentComposeTimeout time.Duration
	RemoveSandbox       bool
}

func Load() (Config, error) {
	cfg := Config{
		Addr:                env("SAS_ADDR", ":8080"),
		APIKey:              os.Getenv("SAS_API_KEY"),
		Executor:            env("SAS_EXECUTOR", "mock"),
		StateDir:            env("SAS_STATE_DIR", "./var/state"),
		ArtifactDir:         env("SAS_ARTIFACT_DIR", "./var/artifacts"),
		AgentCatalogPath:    env("SAS_AGENT_CATALOG", "./configs/agents.json"),
		AgentComposeBin:     env("SAS_AGENT_COMPOSE_BIN", "agent-compose"),
		AgentComposeFile:    env("SAS_AGENT_COMPOSE_FILE", "./agent-compose.yml"),
		AgentComposeHost:    os.Getenv("SAS_AGENT_COMPOSE_HOST"),
		AgentComposeProject: env("SAS_AGENT_COMPOSE_PROJECT", "security-agent-suite"),
	}

	var err error
	if cfg.Workers, err = envInt("SAS_WORKERS", 3, 1, 64); err != nil {
		return Config{}, err
	}
	if cfg.QueueSize, err = envInt("SAS_QUEUE_SIZE", 128, 1, 10000); err != nil {
		return Config{}, err
	}
	if cfg.RateLimitPerMinute, err = envInt("SAS_RATE_LIMIT_PER_MINUTE", 120, 1, 100000); err != nil {
		return Config{}, err
	}
	if cfg.MaxBodyBytes, err = envInt64("SAS_MAX_BODY_BYTES", 1<<20, 1024, 64<<20); err != nil {
		return Config{}, err
	}
	if cfg.RunTimeout, err = envDuration("SAS_RUN_TIMEOUT", 30*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.ShutdownTimeout, err = envDuration("SAS_SHUTDOWN_TIMEOUT", 15*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.AgentComposeTimeout, err = envDuration("SAS_AGENT_COMPOSE_TIMEOUT", 35*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.RemoveSandbox, err = envBool("SAS_AGENT_COMPOSE_REMOVE_SANDBOX", true); err != nil {
		return Config{}, err
	}
	if cfg.LogLevel, err = parseLogLevel(env("SAS_LOG_LEVEL", "info")); err != nil {
		return Config{}, err
	}

	switch cfg.Executor {
	case "mock", "agentcompose-cli":
	default:
		return Config{}, fmt.Errorf("SAS_EXECUTOR must be mock or agentcompose-cli, got %q", cfg.Executor)
	}
	return cfg, nil
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback, min, max int) (int, error) {
	value := env(key, strconv.Itoa(fallback))
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < min || parsed > max {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", key, min, max)
	}
	return parsed, nil
}

func envInt64(key string, fallback, min, max int64) (int64, error) {
	value := env(key, strconv.FormatInt(fallback, 10))
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < min || parsed > max {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", key, min, max)
	}
	return parsed, nil
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	value := env(key, fallback.String())
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive Go duration", key)
	}
	return parsed, nil
}

func envBool(key string, fallback bool) (bool, error) {
	value := env(key, strconv.FormatBool(fallback))
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", key)
	}
	return parsed, nil
}

func parseLogLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("SAS_LOG_LEVEL must be debug, info, warn, or error")
	}
}
