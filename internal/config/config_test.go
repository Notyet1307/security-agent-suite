package config

import "testing"

func TestLoadDefaultsAndValidation(t *testing.T) {
	keys := []string{
		"SAS_ADDR", "SAS_API_KEY", "SAS_EXECUTOR", "SAS_STATE_DIR", "SAS_ARTIFACT_DIR",
		"SAS_AGENT_CATALOG", "SAS_WORKERS", "SAS_QUEUE_SIZE", "SAS_RUN_TIMEOUT",
		"SAS_SHUTDOWN_TIMEOUT", "SAS_MAX_BODY_BYTES", "SAS_RATE_LIMIT_PER_MINUTE",
		"SAS_LOG_LEVEL", "SAS_AGENT_COMPOSE_BIN", "SAS_AGENT_COMPOSE_FILE",
		"SAS_AGENT_COMPOSE_HOST", "SAS_AGENT_COMPOSE_PROJECT", "SAS_AGENT_COMPOSE_TIMEOUT",
		"SAS_AGENT_COMPOSE_REMOVE_SANDBOX",
	}
	for _, key := range keys {
		t.Setenv(key, "")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Executor != "mock" || cfg.Workers != 3 || cfg.QueueSize != 128 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}

	t.Setenv("SAS_EXECUTOR", "unknown")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid executor error")
	}
}

func TestLoadRejectsInvalidNumbers(t *testing.T) {
	t.Setenv("SAS_WORKERS", "0")
	if _, err := Load(); err == nil {
		t.Fatal("expected worker validation error")
	}
}
