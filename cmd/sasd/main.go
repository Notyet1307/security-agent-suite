package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/app"
	"github.com/Notyet1307/security-agent-suite/internal/artifacts"
	"github.com/Notyet1307/security-agent-suite/internal/catalog"
	"github.com/Notyet1307/security-agent-suite/internal/config"
	"github.com/Notyet1307/security-agent-suite/internal/doctor"
	"github.com/Notyet1307/security-agent-suite/internal/executor"
	agentcomposeexecutor "github.com/Notyet1307/security-agent-suite/internal/executor/agentcompose"
	mockexecutor "github.com/Notyet1307/security-agent-suite/internal/executor/mock"
	"github.com/Notyet1307/security-agent-suite/internal/httpapi"
	"github.com/Notyet1307/security-agent-suite/internal/observability"
	"github.com/Notyet1307/security-agent-suite/internal/policy"
	"github.com/Notyet1307/security-agent-suite/internal/prompt"
	filestore "github.com/Notyet1307/security-agent-suite/internal/store/file"
)

var (
	version = "dev"
	commit  = "none"
)

const readinessRefreshInterval = 5 * time.Minute

func main() {
	cfg, err := config.Load()
	if err != nil {
		fatal(slog.Default(), "load configuration", err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)

	agentCatalog, err := catalog.Load(cfg.AgentCatalogPath)
	if err != nil {
		fatal(logger, "load agent catalog", err)
	}
	runStore, err := filestore.New(cfg.StateDir)
	if err != nil {
		fatal(logger, "initialize run store", err)
	}
	artifactStore, err := artifacts.New(cfg.ArtifactDir)
	if err != nil {
		fatal(logger, "initialize artifact store", err)
	}
	metrics := observability.NewMetrics()

	var runtime executor.Executor
	switch cfg.Executor {
	case "mock":
		runtime = mockexecutor.New(artifactStore)
	case "agentcompose-cli":
		runtime = agentcomposeexecutor.New(agentcomposeexecutor.Config{
			Binary: cfg.AgentComposeBin, ComposeFile: cfg.AgentComposeFile,
			Host: cfg.AgentComposeHost, Project: cfg.AgentComposeProject,
			Timeout: cfg.AgentComposeTimeout, RemoveSandbox: cfg.RemoveSandbox,
		}, artifactStore)
	default:
		fatal(logger, "select executor", errors.New("unsupported executor"))
	}

	service := app.New(app.Config{Workers: cfg.Workers, QueueSize: cfg.QueueSize, MaxRunTimeout: cfg.RunTimeout}, runStore, agentCatalog, policy.New(), runtime, prompt.New(), metrics, logger)
	if err := service.Start(); err != nil {
		fatal(logger, "start run service", err)
	}
	defer service.Close()

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	var readiness atomic.Bool
	var readinessDone <-chan struct{}
	if cfg.Executor == "mock" {
		readiness.Store(true)
	} else {
		doctorCfg := doctor.FromEnvironment("", cfg.APIKey, "")
		doctorCfg.Executor = cfg.Executor
		doctorCfg.AgentComposeBin = cfg.AgentComposeBin
		doctorCfg.AgentComposeFile = cfg.AgentComposeFile
		doctorCfg.AgentComposeHost = cfg.AgentComposeHost
		ticker := time.NewTicker(readinessRefreshInterval)
		done := make(chan struct{})
		readinessDone = done
		go func() {
			defer close(done)
			defer ticker.Stop()
			monitorReadiness(signalCtx, ticker.C, func(ctx context.Context) bool {
				return !doctor.RunRuntime(ctx, doctorCfg).RequiredFailures()
			}, &readiness)
		}()
	}

	api := httpapi.New(httpapi.Config{
		APIKey: cfg.APIKey, MaxBodyBytes: cfg.MaxBodyBytes,
		RateLimitPerMinute: cfg.RateLimitPerMinute,
		Version:            version, Commit: commit, Ready: readiness.Load,
	}, service, artifactStore, metrics, logger)

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("security-agent-suite started", "addr", cfg.Addr, "executor", runtime.Name(), "version", version, "commit", commit)
		if cfg.APIKey == "" {
			logger.Warn("SAS_API_KEY is empty; API authentication is disabled")
		}
		serverErr <- httpServer.ListenAndServe()
	}()

	select {
	case <-signalCtx.Done():
		logger.Info("shutdown signal received")
	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			fatal(logger, "http server failed", err)
		}
	}
	stopSignals()
	if readinessDone != nil {
		<-readinessDone
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("http shutdown", "error", err)
	}
}

func monitorReadiness(ctx context.Context, ticks <-chan time.Time, check func(context.Context) bool, ready *atomic.Bool) {
	for {
		if ctx.Err() != nil {
			return
		}
		ready.Store(check(ctx))
		select {
		case <-ctx.Done():
			return
		case <-ticks:
		}
	}
}

func fatal(logger *slog.Logger, message string, err error) {
	logger.Error(message, "error", err)
	os.Exit(1)
}
