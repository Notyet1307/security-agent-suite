package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/app"
	"github.com/Notyet1307/security-agent-suite/internal/artifacts"
	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/observability"
	"github.com/Notyet1307/security-agent-suite/internal/store"
)

type Config struct {
	APIKey             string
	MaxBodyBytes       int64
	RateLimitPerMinute int
	Version            string
	Commit             string
	Ready              func() bool
}

type Server struct {
	cfg       Config
	service   *app.Service
	artifacts *artifacts.Store
	metrics   *observability.Metrics
	logger    *slog.Logger
}

func New(cfg Config, service *app.Service, artifactStore *artifacts.Store, metrics *observability.Metrics, logger *slog.Logger) *Server {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if cfg.RateLimitPerMinute <= 0 {
		cfg.RateLimitPerMinute = 120
	}
	return &Server{cfg: cfg, service: service, artifacts: artifactStore, metrics: metrics, logger: logger}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /metrics", s.prometheus)
	mux.HandleFunc("GET /version", s.version)
	mux.HandleFunc("GET /v1/agents", s.listAgents)
	mux.HandleFunc("GET /v1/agents/{agentID}", s.getAgent)
	mux.HandleFunc("POST /v1/agents/{agentID}/runs", s.createRun)
	mux.HandleFunc("GET /v1/runs", s.listRuns)
	mux.HandleFunc("GET /v1/runs/{runID}", s.getRun)
	mux.HandleFunc("GET /v1/runs/{runID}/events", s.getRunEvents)
	mux.HandleFunc("GET /v1/runs/{runID}/artifacts", s.getRunArtifacts)
	mux.HandleFunc("POST /v1/runs/{runID}/artifacts", s.uploadArtifact)
	mux.HandleFunc("GET /v1/runs/{runID}/artifacts/{artifactID}", s.downloadArtifact)
	mux.HandleFunc("POST /v1/runs/{runID}/approve", s.approveRun)
	mux.HandleFunc("POST /v1/runs/{runID}/cancel", s.cancelRun)

	return chain(
		mux,
		requestContextMiddleware,
		recoverMiddleware(s.logger),
		loggingMiddleware(s.logger, s.metrics),
		rateLimitMiddleware(newLimiter(s.cfg.RateLimitPerMinute)),
		authMiddleware(s.cfg.APIKey),
		tenantMiddleware,
	)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Ready == nil || !s.cfg.Ready() {
		writeStatusError(w, r, http.StatusServiceUnavailable, "not_ready", "service dependencies are not ready")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) prometheus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.metrics.WritePrometheus(w)
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": s.cfg.Version, "commit": s.cfg.Commit})
}

func (s *Server) listAgents(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"agents": s.service.ListAgents()})
}

func (s *Server) getAgent(w http.ResponseWriter, r *http.Request) {
	agent, err := s.service.GetAgent(r.PathValue("agentID"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

func (s *Server) createRun(w http.ResponseWriter, r *http.Request) {
	var req domain.CreateRunRequest
	if err := s.decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	tenantID := tenantIDFromContext(r.Context())
	if req.Scope.TenantID == "" {
		req.Scope.TenantID = tenantID
	} else if req.Scope.TenantID != tenantID {
		writeError(w, r, fmt.Errorf("%w: scope.tenant_id must match X-Tenant-ID", domain.ErrForbidden))
		return
	}
	run, created, err := s.service.CreateRun(r.Context(), r.PathValue("agentID"), req)
	if err != nil {
		writeError(w, r, err)
		return
	}
	status := http.StatusAccepted
	if !created {
		status = http.StatusOK
	}
	w.Header().Set("Location", "/v1/runs/"+run.ID)
	writeJSON(w, status, run)
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 || parsed > 200 {
			writeError(w, r, fmt.Errorf("%w: limit must be between 1 and 200", domain.ErrInvalidRequest))
			return
		}
		limit = parsed
	}
	status := domain.RunStatus(strings.TrimSpace(r.URL.Query().Get("status")))
	if status != "" && !validStatus(status) {
		writeError(w, r, fmt.Errorf("%w: unknown run status %q", domain.ErrInvalidRequest, status))
		return
	}
	runs, err := s.service.ListRuns(r.Context(), store.ListFilter{TenantID: tenantIDFromContext(r.Context()), AgentID: strings.TrimSpace(r.URL.Query().Get("agent_id")), Status: status, Limit: limit})
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": runs, "count": len(runs)})
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.service.GetRun(r.Context(), tenantIDFromContext(r.Context()), r.PathValue("runID"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) getRunEvents(w http.ResponseWriter, r *http.Request) {
	run, err := s.service.GetRun(r.Context(), tenantIDFromContext(r.Context()), r.PathValue("runID"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"run_id": run.ID, "events": run.Events})
}

func (s *Server) getRunArtifacts(w http.ResponseWriter, r *http.Request) {
	run, err := s.service.GetRun(r.Context(), tenantIDFromContext(r.Context()), r.PathValue("runID"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	registered, err := s.artifacts.List(r.Context(), run.ID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	listed := make([]domain.ArtifactRef, 0, len(registered))
	seen := make(map[string]struct{}, len(registered))
	if run.Result != nil {
		for _, ref := range run.Result.Artifacts {
			listed = append(listed, ref)
			seen[ref.ID] = struct{}{}
		}
	}
	for _, ref := range registered {
		if _, exists := seen[ref.ID]; exists {
			continue
		}
		listed = append(listed, ref)
	}
	writeJSON(w, http.StatusOK, map[string]any{"run_id": run.ID, "artifacts": listed})
}

func (s *Server) uploadArtifact(w http.ResponseWriter, r *http.Request) {
	run, err := s.service.GetRun(r.Context(), tenantIDFromContext(r.Context()), r.PathValue("runID"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	if r.ContentLength > s.cfg.MaxBodyBytes {
		writeStatusError(w, r, http.StatusRequestEntityTooLarge, "artifact_too_large", "artifact exceeds the configured request body limit")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	ref, err := s.artifacts.PutReader(
		r.Context(),
		run.ID,
		r.URL.Query().Get("name"),
		r.Header.Get("Content-Type"),
		r.Body,
		r.Header.Get("X-Artifact-SHA256"),
		time.Now(),
	)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeStatusError(w, r, http.StatusRequestEntityTooLarge, "artifact_too_large", "artifact exceeds the configured request body limit")
			return
		}
		writeError(w, r, err)
		return
	}
	w.Header().Set("Location", "/v1/runs/"+run.ID+"/artifacts/"+ref.ID)
	writeJSON(w, http.StatusCreated, ref)
}

func (s *Server) downloadArtifact(w http.ResponseWriter, r *http.Request) {
	run, err := s.service.GetRun(r.Context(), tenantIDFromContext(r.Context()), r.PathValue("runID"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	selected, err := s.artifacts.Get(r.Context(), run.ID, r.PathValue("artifactID"))
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		writeError(w, r, err)
		return
	}
	if errors.Is(err, domain.ErrNotFound) && run.Result != nil {
		for _, ref := range run.Result.Artifacts {
			if ref.ID == r.PathValue("artifactID") {
				selected = ref
				err = nil
				break
			}
		}
	}
	if err != nil {
		writeError(w, r, domain.ErrNotFound)
		return
	}
	file, info, err := s.artifacts.Open(r.Context(), run.ID, selected)
	if err != nil {
		writeError(w, r, err)
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", selected.MediaType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", selected.Name))
	if selected.SHA256 != "" {
		w.Header().Set("ETag", `"sha256:`+selected.SHA256+`"`)
	}
	http.ServeContent(w, r, selected.Name, info.ModTime(), file)
}

func (s *Server) approveRun(w http.ResponseWriter, r *http.Request) {
	var req domain.ApprovalRequest
	if err := s.decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	run, err := s.service.ApproveRun(r.Context(), tenantIDFromContext(r.Context()), r.PathValue("runID"), req)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Actor  string `json:"actor"`
		Reason string `json:"reason"`
	}
	if r.ContentLength != 0 {
		if err := s.decode(w, r, &req); err != nil {
			writeError(w, r, err)
			return
		}
	}
	run, err := s.service.CancelRun(r.Context(), tenantIDFromContext(r.Context()), r.PathValue("runID"), req.Actor, req.Reason)
	if err != nil {
		writeError(w, r, err)
		return
	}
	status := http.StatusOK
	if !run.Status.Terminal() {
		status = http.StatusAccepted
	}
	writeJSON(w, status, run)
}

func (s *Server) decode(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: invalid JSON body: %v", domain.ErrInvalidRequest, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: request body must contain one JSON object", domain.ErrInvalidRequest)
	}
	return nil
}

func validStatus(status domain.RunStatus) bool {
	switch status {
	case domain.RunStatusQueued, domain.RunStatusValidating, domain.RunStatusWaitingApproval, domain.RunStatusRunning, domain.RunStatusSucceeded, domain.RunStatusPartial, domain.RunStatusFailed, domain.RunStatusCancelled:
		return true
	default:
		return false
	}
}
