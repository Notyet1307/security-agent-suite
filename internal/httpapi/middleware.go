package httpapi

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/id"
	"github.com/Notyet1307/security-agent-suite/internal/observability"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(data)
}

type rateEntry struct {
	window time.Time
	count  int
}

type limiter struct {
	mu      sync.Mutex
	limit   int
	entries map[string]rateEntry
}

func newLimiter(limit int) *limiter {
	return &limiter{limit: limit, entries: map[string]rateEntry{}}
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	window := now.UTC().Truncate(time.Minute)
	entry := l.entries[key]
	if !entry.window.Equal(window) {
		entry = rateEntry{window: window}
	}
	entry.count++
	l.entries[key] = entry
	if len(l.entries) > 5000 {
		for candidate, value := range l.entries {
			if value.window.Before(window.Add(-2 * time.Minute)) {
				delete(l.entries, candidate)
			}
		}
	}
	return entry.count <= l.limit
}

func chain(handler http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}

func requestContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if requestID == "" || len(requestID) > 128 {
			generated, err := id.New("req", time.Now())
			if err != nil {
				http.Error(w, "failed to generate request id", http.StatusInternalServerError)
				return
			}
			requestID = generated
		}
		tenantID := strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
		ctx := context.WithValue(r.Context(), requestIDKey, requestID)
		ctx = context.WithValue(ctx, tenantIDKey, tenantID)
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func authMiddleware(apiKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
				next.ServeHTTP(w, r)
				return
			}
			if apiKey == "" {
				next.ServeHTTP(w, r)
				return
			}
			provided := r.Header.Get("X-API-Key")
			if subtle.ConstantTimeCompare([]byte(provided), []byte(apiKey)) != 1 {
				writeError(w, r, fmt.Errorf("%w: valid X-API-Key required", domain.ErrUnauthorized))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func tenantMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/") {
			next.ServeHTTP(w, r)
			return
		}
		if tenantIDFromContext(r.Context()) == "" {
			writeError(w, r, fmt.Errorf("%w: X-Tenant-ID header is required", domain.ErrInvalidRequest))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func rateLimitMiddleware(limiter *limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			key := host + "\x00" + tenantIDFromContext(r.Context())
			if !limiter.allow(key, time.Now()) {
				w.Header().Set("Retry-After", "60")
				writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": map[string]string{"code": "rate_limited", "message": "request rate limit exceeded", "request_id": requestIDFromContext(r.Context())}})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func recoverMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					logger.Error("http panic", "request_id", requestIDFromContext(r.Context()), "panic", recovered, "stack", string(debug.Stack()))
					writeJSON(w, http.StatusInternalServerError, map[string]any{"error": map[string]string{"code": "internal_error", "message": "internal server error", "request_id": requestIDFromContext(r.Context())}})
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func loggingMiddleware(logger *slog.Logger, metrics *observability.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started := time.Now()
			recorder := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(recorder, r)
			if recorder.status == 0 {
				recorder.status = http.StatusOK
			}
			duration := time.Since(started)
			metrics.ObserveHTTP(recorder.status, duration)
			logger.Info("http request", "request_id", requestIDFromContext(r.Context()), "tenant_id", tenantIDFromContext(r.Context()), "method", r.Method, "path", r.URL.Path, "status", recorder.status, "duration_ms", duration.Milliseconds())
		})
	}
}
