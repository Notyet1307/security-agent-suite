package observability

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

type Metrics struct {
	httpRequests       atomic.Int64
	httpErrors         atomic.Int64
	httpDurationMicros atomic.Int64
	runsCreated        atomic.Int64
	runsSucceeded      atomic.Int64
	runsPartial        atomic.Int64
	runsFailed         atomic.Int64
	runsCancelled      atomic.Int64
	queueDepth         atomic.Int64
}

func NewMetrics() *Metrics { return &Metrics{} }

func (m *Metrics) ObserveHTTP(status int, duration time.Duration) {
	m.httpRequests.Add(1)
	m.httpDurationMicros.Add(duration.Microseconds())
	if status >= 400 {
		m.httpErrors.Add(1)
	}
}

func (m *Metrics) RunCreated() { m.runsCreated.Add(1) }

func (m *Metrics) RunCompleted(status domain.RunStatus) {
	switch status {
	case domain.RunStatusSucceeded:
		m.runsSucceeded.Add(1)
	case domain.RunStatusPartial:
		m.runsPartial.Add(1)
	case domain.RunStatusFailed:
		m.runsFailed.Add(1)
	case domain.RunStatusCancelled:
		m.runsCancelled.Add(1)
	}
}

func (m *Metrics) SetQueueDepth(depth int) { m.queueDepth.Store(int64(depth)) }

func (m *Metrics) WritePrometheus(w io.Writer) {
	requests := m.httpRequests.Load()
	duration := m.httpDurationMicros.Load()
	average := float64(0)
	if requests > 0 {
		average = float64(duration) / float64(requests) / 1_000_000
	}
	_, _ = fmt.Fprintf(w, "# TYPE sas_http_requests_total counter\nsas_http_requests_total %d\n", requests)
	_, _ = fmt.Fprintf(w, "# TYPE sas_http_errors_total counter\nsas_http_errors_total %d\n", m.httpErrors.Load())
	_, _ = fmt.Fprintf(w, "# TYPE sas_http_request_duration_seconds_average gauge\nsas_http_request_duration_seconds_average %.6f\n", average)
	_, _ = fmt.Fprintf(w, "# TYPE sas_runs_created_total counter\nsas_runs_created_total %d\n", m.runsCreated.Load())
	_, _ = fmt.Fprintf(w, "# TYPE sas_runs_completed_total counter\nsas_runs_completed_total{status=\"succeeded\"} %d\n", m.runsSucceeded.Load())
	_, _ = fmt.Fprintf(w, "sas_runs_completed_total{status=\"partial\"} %d\n", m.runsPartial.Load())
	_, _ = fmt.Fprintf(w, "sas_runs_completed_total{status=\"failed\"} %d\n", m.runsFailed.Load())
	_, _ = fmt.Fprintf(w, "sas_runs_completed_total{status=\"cancelled\"} %d\n", m.runsCancelled.Load())
	_, _ = fmt.Fprintf(w, "# TYPE sas_run_queue_depth gauge\nsas_run_queue_depth %d\n", m.queueDepth.Load())
}
