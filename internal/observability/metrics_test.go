package observability

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

func TestMetricsPrometheusOutput(t *testing.T) {
	metrics := NewMetrics()
	metrics.ObserveHTTP(200, 10*time.Millisecond)
	metrics.ObserveHTTP(500, 30*time.Millisecond)
	metrics.RunCreated()
	metrics.RunCompleted(domain.RunStatusSucceeded)
	metrics.SetQueueDepth(2)
	var out bytes.Buffer
	metrics.WritePrometheus(&out)
	text := out.String()
	for _, expected := range []string{
		"sas_http_requests_total 2", "sas_http_errors_total 1",
		"sas_runs_created_total 1", `status="succeeded"} 1`, "sas_run_queue_depth 2",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q in metrics:\n%s", expected, text)
		}
	}
}
