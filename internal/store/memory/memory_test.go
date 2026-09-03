package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

func TestStoreIdempotencyAndClone(t *testing.T) {
	store := New()
	run := domain.NewRun("run_1", "event-triage", "事件研判", domain.CreateRunRequest{RequestID: "request-1", Mode: "triage", Scope: domain.Scope{TenantID: "tenant-1"}}, domain.RunStatusQueued, time.Now())
	if err := store.Create(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(context.Background(), run); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("expected already exists, got %v", err)
	}
	loaded, err := store.Get(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Status = domain.RunStatusFailed
	again, _ := store.Get(context.Background(), run.ID)
	if again.Status != domain.RunStatusQueued {
		t.Fatal("store leaked mutable reference")
	}
}
