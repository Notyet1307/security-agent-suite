package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

func TestStorePersistsAndReloads(t *testing.T) {
	root := t.TempDir()
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	run := domain.NewRun("run_persist", "event-triage", "事件研判", domain.CreateRunRequest{RequestID: "req-persist", Mode: "triage", Scope: domain.Scope{TenantID: "tenant"}}, domain.RunStatusQueued, time.Now())
	if err := store.Create(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(context.Background(), run.ID, func(current *domain.Run) error {
		return current.Transition(domain.RunStatusValidating, "validate", "test", time.Now())
	}); err != nil {
		t.Fatal(err)
	}

	reloaded, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reloaded.Get(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Status != domain.RunStatusValidating || len(loaded.Events) != 2 {
		t.Fatalf("unexpected reloaded run: %+v", loaded)
	}
	info, err := os.Stat(filepath.Join(root, "audit.jsonl"))
	if err != nil || info.Size() == 0 {
		t.Fatalf("audit log missing: info=%v err=%v", info, err)
	}
}
