package file

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/store"
)

func TestInputJournalRetriesDirectorySync(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	fail := errors.New("directory sync failed")
	s.syncDir = func(path string) error {
		if filepath.Base(path) == "input-journals" {
			return fail
		}
		return store.SyncDirectory(path)
	}
	j := store.InputJournal{Version: "sas.input-journal/v1", RunID: "run-one", TenantID: "t"}
	if err := s.CreateInputJournal(context.Background(), j); !errors.Is(err, fail) {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.GetInputJournal(context.Background(), j.RunID); !errors.Is(err, fail) {
		t.Fatalf("read bypassed durability failure: %v", err)
	}
	s.syncDir = store.SyncDirectory
	got, err := s.GetInputJournal(context.Background(), j.RunID)
	if err != nil || got.Version != j.Version {
		t.Fatalf("retry: %+v %v", got, err)
	}
}

func TestEvidenceRetriesPublicationWithoutDuplicateLogicalID(t *testing.T) {
	root := t.TempDir()
	runs, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	run := domain.NewRun("run-one", "event-triage", "triage", domain.CreateRunRequest{RequestID: "one", Scope: domain.Scope{TenantID: "t"}}, domain.RunStatusPreparing, now)
	if err = runs.Create(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	evidence, err := NewEvidenceStore(root, runs, nil)
	if err != nil {
		t.Fatal(err)
	}
	fail := errors.New("directory sync failed")
	evidence.syncDir = func(path string) error {
		if filepath.Base(path) == run.ID {
			return fail
		}
		return store.SyncDirectory(path)
	}
	ref := domain.EvidenceRef{ID: "input-test", Type: "input", SourceURI: "tool://synthetic", SHA256: strings.Repeat("a", 64), Tool: "test", ToolVersion: "1", Parameters: map[string]string{}, CollectedAt: now}
	for range 2 {
		if _, err = evidence.Append(context.Background(), "t", run.ID, ref); !errors.Is(err, fail) {
			t.Fatalf("append: %v", err)
		}
	}
	evidence.syncDir = store.SyncDirectory
	if _, err = evidence.Append(context.Background(), "t", run.ID, ref); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewEvidenceStore(root, runs, nil)
	if err != nil {
		t.Fatal(err)
	}
	records, err := reloaded.List(context.Background(), "t", run.ID)
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%d err=%v", len(records), err)
	}
}

func TestRunCreateSyncFailureKeepsRequestReservation(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	fail := errors.New("run directory sync failed")
	s.syncDir = func(string) error { return fail }
	now := time.Now()
	run := domain.NewRun("run-first", "event-triage", "triage", domain.CreateRunRequest{RequestID: "one", Scope: domain.Scope{TenantID: "t"}}, domain.RunStatusPreparing, now)
	if err = s.Create(context.Background(), run); !errors.Is(err, fail) {
		t.Fatalf("create: %v", err)
	}
	if _, err = s.FindByRequestID(context.Background(), "t", "one"); !errors.Is(err, fail) {
		t.Fatalf("unconfirmed request must not be absent or successful: %v", err)
	}
	s.syncDir = store.SyncDirectory
	got, err := s.FindByRequestID(context.Background(), "t", "one")
	if err != nil || got.ID != run.ID {
		t.Fatalf("lost reservation: %+v %v", got, err)
	}
	second := domain.NewRun("run-second", "event-triage", "triage", domain.CreateRunRequest{RequestID: "one", Scope: domain.Scope{TenantID: "t"}}, domain.RunStatusPreparing, now)
	if err = s.Create(context.Background(), second); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("duplicate create: %v", err)
	}
	reloaded, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	records, err := reloaded.List(context.Background(), store.ListFilter{})
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%d err=%v", len(records), err)
	}
}
