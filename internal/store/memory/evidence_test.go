package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/artifacts"
	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

func TestEvidenceStoreAppendOnlyAndTenantScoped(t *testing.T) {
	runs := New()
	now := time.Now().UTC()
	run := domain.NewRun("run-memory-evidence", "event-triage", "事件研判", domain.CreateRunRequest{RequestID: "request-memory-evidence", Mode: "triage", Scope: domain.Scope{TenantID: "tenant-a"}}, domain.RunStatusQueued, now)
	if err := runs.Create(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	artifactStore, err := artifacts.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := artifactStore.Put(context.Background(), run.ID, "source.json", "application/json", []byte("source"), now)
	if err != nil {
		t.Fatal(err)
	}
	evidenceStore, err := NewEvidenceStore(runs, artifactStore)
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.EvidenceRef{ID: "e-memory", Type: "observation", SourceURI: artifact.URI, SHA256: artifact.SHA256, Tool: "collector", ToolVersion: "1.0", Parameters: map[string]string{"limit": "10"}, ArtifactIDs: []string{artifact.ID}, CollectedAt: now}
	if _, err := evidenceStore.Append(context.Background(), "tenant-a", run.ID, ref); err != nil {
		t.Fatal(err)
	}
	unbound := ref
	unbound.ID = "e-unbound"
	unbound.SourceURI = "tool://collector/2"
	unbound.ArtifactIDs = nil
	if _, err := evidenceStore.Append(context.Background(), "tenant-a", run.ID, unbound); err != nil {
		t.Fatalf("append without artifact binding: %v", err)
	}
	if _, err := evidenceStore.Append(context.Background(), "tenant-a", run.ID, ref); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("duplicate append error=%v", err)
	}
	otherRun := domain.NewRun("run-memory-other", "event-triage", "事件研判", domain.CreateRunRequest{RequestID: "request-memory-other", Mode: "triage", Scope: domain.Scope{TenantID: "tenant-a"}}, domain.RunStatusQueued, now)
	if err := runs.Create(context.Background(), otherRun); err != nil {
		t.Fatal(err)
	}
	globalDuplicate := ref
	globalDuplicate.ArtifactIDs = nil
	globalDuplicate.SourceURI = "tool://collector/other"
	if _, err := evidenceStore.Append(context.Background(), "tenant-a", otherRun.ID, globalDuplicate); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("cross-run duplicate append error=%v", err)
	}
	if _, err := evidenceStore.Get(context.Background(), "tenant-b", run.ID, ref.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-tenant get error=%v", err)
	}
	ref.Parameters["limit"] = "changed"
	stored, err := evidenceStore.Get(context.Background(), "tenant-a", run.ID, ref.ID)
	if err != nil || stored.Parameters["limit"] != "10" {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
	listed, err := evidenceStore.List(context.Background(), "tenant-a", run.ID)
	if err != nil || len(listed) != 2 {
		t.Fatalf("list=%+v err=%v", listed, err)
	}
}
