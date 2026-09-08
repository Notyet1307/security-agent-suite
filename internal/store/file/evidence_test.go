package file

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/artifacts"
	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

func TestEvidenceStoreAppendOnlyAndReloads(t *testing.T) {
	root := t.TempDir()
	runs, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 8, 1, 2, 3, 0, time.FixedZone("test", 8*60*60))
	run := domain.NewRun("run-evidence", "event-triage", "事件研判", domain.CreateRunRequest{
		RequestID: "request-evidence",
		Mode:      "triage",
		Scope:     domain.Scope{TenantID: "tenant-a"},
	}, domain.RunStatusQueued, now)
	if err := runs.Create(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	artifactStore, err := artifacts.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := artifactStore.Put(context.Background(), run.ID, "source.json", "application/json", []byte(`{"source":true}`), now)
	if err != nil {
		t.Fatal(err)
	}
	otherArtifact, err := artifactStore.Put(context.Background(), run.ID, "other.json", "application/json", []byte(`{"other":true}`), now)
	if err != nil {
		t.Fatal(err)
	}
	evidenceStore, err := NewEvidenceStore(root, runs, artifactStore)
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.EvidenceRef{
		ID:          "evidence-1",
		Type:        "tool-observation",
		SourceURI:   artifact.URI,
		SHA256:      artifact.SHA256,
		Tool:        "collector",
		ToolVersion: "1.2.3",
		Parameters:  map[string]string{"query": "select *"},
		ArtifactIDs: []string{artifact.ID},
		CollectedAt: now,
		Metadata:    map[string]string{"classification": "internal"},
	}
	got, err := evidenceStore.Append(context.Background(), "tenant-a", run.ID, ref)
	if err != nil {
		t.Fatal(err)
	}
	if got.SHA256 != artifact.SHA256 || !got.CollectedAt.Equal(now.UTC()) || got.ToolVersion != ref.ToolVersion || got.Parameters["query"] != "select *" {
		t.Fatalf("unexpected normalized evidence: %+v", got)
	}
	unbound := ref
	unbound.ID = "evidence-unbound"
	unbound.SourceURI = "tool://collector/1"
	unbound.ArtifactIDs = nil
	unbound.Parameters = map[string]string{}
	if _, err := evidenceStore.Append(context.Background(), "tenant-a", run.ID, unbound); err != nil {
		t.Fatalf("append without artifact binding: %v", err)
	}
	got.Parameters["query"] = "mutated"
	ref.Metadata["classification"] = "changed"
	stored, err := evidenceStore.Get(context.Background(), "tenant-a", run.ID, ref.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Parameters["query"] != "select *" || stored.Metadata["classification"] != "internal" {
		t.Fatalf("store leaked mutable evidence: %+v", stored)
	}
	if _, err := evidenceStore.Append(context.Background(), "tenant-a", run.ID, ref); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("duplicate append error=%v", err)
	}
	if _, err := evidenceStore.Get(context.Background(), "tenant-b", run.ID, ref.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-tenant get error=%v", err)
	}
	if _, err := evidenceStore.Append(context.Background(), "tenant-b", run.ID, ref); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-tenant append error=%v", err)
	}
	otherRun := domain.NewRun("run-evidence-other", "event-triage", "事件研判", domain.CreateRunRequest{RequestID: "request-evidence-other", Mode: "triage", Scope: domain.Scope{TenantID: "tenant-a"}}, domain.RunStatusQueued, now)
	if err := runs.Create(context.Background(), otherRun); err != nil {
		t.Fatal(err)
	}
	globalDuplicate := ref
	globalDuplicate.ArtifactIDs = nil
	globalDuplicate.SourceURI = "tool://collector/other"
	if _, err := evidenceStore.Append(context.Background(), "tenant-a", otherRun.ID, globalDuplicate); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("cross-run duplicate append error=%v", err)
	}
	mismatchedHash := ref
	mismatchedHash.ID = "evidence-hash-mismatch"
	mismatchedHash.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := evidenceStore.Append(context.Background(), "tenant-a", run.ID, mismatchedHash); !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("mismatched artifact hash error=%v", err)
	}
	crossMatched := ref
	crossMatched.ID = "evidence-cross-match"
	crossMatched.SourceURI = otherArtifact.URI
	crossMatched.ArtifactIDs = []string{artifact.ID, otherArtifact.ID}
	if _, err := evidenceStore.Append(context.Background(), "tenant-a", run.ID, crossMatched); !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("cross-artifact hash/source error=%v", err)
	}
	unsafeID := ref
	unsafeID.ID = "../evidence-unsafe"
	if _, err := evidenceStore.Append(context.Background(), "tenant-a", run.ID, unsafeID); !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("unsafe evidence id error=%v", err)
	}
	if _, err := evidenceStore.Append(context.Background(), "tenant-a", "../"+run.ID, ref); !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("unsafe run id error=%v", err)
	}
	invalidArtifact := ref
	invalidArtifact.ID = "evidence-2"
	invalidArtifact.ArtifactIDs = []string{"missing-artifact"}
	if _, err := evidenceStore.Append(context.Background(), "tenant-a", run.ID, invalidArtifact); !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("invalid artifact error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	invalidArtifact.ID = "evidence-3"
	if _, err := evidenceStore.Append(cancelled, "tenant-a", run.ID, invalidArtifact); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled append error=%v", err)
	}
	listed, err := evidenceStore.List(context.Background(), "tenant-a", run.ID)
	if err != nil || len(listed) != 2 || listed[0].ID != ref.ID || listed[1].ID != unbound.ID {
		t.Fatalf("list=%+v err=%v", listed, err)
	}
	if _, err := evidenceStore.List(cancelled, "tenant-a", run.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled list error=%v", err)
	}
	reloaded, err := NewEvidenceStore(root, runs, artifactStore)
	if err != nil {
		t.Fatal(err)
	}
	reloadedRef, err := reloaded.Get(context.Background(), "tenant-a", run.ID, ref.ID)
	if err != nil || reloadedRef.ToolVersion != ref.ToolVersion || reloadedRef.ArtifactIDs[0] != artifact.ID {
		t.Fatalf("reloaded=%+v err=%v", reloadedRef, err)
	}
	reloadedUnbound, err := reloaded.Get(context.Background(), "tenant-a", run.ID, unbound.ID)
	if err != nil || reloadedUnbound.SourceURI != unbound.SourceURI || len(reloadedUnbound.ArtifactIDs) != 0 {
		t.Fatalf("reloaded unbound=%+v err=%v", reloadedUnbound, err)
	}
}

func TestEvidenceStoreRejectsMissingRequiredFields(t *testing.T) {
	runs, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	run := domain.NewRun("run-invalid-evidence", "event-triage", "事件研判", domain.CreateRunRequest{RequestID: "request-invalid-evidence", Mode: "triage", Scope: domain.Scope{TenantID: "tenant-a"}}, domain.RunStatusQueued, time.Now())
	if err := runs.Create(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	artifactStore, err := artifacts.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := artifactStore.Put(context.Background(), run.ID, "source.json", "application/json", []byte("{\"source\":true}"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	evidenceStore, err := NewEvidenceStore(t.TempDir(), runs, artifactStore)
	if err != nil {
		t.Fatal(err)
	}
	cases := []domain.EvidenceRef{
		{ID: "e0", Type: "tool", SourceURI: artifact.URI, SHA256: artifact.SHA256, Tool: "collector", ToolVersion: "1", CollectedAt: time.Now(), ArtifactIDs: []string{artifact.ID}},
		{ID: "e1", Type: "tool", SourceURI: artifact.URI, Tool: "collector", ToolVersion: "1", Parameters: map[string]string{}, CollectedAt: time.Now(), ArtifactIDs: []string{artifact.ID}},
		{ID: "e2", Type: "tool", SourceURI: artifact.URI, SHA256: "not-a-hash", Tool: "collector", ToolVersion: "1", Parameters: map[string]string{}, CollectedAt: time.Now(), ArtifactIDs: []string{artifact.ID}},
		{ID: "e4", Type: "tool", SourceURI: artifact.URI, SHA256: artifact.SHA256, Tool: "collector", ToolVersion: "1", Parameters: map[string]string{}, CollectedAt: time.Now(), ArtifactIDs: []string{"missing-artifact"}},
	}
	for _, ref := range cases {
		if _, err := evidenceStore.Append(context.Background(), "tenant-a", run.ID, ref); !errors.Is(err, domain.ErrInvalidRequest) {
			t.Errorf("ref=%+v error=%v", ref, err)
		}
	}
}
