package artifacts

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

func TestPutOpenAndSanitize(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	ref, err := store.Put(context.Background(), "run_safe", "../unsafe report?.json", "application/json", []byte(`{"ok":true}`), now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(ref.Name, `/\\?`) || ref.SHA256 == "" || ref.SizeBytes == 0 {
		t.Fatalf("unexpected ref: %+v", ref)
	}
	file, info, err := store.Open(context.Background(), "run_safe", ref)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data, _ := io.ReadAll(file)
	if string(data) != `{"ok":true}` || info.Size() != ref.SizeBytes {
		t.Fatalf("unexpected artifact content=%s size=%d", data, info.Size())
	}
}

func TestArtifactPathBoundaries(t *testing.T) {
	store, _ := New(t.TempDir())
	if _, err := store.Put(context.Background(), "../escape", "x", "text/plain", nil, time.Now()); err == nil {
		t.Fatal("expected unsafe run id to be rejected")
	}
	ref := domain.ArtifactRef{URI: "artifact://runs/run-a/../../secret"}
	if _, _, err := store.Open(context.Background(), "run-a", ref); err == nil {
		t.Fatal("expected traversal URI to be rejected")
	}
	ref.URI = "artifact://runs/run-b/file"
	if _, _, err := store.Open(context.Background(), "run-a", ref); err == nil {
		t.Fatal("expected cross-run artifact to be rejected")
	}
}
