package artifacts

import (
	"context"
	"errors"
	"github.com/Notyet1307/security-agent-suite/internal/store"
	"io"
	"path/filepath"
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

func TestPutReaderRegistersMetadataAndValidatesHash(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	const expectedSHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	ref, err := store.PutReader(context.Background(), "run-upload", "evidence.txt", "text/plain; charset=utf-8", strings.NewReader("hello"), expectedSHA256, now)
	if err != nil {
		t.Fatal(err)
	}
	if ref.SHA256 != expectedSHA256 || ref.SizeBytes != 5 || ref.MediaType != "text/plain; charset=utf-8" {
		t.Fatalf("unexpected uploaded artifact: %+v", ref)
	}
	got, err := store.Get(context.Background(), "run-upload", ref.ID)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := store.List(context.Background(), "run-upload")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != ref.ID || got.URI != ref.URI || len(refs) != 1 || refs[0].ID != ref.ID {
		t.Fatalf("registered artifact mismatch: got=%+v list=%+v", got, refs)
	}

	_, err = store.PutReader(context.Background(), "run-upload", "bad.txt", "text/plain", strings.NewReader("hello"), strings.Repeat("0", 64), now)
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("expected hash mismatch to be invalid, got %v", err)
	}
	_, err = store.PutReader(context.Background(), "run-upload", strings.Repeat("x", maxArtifactNameBytes+1), "text/plain", strings.NewReader("hello"), "", now)
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("expected long name to be invalid, got %v", err)
	}
	_, err = store.PutReader(context.Background(), "run-upload", "bad.txt", "not-a-media-type", strings.NewReader("hello"), "", now)
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("expected media type to be invalid, got %v", err)
	}
	refs, err = store.List(context.Background(), "run-upload")
	if err != nil || len(refs) != 1 {
		t.Fatalf("failed upload was registered: refs=%+v err=%v", refs, err)
	}
}

func TestMetadataSyncFailureRetainsBytesAndRequiresSyncBeforeInputRead(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fail := errors.New("metadata directory sync failed")
	s.syncDir = func(path string) error {
		if filepath.Base(path) == metadataDirectory {
			return fail
		}
		return store.SyncDirectory(path)
	}
	if _, err = s.Put(context.Background(), "run-one", "source.json", "application/json", []byte(`{}`), time.Now()); !errors.Is(err, fail) {
		t.Fatalf("put: %v", err)
	}
	refs, err := s.List(context.Background(), "run-one")
	if err != nil || len(refs) != 1 {
		t.Fatalf("uncertain metadata lost: %v %v", refs, err)
	}
	if _, err = s.ReadInput(context.Background(), "run-one", refs[0], 100); !errors.Is(err, fail) {
		t.Fatalf("unsynced metadata trusted: %v", err)
	}
	s.syncDir = store.SyncDirectory
	raw, err := s.ReadInput(context.Background(), "run-one", refs[0], 100)
	if err != nil || string(raw) != `{}` {
		t.Fatalf("original bytes lost: %q %v", raw, err)
	}
}
