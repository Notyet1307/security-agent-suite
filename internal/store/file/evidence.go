package file

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/store"
)

const maxEvidenceFileBytes = 8 << 20

type EvidenceStore struct {
	mu        sync.RWMutex
	syncDir   func(string) error
	dir       string
	runs      store.RunReader
	artifacts store.ArtifactReader
	records   map[string]evidenceRecord
}

type evidenceRecord struct {
	tenantID string
	runID    string
	evidence domain.EvidenceRef
}

func NewEvidenceStore(root string, runs store.RunReader, artifacts store.ArtifactReader) (*EvidenceStore, error) {
	if runs == nil {
		return nil, errors.New("evidence run reader is required")
	}
	dir := filepath.Join(root, "evidence")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create evidence directory: %w", err)
	}
	if err := store.SyncDirectory(root); err != nil {
		return nil, err
	}
	s := &EvidenceStore{syncDir: store.SyncDirectory, dir: dir, runs: runs, artifacts: artifacts, records: map[string]evidenceRecord{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *EvidenceStore) load() error {
	runEntries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("read evidence directory: %w", err)
	}
	for _, runEntry := range runEntries {
		if runEntry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("evidence run directory %q is a symbolic link", runEntry.Name())
		}
		if !runEntry.IsDir() {
			continue
		}
		if !store.ValidIdentifier(runEntry.Name()) {
			return fmt.Errorf("invalid evidence run directory %q", runEntry.Name())
		}
		run, err := s.runs.Get(context.Background(), runEntry.Name())
		if err != nil {
			return fmt.Errorf("load evidence run %s: %w", runEntry.Name(), err)
		}
		if run == nil {
			return fmt.Errorf("load evidence run %s: run store returned nil", runEntry.Name())
		}
		tenantID := run.Scope.TenantID
		runDir := filepath.Join(s.dir, runEntry.Name())
		if err := s.syncDir(runDir); err != nil {
			return err
		}
		entries, err := os.ReadDir(runDir)
		if err != nil {
			return fmt.Errorf("read evidence run directory %s: %w", runEntry.Name(), err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			path := filepath.Join(runDir, entry.Name())
			info, err := os.Lstat(path)
			if err != nil {
				return fmt.Errorf("stat evidence %s: %w", entry.Name(), err)
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxEvidenceFileBytes {
				return fmt.Errorf("evidence %s is not a bounded regular file", entry.Name())
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read evidence %s: %w", entry.Name(), err)
			}
			var ref domain.EvidenceRef
			if err := json.Unmarshal(data, &ref); err != nil {
				return fmt.Errorf("decode evidence %s: %w", entry.Name(), err)
			}
			normalized, err := store.NormalizeEvidence(ref)
			if err != nil {
				return fmt.Errorf("invalid persisted evidence %s: %w", entry.Name(), err)
			}
			if err := store.ValidateEvidenceScope(context.Background(), s.runs, s.artifacts, tenantID, runEntry.Name(), normalized); err != nil {
				return fmt.Errorf("invalid persisted evidence %s: %w", entry.Name(), err)
			}
			storageID := strings.TrimSuffix(entry.Name(), ".json")
			if !store.ValidIdentifier(storageID) {
				return fmt.Errorf("invalid evidence filename %q", entry.Name())
			}
			if _, exists := s.records[normalized.ID]; exists {
				return fmt.Errorf("duplicate persisted evidence id %q", normalized.ID)
			}
			s.records[normalized.ID] = evidenceRecord{tenantID: tenantID, runID: runEntry.Name(), evidence: normalized}
		}
	}
	return nil
}

func (s *EvidenceStore) Append(ctx context.Context, tenantID, runID string, evidence domain.EvidenceRef) (domain.EvidenceRef, error) {
	if err := ctx.Err(); err != nil {
		return domain.EvidenceRef{}, err
	}
	tenantID = strings.TrimSpace(tenantID)
	rawRunID := strings.TrimSpace(runID)
	runID = filepath.Base(rawRunID)
	if tenantID == "" || len(tenantID) > 128 || rawRunID == "" || runID != rawRunID || strings.ContainsAny(rawRunID, `/\\`) || !store.ValidIdentifier(runID) {
		return domain.EvidenceRef{}, fmt.Errorf("%w: invalid evidence namespace", domain.ErrInvalidRequest)
	}
	normalized, err := store.NormalizeEvidence(evidence)
	if err != nil {
		return domain.EvidenceRef{}, err
	}
	if err := store.ValidateEvidenceScope(ctx, s.runs, s.artifacts, tenantID, runID, normalized); err != nil {
		return domain.EvidenceRef{}, err
	}
	if err := ctx.Err(); err != nil {
		return domain.EvidenceRef{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[normalized.ID]; exists {
		return domain.EvidenceRef{}, domain.ErrAlreadyExists
	}
	storageID := fmt.Sprintf("evidence_%x", sha256.Sum256([]byte(normalized.ID)))
	runDir := filepath.Join(s.dir, runID)
	if err := os.MkdirAll(runDir, 0o750); err != nil {
		return domain.EvidenceRef{}, fmt.Errorf("create evidence run directory: %w", err)
	}
	if err := s.syncDir(s.dir); err != nil {
		return domain.EvidenceRef{}, err
	}
	if err := s.writeImmutable(runDir, storageID, normalized); err != nil {
		return domain.EvidenceRef{}, err
	}
	s.records[normalized.ID] = evidenceRecord{tenantID: tenantID, runID: runID, evidence: normalized}
	return store.CloneEvidence(normalized), nil
}

func (s *EvidenceStore) Get(ctx context.Context, tenantID, runID, evidenceID string) (domain.EvidenceRef, error) {
	if err := ctx.Err(); err != nil {
		return domain.EvidenceRef{}, err
	}
	tenantID = strings.TrimSpace(tenantID)
	runID = strings.TrimSpace(runID)
	evidenceID = strings.TrimSpace(evidenceID)
	if tenantID == "" || len(tenantID) > 128 || !store.ValidIdentifier(runID) || !store.ValidIdentifier(evidenceID) {
		return domain.EvidenceRef{}, fmt.Errorf("%w: invalid evidence namespace", domain.ErrInvalidRequest)
	}
	if err := store.ValidateEvidenceScope(ctx, s.runs, nil, tenantID, runID, domain.EvidenceRef{}); err != nil {
		return domain.EvidenceRef{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[evidenceID]
	if !ok || record.runID != runID || record.tenantID != tenantID {
		return domain.EvidenceRef{}, domain.ErrNotFound
	}
	return store.CloneEvidence(record.evidence), nil
}

func (s *EvidenceStore) List(ctx context.Context, tenantID, runID string) ([]domain.EvidenceRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tenantID = strings.TrimSpace(tenantID)
	runID = strings.TrimSpace(runID)
	if tenantID == "" || len(tenantID) > 128 || !store.ValidIdentifier(runID) {
		return nil, fmt.Errorf("%w: invalid evidence namespace", domain.ErrInvalidRequest)
	}
	if err := store.ValidateEvidenceScope(ctx, s.runs, nil, tenantID, runID, domain.EvidenceRef{}); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]domain.EvidenceRef, 0)
	for _, record := range s.records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if record.runID != runID || record.tenantID != tenantID {
			continue
		}
		result = append(result, store.CloneEvidence(record.evidence))
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].CollectedAt.Equal(result[j].CollectedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].CollectedAt.Before(result[j].CollectedAt)
	})
	return result, nil
}

func (s *EvidenceStore) writeImmutable(runDir, storageID string, evidence domain.EvidenceRef) error {
	if !store.ValidIdentifier(storageID) {
		return fmt.Errorf("%w: invalid evidence storage id", domain.ErrInvalidRequest)
	}
	data, err := json.MarshalIndent(struct {
		domain.EvidenceRef
		Parameters map[string]string `json:"parameters"`
	}{EvidenceRef: evidence, Parameters: evidence.Parameters}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode evidence: %w", err)
	}
	if len(data)+1 > maxEvidenceFileBytes {
		return fmt.Errorf("%w: evidence record is too large", domain.ErrInvalidRequest)
	}
	tmp, err := os.CreateTemp(runDir, ".evidence-*.tmp")
	if err != nil {
		return fmt.Errorf("create evidence temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	defer cleanup()
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod evidence: %w", err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write evidence: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync evidence: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close evidence: %w", err)
	}
	path := filepath.Join(runDir, storageID+".json")
	if err := os.Link(tmpName, path); err != nil {
		if os.IsExist(err) {
			existing, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if !bytes.Equal(existing, append(data, '\n')) {
				return domain.ErrAlreadyExists
			}
			return s.syncDir(runDir)
		}
		return fmt.Errorf("publish evidence: %w", err)
	}
	return s.syncDir(runDir)
}

var _ store.EvidenceStore = (*EvidenceStore)(nil)
