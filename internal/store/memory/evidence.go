package memory

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/store"
)

type EvidenceStore struct {
	mu        sync.RWMutex
	runs      store.RunReader
	artifacts store.ArtifactReader
	records   map[string]evidenceRecord
}

type evidenceRecord struct {
	tenantID string
	runID    string
	evidence domain.EvidenceRef
}

func NewEvidenceStore(runs store.RunReader, artifacts store.ArtifactReader) (*EvidenceStore, error) {
	if runs == nil {
		return nil, errors.New("evidence run reader is required")
	}
	return &EvidenceStore{runs: runs, artifacts: artifacts, records: map[string]evidenceRecord{}}, nil
}

func (s *EvidenceStore) Append(ctx context.Context, tenantID, runID string, evidence domain.EvidenceRef) (domain.EvidenceRef, error) {
	if err := ctx.Err(); err != nil {
		return domain.EvidenceRef{}, err
	}
	tenantID = strings.TrimSpace(tenantID)
	runID = strings.TrimSpace(runID)
	if tenantID == "" || len(tenantID) > 128 || !store.ValidIdentifier(runID) {
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

var _ store.EvidenceStore = (*EvidenceStore)(nil)
