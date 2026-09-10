package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"mime"
	"reflect"
	"strings"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/id"
	"github.com/Notyet1307/security-agent-suite/internal/policy"
	"github.com/Notyet1307/security-agent-suite/internal/store"
	"github.com/Notyet1307/security-agent-suite/internal/validation"
)

func (s *Service) inputLimit() int64 {
	if s.cfg.MaxInputBytes > 0 && s.cfg.MaxInputBytes < domain.MaxInputBytes {
		return s.cfg.MaxInputBytes
	}
	return domain.MaxInputBytes
}
func (s *Service) inputReady() error {
	if s.cfg.InputArtifacts == nil || s.journals == nil || s.evidence == nil {
		return fmt.Errorf("manual input persistence is unavailable")
	}
	return nil
}
func (s *Service) UploadInput(ctx context.Context, tenant, runID, name, contentType, digest string, body io.Reader) (domain.ArtifactRef, error) {
	s.inputMu.Lock()
	defer s.inputMu.Unlock()
	run, err := s.GetRun(ctx, tenant, runID)
	if err != nil {
		return domain.ArtifactRef{}, err
	}
	if !run.Manual() || run.Status != domain.RunStatusPreparing || run.Submission != nil {
		return domain.ArtifactRef{}, domain.ErrConflict
	}
	if err = s.inputReady(); err != nil {
		return domain.ArtifactRef{}, err
	}
	if run.InputManifest == nil {
		return domain.ArtifactRef{}, domain.ErrConflict
	}
	media, params, err := mime.ParseMediaType(contentType)
	if err != nil || media != "application/json" || len(params) > 1 {
		return domain.ArtifactRef{}, domain.ErrInvalidRequest
	}
	for k, v := range params {
		if k != "charset" || !strings.EqualFold(v, "utf-8") {
			return domain.ArtifactRef{}, domain.ErrInvalidRequest
		}
	}
	digest = strings.ToLower(strings.TrimSpace(digest))
	if digest == "" || digest != run.InputManifest.SHA256 {
		return domain.ArtifactRef{}, domain.ErrInvalidRequest
	}
	return s.cfg.InputArtifacts.PutInputReader(ctx, runID, name, body, *run.InputManifest, s.inputLimit(), time.Now())
}

func (s *Service) validateArtifact(ctx context.Context, run *domain.Run, art domain.ArtifactRef) error {
	if run.InputManifest == nil {
		return domain.ErrConflict
	}
	m := run.InputManifest
	if art.SizeBytes > s.inputLimit() {
		return domain.ErrInputTooLarge
	}
	if art.SHA256 != m.SHA256 || art.SizeBytes != m.SizeBytes || art.MediaType != m.MediaType {
		return domain.ErrInvalidRequest
	}
	raw, err := s.cfg.InputArtifacts.ReadInput(ctx, run.ID, art, s.inputLimit())
	if err != nil {
		return err
	}
	if int64(len(raw)) != m.SizeBytes || fmt.Sprintf("%x", sha256.Sum256(raw)) != m.SHA256 {
		return domain.ErrInvalidRequest
	}
	return validation.ValidateInput(raw)
}
func submissionFor(run *domain.Run, art domain.ArtifactRef, evidence domain.EvidenceRef) domain.Submission {
	m := run.InputManifest
	fingerprint := policy.Fingerprint("sas.manual-submit/v1", map[string]any{"run_id": run.ID, "artifact_id": art.ID, "schema": m.Schema, "sha256": art.SHA256, "size_bytes": art.SizeBytes, "media_type": art.MediaType})
	return domain.Submission{RunID: run.ID, ArtifactID: art.ID, Schema: m.Schema, SHA256: art.SHA256, SizeBytes: art.SizeBytes, MediaType: art.MediaType, EvidenceID: evidence.ID, SubmittedAt: evidence.CollectedAt, Fingerprint: fingerprint}
}
func frozenInput(j store.InputJournal) []domain.InputRef {
	return []domain.InputRef{{Type: "alert", URI: j.Artifact.URI, SHA256: j.Artifact.SHA256, MediaType: j.Artifact.MediaType, SizeBytes: j.Artifact.SizeBytes, Metadata: map[string]string{"schema": domain.InputSchema}}}
}
func (s *Service) validCreation(run *domain.Run) bool {
	if run.InputManifest == nil {
		return false
	}
	req := domain.CreateRunRequest{CaseID: run.CaseID, Mode: run.Mode, ExecutionMode: run.ExecutionMode, InputManifest: run.InputManifest, Scope: run.Scope, Policy: run.Policy, Output: run.Output, Metadata: run.Metadata}
	return run.CreationFingerprint == policy.CreationFingerprint(run.AgentID, req)
}
func validJournal(run *domain.Run, j store.InputJournal) bool {
	if run.InputManifest == nil {
		return false
	}
	e := j.Evidence
	wantEvidence := domain.EvidenceRef{ID: e.ID, Type: "input", SourceURI: j.Artifact.URI, SHA256: j.Artifact.SHA256, ArtifactIDs: []string{j.Artifact.ID}, Tool: "sas-input-validator", ToolVersion: "1", Parameters: map[string]string{"schema": domain.InputSchema}, CollectedAt: e.CollectedAt, Metadata: map[string]string{"time_semantics": "server_validation"}}
	return j.Version == "sas.input-journal/v1" && j.RunID == run.ID && j.TenantID == run.Scope.TenantID && strings.HasPrefix(e.ID, "input_") && !e.CollectedAt.IsZero() && reflect.DeepEqual(e, wantEvidence) && j.Submission == submissionFor(run, j.Artifact, e) && j.Artifact.SHA256 == run.InputManifest.SHA256 && j.Artifact.SizeBytes == run.InputManifest.SizeBytes && j.Artifact.MediaType == run.InputManifest.MediaType
}

func (s *Service) SubmitRun(ctx context.Context, tenant, runID, artifactID string) (*domain.Run, bool, error) {
	s.inputMu.Lock()
	defer s.inputMu.Unlock()
	run, err := s.GetRun(ctx, tenant, runID)
	if err != nil {
		return nil, false, err
	}
	if !store.ValidIdentifier(artifactID) || len(artifactID) > 128 {
		return nil, false, domain.ErrInvalidRequest
	}
	if !run.Manual() || !s.validCreation(run) {
		return nil, false, domain.ErrConflict
	}
	if run.Submission != nil {
		if run.Submission.ArtifactID != artifactID {
			return nil, false, domain.ErrConflict
		}
		return run, false, nil
	}
	if run.Status != domain.RunStatusPreparing {
		return nil, false, domain.ErrConflict
	}
	if err = s.inputReady(); err != nil {
		return nil, false, err
	}
	j, err := s.journals.GetInputJournal(ctx, runID)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return nil, false, err
	}
	exists := err == nil
	if exists && (!validJournal(run, j) || j.Artifact.ID != artifactID) {
		return nil, false, domain.ErrConflict
	}
	art, err := s.cfg.InputArtifacts.Get(ctx, runID, artifactID)
	if err != nil {
		return nil, false, err
	}
	if err = s.validateArtifact(ctx, run, art); err != nil {
		return nil, false, err
	}
	if !exists {
		now := time.Now().UTC()
		eid, err := id.New("input", now)
		if err != nil {
			return nil, false, err
		}
		evidence := domain.EvidenceRef{ID: eid, Type: "input", SourceURI: art.URI, SHA256: art.SHA256, ArtifactIDs: []string{art.ID}, Tool: "sas-input-validator", ToolVersion: "1", Parameters: map[string]string{"schema": domain.InputSchema}, CollectedAt: now, Metadata: map[string]string{"time_semantics": "server_validation"}}
		if _, err = s.evidence.Get(ctx, tenant, runID, eid); err == nil {
			return nil, false, domain.ErrConflict
		} else if !errors.Is(err, domain.ErrNotFound) {
			return nil, false, err
		}
		j = store.InputJournal{Version: "sas.input-journal/v1", TenantID: tenant, RunID: runID, Artifact: art, Evidence: evidence, Submission: submissionFor(run, art, evidence)}
		if err = s.journals.CreateInputJournal(ctx, j); err != nil {
			return nil, false, err
		}
	} else if !reflect.DeepEqual(art, j.Artifact) {
		return nil, false, domain.ErrConflict
	}
	existing, err := s.evidence.Get(ctx, tenant, runID, j.Evidence.ID)
	if errors.Is(err, domain.ErrNotFound) {
		_, err = s.evidence.Append(ctx, tenant, runID, j.Evidence)
	} else if err == nil && !reflect.DeepEqual(existing, j.Evidence) {
		err = domain.ErrConflict
	}
	if err != nil {
		return nil, false, err
	}
	updated, err := s.store.Update(ctx, runID, func(current *domain.Run) error {
		if current.Status != domain.RunStatusPreparing || current.Submission != nil {
			return domain.ErrConflict
		}
		current.Inputs = frozenInput(j)
		submission := j.Submission
		current.Submission = &submission
		return current.Transition(domain.RunStatusQueued, "validated input submitted", "api", time.Now())
	})
	if err != nil {
		return nil, false, err
	}
	// The durable queued record is the outbox. Failure to notify is repaired by
	// the dispatcher; it must never undo an accepted submission.
	_ = s.enqueue(s.ctx, runID)
	return updated, true, nil
}

// AppendEvidence serializes public appends with internal registration. A tool
// label alone conveys no trust; IDs reserved in private journals are protected.
func (s *Service) AppendEvidence(ctx context.Context, tenant, runID string, ref domain.EvidenceRef, evidenceStore store.EvidenceStore) (domain.EvidenceRef, error) {
	s.inputMu.Lock()
	defer s.inputMu.Unlock()
	if _, err := s.GetRun(ctx, tenant, runID); err != nil {
		return domain.EvidenceRef{}, err
	}
	if evidenceStore == nil {
		return domain.EvidenceRef{}, fmt.Errorf("evidence persistence unavailable")
	}
	if s.journals != nil {
		// ponytail: scan journals for reserved IDs; add an index if public append throughput requires it.
		runs, err := s.store.List(ctx, store.ListFilter{})
		if err != nil {
			return domain.EvidenceRef{}, err
		}
		for _, run := range runs {
			if !run.Manual() {
				continue
			}
			j, err := s.journals.GetInputJournal(ctx, run.ID)
			if errors.Is(err, domain.ErrNotFound) {
				continue
			}
			if err != nil {
				return domain.EvidenceRef{}, err
			}
			if j.Evidence.ID == strings.TrimSpace(ref.ID) {
				return domain.EvidenceRef{}, domain.ErrConflict
			}
		}
	}
	return evidenceStore.Append(ctx, tenant, runID, ref)
}
func (s *Service) checkFrozen(ctx context.Context, run *domain.Run) error {
	if err := s.inputReady(); err != nil {
		return err
	}
	if !s.validCreation(run) || run.Submission == nil {
		return fmt.Errorf("invalid frozen input")
	}
	j, err := s.journals.GetInputJournal(ctx, run.ID)
	if err != nil {
		return fmt.Errorf("load input journal: %w", err)
	}
	if !validJournal(run, j) || *run.Submission != j.Submission || !reflect.DeepEqual(run.Inputs, frozenInput(j)) {
		return fmt.Errorf("frozen input does not match journal")
	}
	evidence, err := s.evidence.Get(ctx, run.Scope.TenantID, run.ID, j.Evidence.ID)
	if err != nil {
		return fmt.Errorf("load input evidence: %w", err)
	}
	if !reflect.DeepEqual(evidence, j.Evidence) {
		return fmt.Errorf("input evidence does not match journal")
	}
	art, err := s.cfg.InputArtifacts.Get(ctx, run.ID, j.Artifact.ID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(art, j.Artifact) {
		return fmt.Errorf("input artifact metadata changed")
	}
	return s.validateArtifact(ctx, run, art)
}
func (s *Service) dispatchInputs() {
	defer s.wg.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
		// ponytail: scan the single-node durable queue; index/paginate if backlog makes this costly.
		runs, err := s.store.List(s.ctx, store.ListFilter{Status: domain.RunStatusQueued})
		if err != nil {
			s.logger.Error("scan manual queue", "error", err)
			continue
		}
		for _, r := range runs {
			if r.Manual() {
				_ = s.enqueue(s.ctx, r.ID)
			}
		}
	}
}
