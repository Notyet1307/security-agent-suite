package store

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

type ListFilter struct {
	TenantID string
	AgentID  string
	Status   domain.RunStatus
	Limit    int
}

type RunReader interface {
	Get(ctx context.Context, id string) (*domain.Run, error)
}

type ArtifactReader interface {
	Get(ctx context.Context, runID, artifactID string) (domain.ArtifactRef, error)
}

type RunStore interface {
	Create(ctx context.Context, run *domain.Run) error
	Get(ctx context.Context, id string) (*domain.Run, error)
	FindByRequestID(ctx context.Context, tenantID, requestID string) (*domain.Run, error)
	Update(ctx context.Context, id string, mutate func(*domain.Run) error) (*domain.Run, error)
	List(ctx context.Context, filter ListFilter) ([]domain.Run, error)
}

type EvidenceStore interface {
	Append(ctx context.Context, tenantID, runID string, evidence domain.EvidenceRef) (domain.EvidenceRef, error)
	Get(ctx context.Context, tenantID, runID, evidenceID string) (domain.EvidenceRef, error)
	List(ctx context.Context, tenantID, runID string) ([]domain.EvidenceRef, error)
}

const (
	maxEvidenceIDBytes        = 128
	maxEvidenceTypeBytes      = 128
	maxEvidenceSourceURIBytes = 2048
	maxEvidenceToolBytes      = 128
	maxEvidenceVersionBytes   = 128
	maxEvidenceExcerptBytes   = 64 << 10
	maxEvidenceMapEntries     = 128
	maxEvidenceMapValueBytes  = 4 << 10
	maxEvidenceArtifactRefs   = 128
)

func CloneEvidence(ref domain.EvidenceRef) domain.EvidenceRef {
	ref.ArtifactIDs = append([]string(nil), ref.ArtifactIDs...)
	ref.Parameters = cloneStringMap(ref.Parameters)
	ref.Metadata = cloneStringMap(ref.Metadata)
	return ref
}

func NormalizeEvidence(ref domain.EvidenceRef) (domain.EvidenceRef, error) {
	ref = CloneEvidence(ref)
	ref.ID = strings.TrimSpace(ref.ID)
	ref.Type = strings.TrimSpace(ref.Type)
	ref.SourceURI = strings.TrimSpace(ref.SourceURI)
	ref.Tool = strings.TrimSpace(ref.Tool)
	ref.ToolVersion = strings.TrimSpace(ref.ToolVersion)
	if !ValidIdentifier(ref.ID) || len(ref.ID) > maxEvidenceIDBytes {
		return domain.EvidenceRef{}, fmt.Errorf("%w: evidence id must be a safe non-empty identifier", domain.ErrInvalidRequest)
	}
	if ref.Type == "" || len(ref.Type) > maxEvidenceTypeBytes || !utf8.ValidString(ref.Type) {
		return domain.EvidenceRef{}, fmt.Errorf("%w: evidence type is required and bounded", domain.ErrInvalidRequest)
	}
	if ref.SourceURI == "" || len(ref.SourceURI) > maxEvidenceSourceURIBytes || !utf8.ValidString(ref.SourceURI) {
		return domain.EvidenceRef{}, fmt.Errorf("%w: evidence source_uri is required and bounded", domain.ErrInvalidRequest)
	}
	ref.SHA256 = strings.ToLower(strings.TrimSpace(ref.SHA256))
	if len(ref.SHA256) != 64 {
		return domain.EvidenceRef{}, fmt.Errorf("%w: evidence sha256 must be 64 hexadecimal characters", domain.ErrInvalidRequest)
	}
	digest, err := hex.DecodeString(ref.SHA256)
	if err != nil || len(digest) != 32 {
		return domain.EvidenceRef{}, fmt.Errorf("%w: evidence sha256 must be hexadecimal", domain.ErrInvalidRequest)
	}
	if ref.Tool == "" || len(ref.Tool) > maxEvidenceToolBytes || !utf8.ValidString(ref.Tool) {
		return domain.EvidenceRef{}, fmt.Errorf("%w: evidence tool is required and bounded", domain.ErrInvalidRequest)
	}
	if ref.ToolVersion == "" || len(ref.ToolVersion) > maxEvidenceVersionBytes || !utf8.ValidString(ref.ToolVersion) {
		return domain.EvidenceRef{}, fmt.Errorf("%w: evidence tool_version is required and bounded", domain.ErrInvalidRequest)
	}
	if ref.CollectedAt.IsZero() {
		return domain.EvidenceRef{}, fmt.Errorf("%w: evidence collected_at is required", domain.ErrInvalidRequest)
	}
	ref.CollectedAt = ref.CollectedAt.UTC()
	if len(ref.Excerpt) > maxEvidenceExcerptBytes || !utf8.ValidString(ref.Excerpt) {
		return domain.EvidenceRef{}, fmt.Errorf("%w: evidence excerpt is invalid or too long", domain.ErrInvalidRequest)
	}
	if ref.Parameters == nil {
		return domain.EvidenceRef{}, fmt.Errorf("%w: evidence parameters are required", domain.ErrInvalidRequest)
	}
	if err := validateStringMap("parameters", ref.Parameters); err != nil {
		return domain.EvidenceRef{}, err
	}
	if err := validateStringMap("metadata", ref.Metadata); err != nil {
		return domain.EvidenceRef{}, err
	}
	if len(ref.ArtifactIDs) > maxEvidenceArtifactRefs {
		return domain.EvidenceRef{}, fmt.Errorf("%w: too many artifact references", domain.ErrInvalidRequest)
	}
	if len(ref.ArtifactIDs) > 0 {
		seen := make(map[string]struct{}, len(ref.ArtifactIDs))
		for i, artifactID := range ref.ArtifactIDs {
			artifactID = strings.TrimSpace(artifactID)
			if !ValidIdentifier(artifactID) || len(artifactID) > maxEvidenceIDBytes {
				return domain.EvidenceRef{}, fmt.Errorf("%w: artifact_ids[%d] is invalid", domain.ErrInvalidRequest, i)
			}
			if _, exists := seen[artifactID]; exists {
				return domain.EvidenceRef{}, fmt.Errorf("%w: duplicate artifact reference %q", domain.ErrInvalidRequest, artifactID)
			}
			seen[artifactID] = struct{}{}
			ref.ArtifactIDs[i] = artifactID
		}
	}
	return ref, nil
}

func ValidateEvidenceScope(ctx context.Context, runs RunReader, artifacts ArtifactReader, tenantID, runID string, ref domain.EvidenceRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if runs == nil {
		return fmt.Errorf("evidence run reader is not configured")
	}
	run, err := runs.Get(ctx, runID)
	if err != nil {
		return err
	}
	if run == nil {
		return fmt.Errorf("evidence run reader returned a nil run")
	}
	if run.Scope.TenantID != tenantID {
		return domain.ErrNotFound
	}
	if len(ref.ArtifactIDs) == 0 {
		return nil
	}
	if artifacts == nil {
		return fmt.Errorf("evidence artifact reader is not configured")
	}
	hashMatches := false
	sourceIsArtifact := strings.HasPrefix(ref.SourceURI, "artifact://")
	boundMatch := false
	for _, artifactID := range ref.ArtifactIDs {
		if err := ctx.Err(); err != nil {
			return err
		}
		artifact, err := artifacts.Get(ctx, runID, artifactID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return fmt.Errorf("%w: artifact %q is not registered for run", domain.ErrInvalidRequest, artifactID)
			}
			return err
		}
		hashMatches = hashMatches || strings.EqualFold(artifact.SHA256, ref.SHA256)
		boundMatch = boundMatch || (artifact.URI == ref.SourceURI && strings.EqualFold(artifact.SHA256, ref.SHA256))
	}
	if sourceIsArtifact && !boundMatch {
		return fmt.Errorf("%w: artifact source_uri and sha256 must match the same referenced artifact", domain.ErrInvalidRequest)
	}
	if !sourceIsArtifact && !hashMatches {
		return fmt.Errorf("%w: evidence sha256 does not match a referenced artifact", domain.ErrInvalidRequest)
	}
	return nil
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	copyValues := make(map[string]string, len(values))
	for key, value := range values {
		copyValues[key] = value
	}
	return copyValues
}

func validateStringMap(name string, values map[string]string) error {
	if len(values) > maxEvidenceMapEntries {
		return fmt.Errorf("%w: %s has too many entries", domain.ErrInvalidRequest, name)
	}
	for key, value := range values {
		if strings.TrimSpace(key) == "" || len(key) > maxEvidenceIDBytes || len(value) > maxEvidenceMapValueBytes || !utf8.ValidString(key) || !utf8.ValidString(value) {
			return fmt.Errorf("%w: %s contains an invalid entry", domain.ErrInvalidRequest, name)
		}
	}
	return nil
}

func ValidIdentifier(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '_' && char != '-' && char != '.' {
			return false
		}
	}
	return true
}
