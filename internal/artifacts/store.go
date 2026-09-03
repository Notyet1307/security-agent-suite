package artifacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/id"
)

var safeName = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

type Store struct {
	root string
}

func New(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("create artifact directory: %w", err)
	}
	return &Store{root: root}, nil
}

func (s *Store) Put(ctx context.Context, runID, name, mediaType string, data []byte, now time.Time) (domain.ArtifactRef, error) {
	if err := ctx.Err(); err != nil {
		return domain.ArtifactRef{}, err
	}
	runID = strings.TrimSpace(runID)
	if runID == "" || filepath.Base(runID) != runID || strings.ContainsAny(runID, `/\`) {
		return domain.ArtifactRef{}, fmt.Errorf("run id must be a single safe path segment")
	}
	name = safeName.ReplaceAllString(filepath.Base(strings.TrimSpace(name)), "-")
	name = strings.Trim(name, ".-")
	if name == "" {
		name = "artifact.bin"
	}
	runDir := filepath.Join(s.root, runID)
	if err := os.MkdirAll(runDir, 0o750); err != nil {
		return domain.ArtifactRef{}, fmt.Errorf("create run artifact directory: %w", err)
	}
	artifactID, err := id.New("art", now)
	if err != nil {
		return domain.ArtifactRef{}, err
	}
	storedName := artifactID + "-" + name
	path := filepath.Join(runDir, storedName)
	if err := os.WriteFile(path, data, 0o640); err != nil {
		return domain.ArtifactRef{}, fmt.Errorf("write artifact: %w", err)
	}
	digest := sha256.Sum256(data)
	return domain.ArtifactRef{
		ID:        artifactID,
		Name:      name,
		URI:       "artifact://runs/" + runID + "/" + storedName,
		MediaType: mediaType,
		SHA256:    hex.EncodeToString(digest[:]),
		SizeBytes: int64(len(data)),
		CreatedAt: now.UTC(),
	}, nil
}

// Open opens a previously written artifact after validating that its URI stays
// inside the configured artifact root and the requested run namespace.
func (s *Store) Open(ctx context.Context, runID string, ref domain.ArtifactRef) (*os.File, os.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	runID = strings.TrimSpace(runID)
	if runID == "" || filepath.Base(runID) != runID || strings.ContainsAny(runID, `/\`) {
		return nil, nil, fmt.Errorf("invalid run id")
	}
	prefix := "artifact://runs/" + runID + "/"
	if !strings.HasPrefix(ref.URI, prefix) {
		return nil, nil, fmt.Errorf("artifact URI does not belong to run")
	}
	storedName := strings.TrimPrefix(ref.URI, prefix)
	if storedName == "" || filepath.Base(storedName) != storedName {
		return nil, nil, fmt.Errorf("invalid artifact URI")
	}
	path := filepath.Join(s.root, runID, storedName)
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, domain.ErrNotFound
		}
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, domain.ErrNotFound
	}
	return file, info, nil
}
