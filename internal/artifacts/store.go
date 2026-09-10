package artifacts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/id"
	"github.com/Notyet1307/security-agent-suite/internal/store"
)

var safeName = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

const (
	metadataDirectory    = ".metadata"
	maxArtifactNameBytes = 200
	maxMediaTypeBytes    = 255
)

type Store struct {
	root    string
	syncDir func(string) error
}

func New(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("create artifact directory: %w", err)
	}
	if err := store.SyncDirectory(filepath.Dir(root)); err != nil {
		return nil, err
	}
	return &Store{root: root, syncDir: store.SyncDirectory}, nil
}

func (s *Store) Put(ctx context.Context, runID, name, mediaType string, data []byte, now time.Time) (domain.ArtifactRef, error) {
	return s.PutReader(ctx, runID, name, mediaType, bytes.NewReader(data), "", now)
}

// PutReader streams an artifact to disk, computes its SHA-256, and registers
// the resulting metadata without loading the complete body into memory.
func (s *Store) PutReader(ctx context.Context, runID, name, mediaType string, data io.Reader, expectedSHA256 string, now time.Time) (domain.ArtifactRef, error) {
	return s.putReader(ctx, runID, name, mediaType, data, expectedSHA256, 0, 0, now)
}

func (s *Store) putReader(ctx context.Context, runID, name, mediaType string, data io.Reader, expectedSHA256 string, expectedSize, limit int64, now time.Time) (domain.ArtifactRef, error) {
	if err := ctx.Err(); err != nil {
		return domain.ArtifactRef{}, err
	}
	rawRunID := strings.TrimSpace(runID)
	runID = filepath.Base(rawRunID)
	if rawRunID == "" || runID != rawRunID || strings.ContainsAny(rawRunID, `/\`) {
		return domain.ArtifactRef{}, fmt.Errorf("%w: run id must be a single safe path segment", domain.ErrInvalidRequest)
	}
	if data == nil {
		return domain.ArtifactRef{}, fmt.Errorf("%w: artifact body is required", domain.ErrInvalidRequest)
	}
	mediaType = strings.TrimSpace(mediaType)
	if len(mediaType) > maxMediaTypeBytes {
		return domain.ArtifactRef{}, fmt.Errorf("%w: Content-Type is too long", domain.ErrInvalidRequest)
	}
	parsedMediaType, params, err := mime.ParseMediaType(mediaType)
	if err != nil || !strings.Contains(parsedMediaType, "/") {
		return domain.ArtifactRef{}, fmt.Errorf("%w: valid Content-Type is required", domain.ErrInvalidRequest)
	}
	mediaType = mime.FormatMediaType(parsedMediaType, params)
	expectedSHA256 = strings.ToLower(strings.TrimSpace(expectedSHA256))
	if expectedSHA256 != "" {
		digest, decodeErr := hex.DecodeString(expectedSHA256)
		if decodeErr != nil || len(digest) != sha256.Size {
			return domain.ArtifactRef{}, fmt.Errorf("%w: X-Artifact-SHA256 must be 64 hexadecimal characters", domain.ErrInvalidRequest)
		}
	}

	name = filepath.Base(strings.TrimSpace(name))
	name = safeName.ReplaceAllString(name, "-")
	if name == "" {
		return domain.ArtifactRef{}, fmt.Errorf("%w: artifact name is required", domain.ErrInvalidRequest)
	}
	if len(name) > maxArtifactNameBytes {
		return domain.ArtifactRef{}, fmt.Errorf("%w: artifact name is too long", domain.ErrInvalidRequest)
	}
	runDir := filepath.Join(s.root, runID)
	if err := os.MkdirAll(runDir, 0o750); err != nil {
		return domain.ArtifactRef{}, fmt.Errorf("create run artifact directory: %w", err)
	}
	artifactID, err := id.New("art", now)
	if err != nil {
		return domain.ArtifactRef{}, err
	}
	storedName := artifactID
	path := filepath.Join(runDir, storedName)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return domain.ArtifactRef{}, fmt.Errorf("create artifact: %w", err)
	}
	hasher := sha256.New()
	if limit > 0 {
		data = io.LimitReader(data, limit+1)
	}
	size, copyErr := io.Copy(io.MultiWriter(file, hasher), data)
	if copyErr == nil && limit > 0 && size > limit {
		copyErr = domain.ErrInputTooLarge
	}
	if copyErr == nil && expectedSize > 0 && size != expectedSize {
		copyErr = domain.ErrInvalidRequest
	}
	if copyErr == nil {
		copyErr = file.Sync()
	}
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(path)
		return domain.ArtifactRef{}, fmt.Errorf("write artifact: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return domain.ArtifactRef{}, fmt.Errorf("close artifact: %w", closeErr)
	}
	if err := ctx.Err(); err != nil {
		_ = os.Remove(path)
		return domain.ArtifactRef{}, err
	}
	if size == 0 {
		_ = os.Remove(path)
		return domain.ArtifactRef{}, fmt.Errorf("%w: artifact body must not be empty", domain.ErrInvalidRequest)
	}
	actualSHA256 := hex.EncodeToString(hasher.Sum(nil))
	if expectedSHA256 != "" && expectedSHA256 != actualSHA256 {
		_ = os.Remove(path)
		return domain.ArtifactRef{}, fmt.Errorf("%w: artifact SHA-256 does not match X-Artifact-SHA256", domain.ErrInvalidRequest)
	}
	ref := domain.ArtifactRef{
		ID:        artifactID,
		Name:      name,
		URI:       "artifact://runs/" + runID + "/" + storedName,
		MediaType: mediaType,
		SHA256:    actualSHA256,
		SizeBytes: size,
		CreatedAt: now.UTC(),
	}
	if err := s.syncDir(s.root); err != nil {
		_ = os.Remove(path)
		return domain.ArtifactRef{}, err
	}
	if err := s.syncDir(runDir); err != nil {
		_ = os.Remove(path)
		return domain.ArtifactRef{}, err
	}
	if published, err := s.writeMetadata(runDir, ref); err != nil {
		if !published {
			_ = os.Remove(path)
		}
		return domain.ArtifactRef{}, err
	}
	return ref, nil
}

func (s *Store) writeMetadata(runDir string, ref domain.ArtifactRef) (bool, error) {
	dir := filepath.Join(runDir, metadataDirectory)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return false, fmt.Errorf("create artifact metadata directory: %w", err)
	}
	file, err := os.CreateTemp(dir, "."+ref.ID+"-*.tmp")
	if err != nil {
		return false, fmt.Errorf("create artifact metadata: %w", err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0o640); err != nil {
		_ = file.Close()
		return false, fmt.Errorf("set artifact metadata permissions: %w", err)
	}
	if err := json.NewEncoder(file).Encode(ref); err != nil {
		_ = file.Close()
		return false, fmt.Errorf("write artifact metadata: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return false, err
	}
	if err := file.Close(); err != nil {
		return false, fmt.Errorf("close artifact metadata: %w", err)
	}
	path := filepath.Join(dir, ref.ID+".json")
	if _, err := os.Lstat(path); err == nil {
		return false, fmt.Errorf("artifact metadata already exists")
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("inspect artifact metadata: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return false, fmt.Errorf("publish artifact metadata: %w", err)
	}
	if err := s.syncDir(dir); err != nil {
		return true, err
	}
	return true, s.syncDir(runDir)
}

// Get returns registered metadata for one artifact in a run namespace.
func (s *Store) Get(ctx context.Context, runID, artifactID string) (domain.ArtifactRef, error) {
	if err := ctx.Err(); err != nil {
		return domain.ArtifactRef{}, err
	}
	rawRunID := strings.TrimSpace(runID)
	runID = filepath.Base(rawRunID)
	rawArtifactID := strings.TrimSpace(artifactID)
	artifactID = filepath.Base(rawArtifactID)
	if rawRunID == "" || runID != rawRunID || strings.ContainsAny(rawRunID, `/\\`) || rawArtifactID == "" || artifactID != rawArtifactID || strings.ContainsAny(rawArtifactID, `/\\`) {
		return domain.ArtifactRef{}, fmt.Errorf("%w: invalid artifact namespace", domain.ErrInvalidRequest)
	}
	metadataDir := filepath.Join(s.root, runID, metadataDirectory)
	entries, err := os.ReadDir(metadataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return domain.ArtifactRef{}, domain.ErrNotFound
		}
		return domain.ArtifactRef{}, err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return domain.ArtifactRef{}, err
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		ref, err := readMetadata(filepath.Join(metadataDir, entry.Name()), runID)
		if err != nil {
			return domain.ArtifactRef{}, err
		}
		if ref.ID == artifactID {
			return ref, nil
		}
	}
	return domain.ArtifactRef{}, domain.ErrNotFound
}

func readMetadata(path, runID string) (domain.ArtifactRef, error) {
	entry, err := os.Lstat(path)
	if err != nil {
		return domain.ArtifactRef{}, err
	}
	if entry.Mode()&os.ModeSymlink != 0 || !entry.Mode().IsRegular() || entry.Size() <= 0 || entry.Size() > 64<<10 {
		return domain.ArtifactRef{}, fmt.Errorf("invalid artifact metadata file")
	}
	file, err := os.Open(path)
	if err != nil {
		return domain.ArtifactRef{}, err
	}
	defer file.Close()
	var ref domain.ArtifactRef
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ref); err != nil {
		return domain.ArtifactRef{}, fmt.Errorf("decode artifact metadata: %w", err)
	}
	if filepath.Base(ref.ID) != ref.ID || strings.ContainsAny(ref.ID, `/\\`) || ref.ID == "" || ref.Name == "" || ref.MediaType == "" || ref.SHA256 == "" || ref.SizeBytes <= 0 || ref.CreatedAt.IsZero() {
		return domain.ArtifactRef{}, fmt.Errorf("invalid artifact metadata")
	}
	prefix := "artifact://runs/" + runID + "/"
	storedName := strings.TrimPrefix(ref.URI, prefix)
	if !strings.HasPrefix(ref.URI, prefix) || storedName == "" || filepath.Base(storedName) != storedName || strings.ContainsAny(storedName, `/\\`) {
		return domain.ArtifactRef{}, fmt.Errorf("invalid artifact metadata URI")
	}
	return ref, nil
}

// List returns registered artifacts in deterministic creation order.
func (s *Store) List(ctx context.Context, runID string) ([]domain.ArtifactRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rawRunID := strings.TrimSpace(runID)
	runID = filepath.Base(rawRunID)
	if rawRunID == "" || runID != rawRunID || strings.ContainsAny(rawRunID, `/\`) {
		return nil, fmt.Errorf("%w: invalid run id", domain.ErrInvalidRequest)
	}
	metadataDir := filepath.Join(s.root, runID, metadataDirectory)
	entries, err := os.ReadDir(metadataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []domain.ArtifactRef{}, nil
		}
		return nil, err
	}
	refs := make([]domain.ArtifactRef, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		ref, err := readMetadata(filepath.Join(metadataDir, entry.Name()), runID)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].CreatedAt.Equal(refs[j].CreatedAt) {
			return refs[i].ID < refs[j].ID
		}
		return refs[i].CreatedAt.Before(refs[j].CreatedAt)
	})
	return refs, nil
}

// Open opens a previously written artifact after validating that its URI stays
// inside the configured artifact root and the requested run namespace.
func (s *Store) Open(ctx context.Context, runID string, ref domain.ArtifactRef) (*os.File, os.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	rawRunID := strings.TrimSpace(runID)
	runID = filepath.Base(rawRunID)
	if rawRunID == "" || runID != rawRunID || strings.ContainsAny(rawRunID, `/\`) {
		return nil, nil, fmt.Errorf("invalid run id")
	}
	prefix := "artifact://runs/" + runID + "/"
	if !strings.HasPrefix(ref.URI, prefix) {
		return nil, nil, fmt.Errorf("artifact URI does not belong to run")
	}
	rawStoredName := strings.TrimPrefix(ref.URI, prefix)
	storedName := filepath.Base(rawStoredName)
	if rawStoredName == "" || storedName != rawStoredName || strings.ContainsAny(rawStoredName, `/\`) {
		return nil, nil, fmt.Errorf("invalid artifact URI")
	}
	path := filepath.Join(s.root, runID, storedName)
	entry, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, domain.ErrNotFound
		}
		return nil, nil, err
	}
	if entry.Mode()&os.ModeSymlink != 0 || !entry.Mode().IsRegular() {
		return nil, nil, domain.ErrNotFound
	}
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
	if !info.Mode().IsRegular() || (ref.SizeBytes > 0 && info.Size() != ref.SizeBytes) {
		_ = file.Close()
		return nil, nil, domain.ErrNotFound
	}
	return file, info, nil
}

func (s *Store) PutInputReader(ctx context.Context, runID, name string, data io.Reader, m domain.InputManifest, limit int64, now time.Time) (domain.ArtifactRef, error) {
	return s.putReader(ctx, runID, name, "application/json", data, m.SHA256, m.SizeBytes, limit, now)
}
func (s *Store) ReadInput(ctx context.Context, runID string, ref domain.ArtifactRef, limit int64) ([]byte, error) {
	// Open validates the path; size/hash are verified against actual bytes by submit.
	ref.SizeBytes = 0
	for _, dir := range []string{s.root, filepath.Join(s.root, runID), filepath.Join(s.root, runID, metadataDirectory)} {
		if err := s.syncDir(dir); err != nil {
			return nil, err
		}
	}
	f, _, err := s.Open(ctx, runID, ref)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, domain.ErrInputTooLarge
	}
	return raw, ctx.Err()
}
